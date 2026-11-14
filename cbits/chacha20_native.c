#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__aarch64__)

#include <arm_neon.h>

#elif defined(__x86_64__)

#include <cpuid.h>
#include <immintrin.h>

#endif

#if defined(__aarch64__) || defined(__x86_64__)

static const uint32_t chacha_constants[4] = {
    0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
};

/*
 * A kernel's stack frame holds copies of the key, e.g. in spilled
 * state registers, after it returns.  Each exported entry point thus
 * runs its kernel in a frame of its own and then overwrites the stack
 * region below it with zeros, so that no key material remains there.
 *
 * The region must exceed the kernels' frames, including any they call,
 * with room for other compilers and flags.  At -O2 (clang 21, gcc 14
 * and 16), the single- and two-block kernels' frames are at most
 * about 400 bytes, and the four- and eight-block kernels' at most
 * about 700 bytes on aarch64 and 2.2 KiB on x86_64.
 */
#define BURN_SMALL 1024
#if defined(__aarch64__)
#define BURN_LARGE 2048
#else
#define BURN_LARGE 4096
#endif

/* zero 'n' bytes, in a way the compiler may not elide */
static inline void scrub(uint8_t *buf, size_t n) {
    memset(buf, 0, n);
    __asm__ __volatile__("" : : "r"(buf) : "memory");
}

__attribute__((noinline))
static void burn_stack_small(void) {
    uint8_t buf[BURN_SMALL];
    scrub(buf, sizeof buf);
}

__attribute__((noinline))
static void burn_stack_large(void) {
    uint8_t buf[BURN_LARGE];
    scrub(buf, sizeof buf);
}

#endif

#if defined(__aarch64__)

/*
 * ChaCha20 NEON kernel using intra-block parallelism.  The 16-word
 * state matrix
 *
 *     s00 s01 s02 s03
 *     s04 s05 s06 s07
 *     s08 s09 s10 s11
 *     s12 s13 s14 s15
 *
 * is held in four 128-bit NEON registers v0..v3, one per row.  A
 * column quarter-round on (s00, s04, s08, s12), (s01, s05, s09, s13),
 * etc., becomes one set of element-wise vector operations on
 * (v0, v1, v2, v3) — four quarter-rounds in parallel.  Diagonal
 * rounds are reached by left-rotating v1, v2, v3 by 1, 2, 3 lanes
 * respectively with VEXT before the second quarter-round, then
 * rotating back.
 */

/* 32-bit left rotations.  Rotate-by-16 reduces to REV32.u16; the
 * others compile to a shift-shift-or pair (the compiler folds rotate-
 * by-8 to a TBL with a constant shuffle on some targets).         */
#define ROTL32_16(x) \
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
#define ROTL32_12(x) \
    vorrq_u32(vshlq_n_u32((x), 12), vshrq_n_u32((x), 20))
#define ROTL32_8(x) \
    vorrq_u32(vshlq_n_u32((x),  8), vshrq_n_u32((x), 24))
#define ROTL32_7(x) \
    vorrq_u32(vshlq_n_u32((x),  7), vshrq_n_u32((x), 25))

#define QUARTER(v0, v1, v2, v3)                          \
    do {                                                  \
        v0 = vaddq_u32(v0, v1);                           \
        v3 = veorq_u32(v3, v0); v3 = ROTL32_16(v3);       \
        v2 = vaddq_u32(v2, v3);                           \
        v1 = veorq_u32(v1, v2); v1 = ROTL32_12(v1);       \
        v0 = vaddq_u32(v0, v1);                           \
        v3 = veorq_u32(v3, v0); v3 = ROTL32_8(v3);        \
        v2 = vaddq_u32(v2, v3);                           \
        v1 = veorq_u32(v1, v2); v1 = ROTL32_7(v1);        \
    } while (0)

/* ChaCha core: 'drounds' iterations of (column + diagonal), e.g.
 * 10 for ChaCha20. */
static inline void chacha20_core(uint32x4_t *v0, uint32x4_t *v1,
                                  uint32x4_t *v2, uint32x4_t *v3,
                                  uint32x4_t s0, uint32x4_t s1,
                                  uint32x4_t s2, uint32x4_t s3,
                                  int drounds) {
    uint32x4_t a = s0, b = s1, c = s2, d = s3;
    for (int i = 0; i < drounds; i++) {
        QUARTER(a, b, c, d);
        /* shift rows: row 1 left 1, row 2 left 2, row 3 left 3.    */
        b = vextq_u32(b, b, 1);
        c = vextq_u32(c, c, 2);
        d = vextq_u32(d, d, 3);
        QUARTER(a, b, c, d);
        /* shift back.                                              */
        b = vextq_u32(b, b, 3);
        c = vextq_u32(c, c, 2);
        d = vextq_u32(d, d, 1);
    }
    *v0 = vaddq_u32(a, s0);
    *v1 = vaddq_u32(b, s1);
    *v2 = vaddq_u32(c, s2);
    *v3 = vaddq_u32(d, s3);
}

/*
 * ChaCha NEON kernel using inter-block parallelism: four consecutive
 * blocks at once, with register x[i] holding word i of each block.  A
 * quarter-round is then one set of element-wise operations on four
 * registers, with no lane rotation, and the four quarter-rounds of
 * each half-round are independent chains.  The registers, stored in
 * order, give the blocks interleaved word by word.
 */
static inline __attribute__((always_inline))
void chacha20_core4v(uint32x4_t x[16], int drounds) {
    for (int i = 0; i < drounds; i++) {
        QUARTER(x[0], x[4], x[ 8], x[12]);
        QUARTER(x[1], x[5], x[ 9], x[13]);
        QUARTER(x[2], x[6], x[10], x[14]);
        QUARTER(x[3], x[7], x[11], x[15]);
        QUARTER(x[0], x[5], x[10], x[15]);
        QUARTER(x[1], x[6], x[11], x[12]);
        QUARTER(x[2], x[7], x[ 8], x[13]);
        QUARTER(x[3], x[4], x[ 9], x[14]);
    }
}

/* Transpose four registers, each holding one word of four blocks,
 * into four each holding four consecutive words of one block. */
static inline void chacha20_transpose4(uint32x4_t *a, uint32x4_t *b,
                                       uint32x4_t *c, uint32x4_t *d) {
    uint64x2_t t0 = vreinterpretq_u64_u32(vtrn1q_u32(*a, *b));
    uint64x2_t t1 = vreinterpretq_u64_u32(vtrn2q_u32(*a, *b));
    uint64x2_t t2 = vreinterpretq_u64_u32(vtrn1q_u32(*c, *d));
    uint64x2_t t3 = vreinterpretq_u64_u32(vtrn2q_u32(*c, *d));
    *a = vreinterpretq_u32_u64(vtrn1q_u64(t0, t2));
    *b = vreinterpretq_u32_u64(vtrn1q_u64(t1, t3));
    *c = vreinterpretq_u32_u64(vtrn2q_u64(t0, t2));
    *d = vreinterpretq_u32_u64(vtrn2q_u64(t1, t3));
}

/* Set up the constant rows of the state from key + nonce.  s3
 * (counter + nonce) varies per block and is built inside the loop. */
static inline void chacha20_setup(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   uint32x4_t *s0, uint32x4_t *s1,
                                   uint32x4_t *s2,
                                   uint32_t *n0, uint32_t *n1,
                                   uint32_t *n2) {
    *s0 = vld1q_u32(chacha_constants);
    *s1 = vreinterpretq_u32_u8(vld1q_u8(key));
    *s2 = vreinterpretq_u32_u8(vld1q_u8(key + 16));
    memcpy(n0, nonce + 0, 4);
    memcpy(n1, nonce + 4, 4);
    memcpy(n2, nonce + 8, 4);
}

/*
 * Generate one 64-byte keystream block at 'out', using 'drounds'
 * double rounds (10 for ChaCha20).
 */
static __attribute__((noinline))
void chacha20_block_kernel(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64],
                           int drounds) {
    uint32x4_t s0, s1, s2;
    uint32_t n0, n1, n2;
    chacha20_setup(key, nonce, &s0, &s1, &s2, &n0, &n1, &n2);

    uint32_t s3_in[4] = { counter, n0, n1, n2 };
    uint32x4_t s3 = vld1q_u32(s3_in);
    uint32x4_t v0, v1, v2, v3;
    chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3, drounds);

    vst1q_u8(out + 0,  vreinterpretq_u8_u32(v0));
    vst1q_u8(out + 16, vreinterpretq_u8_u32(v1));
    vst1q_u8(out + 32, vreinterpretq_u8_u32(v2));
    vst1q_u8(out + 48, vreinterpretq_u8_u32(v3));
}

/*
 * Encrypt/decrypt the longest prefix of 'in' that is a whole number of
 * 256-byte groups of four blocks, via the four-block core, transposing
 * each group's rows back into block order.  Returns the number of
 * bytes processed.  'in' and 'out' may be the same buffer.
 */
static __attribute__((noinline))
size_t chacha20_cipher4_kernel(const uint8_t key[32], uint32_t counter,
                               const uint8_t nonce[12],
                               const uint8_t *in, uint8_t *out,
                               size_t inlen, int drounds) {
    uint32_t k[8], n[3];
    memcpy(k, key, 32);
    memcpy(n, nonce, 12);
    uint32x4_t s[16];
    for (int i = 0; i < 4; i++) s[i] = vdupq_n_u32(chacha_constants[i]);
    for (int i = 0; i < 8; i++) s[4 + i] = vdupq_n_u32(k[i]);
    for (int i = 0; i < 3; i++) s[13 + i] = vdupq_n_u32(n[i]);
    static const uint32_t lanes[4] = { 0, 1, 2, 3 };
    const uint32x4_t inc = vld1q_u32(lanes);

    size_t pos = 0;
    while (pos + 256 <= inlen) {
        s[12] = vaddq_u32(vdupq_n_u32(counter), inc);
        uint32x4_t x[16];
        for (int i = 0; i < 16; i++) x[i] = s[i];
        chacha20_core4v(x, drounds);
        for (int i = 0; i < 16; i++) x[i] = vaddq_u32(x[i], s[i]);

        for (int r = 0; r < 4; r++) {
            chacha20_transpose4(&x[4 * r], &x[4 * r + 1],
                                &x[4 * r + 2], &x[4 * r + 3]);
            for (int j = 0; j < 4; j++) {
                size_t o = pos + 64 * j + 16 * r;
                vst1q_u8(out + o,
                         veorq_u8(vld1q_u8(in + o),
                                  vreinterpretq_u8_u32(x[4 * r + j])));
            }
        }
        pos += 256;
        counter += 4;
    }
    return pos;
}

/*
 * Encrypt/decrypt 'inlen' bytes at 'in' into 'out' using ChaCha with
 * 'drounds' double rounds (10 for ChaCha20) and the given key,
 * starting counter, and nonce.  Stream cipher, so the same routine
 * decrypts.  'in' and 'out' may be the same buffer.
 */
static __attribute__((noinline))
void chacha20_cipher_kernel(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12],
                            const uint8_t *in, uint8_t *out,
                            size_t inlen, int drounds) {
    uint32x4_t s0, s1, s2;
    uint32_t n0, n1, n2;
    chacha20_setup(key, nonce, &s0, &s1, &s2, &n0, &n1, &n2);

    size_t pos = 0;
    while (pos + 64 <= inlen) {
        uint32_t s3_in[4] = { counter, n0, n1, n2 };
        uint32x4_t s3 = vld1q_u32(s3_in);
        uint32x4_t v0, v1, v2, v3;
        chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3, drounds);

        uint8x16_t i0 = vld1q_u8(in + pos +  0);
        uint8x16_t i1 = vld1q_u8(in + pos + 16);
        uint8x16_t i2 = vld1q_u8(in + pos + 32);
        uint8x16_t i3 = vld1q_u8(in + pos + 48);

        vst1q_u8(out + pos +  0,
                 veorq_u8(i0, vreinterpretq_u8_u32(v0)));
        vst1q_u8(out + pos + 16,
                 veorq_u8(i1, vreinterpretq_u8_u32(v1)));
        vst1q_u8(out + pos + 32,
                 veorq_u8(i2, vreinterpretq_u8_u32(v2)));
        vst1q_u8(out + pos + 48,
                 veorq_u8(i3, vreinterpretq_u8_u32(v3)));

        pos += 64;
        counter++;
    }

    /* trailing partial block (< 64 bytes) */
    if (pos < inlen) {
        uint32_t s3_in[4] = { counter, n0, n1, n2 };
        uint32x4_t s3 = vld1q_u32(s3_in);
        uint32x4_t v0, v1, v2, v3;
        chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3, drounds);

        uint8_t block[64];
        vst1q_u8(block +  0, vreinterpretq_u8_u32(v0));
        vst1q_u8(block + 16, vreinterpretq_u8_u32(v1));
        vst1q_u8(block + 32, vreinterpretq_u8_u32(v2));
        vst1q_u8(block + 48, vreinterpretq_u8_u32(v3));

        size_t remaining = inlen - pos;
        for (size_t i = 0; i < remaining; i++) {
            out[pos + i] = in[pos + i] ^ block[i];
        }
    }
}

/*
 * Write 'ngroups' groups of four consecutive keystream blocks to
 * 'out', 256 bytes per group, using 'drounds' double rounds and
 * starting at block 'counter'.  Within a group the blocks are
 * interleaved word by word: word i of block j is at byte offset
 * 16 * i + 4 * j.  If 'key_ff_only' is nonzero, the final addition of
 * the input state is applied to the key words only, omitting the
 * public constant, counter, and nonce words, as in ChaCha8Rand.
 * 'out' must not overlap 'key' or 'nonce'.
 */
static __attribute__((noinline))
void chacha20_interleaved_kernel(const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12], uint8_t *out,
                                 size_t ngroups, int drounds,
                                 int key_ff_only) {
    uint32_t k[8], n[3];
    memcpy(k, key, 32);
    memcpy(n, nonce, 12);

    uint32x4_t s[16];
    for (int i = 0; i < 4; i++) s[i]      = vdupq_n_u32(chacha_constants[i]);
    for (int i = 0; i < 8; i++) s[4 + i]  = vdupq_n_u32(k[i]);
    for (int i = 0; i < 3; i++) s[13 + i] = vdupq_n_u32(n[i]);
    static const uint32_t lanes[4] = { 0, 1, 2, 3 };
    const uint32x4_t inc = vld1q_u32(lanes);

    for (size_t g = 0; g < ngroups; g++) {
        s[12] = vaddq_u32(vdupq_n_u32(counter), inc);
        uint32x4_t x[16];
        for (int i = 0; i < 16; i++) x[i] = s[i];
        chacha20_core4v(x, drounds);

        uint8_t *o = out + 256 * g;
        for (int i = 0; i < 16; i++) {
            int add = !key_ff_only || (i >= 4 && i < 12);
            uint32x4_t v = add ? vaddq_u32(x[i], s[i]) : x[i];
            vst1q_u8(o + 16 * i, vreinterpretq_u8_u32(v));
        }
        counter += 4;
    }
}

/* exported entry points: run each kernel, then scrub the stack */

void chacha20_block_native(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64],
                           int drounds) {
    chacha20_block_kernel(key, counter, nonce, out, drounds);
    burn_stack_small();
}

void chacha20_cipher_native(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12],
                            const uint8_t *in, uint8_t *out,
                            size_t inlen, int drounds) {
    /* groups of four blocks via the four-block kernel, whose frame is
     * deeper, and the rest via the single-block kernel */
    size_t done = 0;
    if (inlen >= 256)
        done = chacha20_cipher4_kernel(key, counter, nonce, in, out,
                                       inlen, drounds);
    chacha20_cipher_kernel(key, counter + (uint32_t)(done / 64), nonce,
                           in + done, out + done, inlen - done, drounds);
    if (done)
        burn_stack_large();
    else
        burn_stack_small();
}

void chacha20_interleaved_native(const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12], uint8_t *out,
                                 size_t ngroups, int drounds,
                                 int key_ff_only) {
    chacha20_interleaved_kernel(key, counter, nonce, out, ngroups,
                                drounds, key_ff_only);
    burn_stack_large();
}

int chacha20_native_available(void) {
    return 1;
}

#elif defined(__x86_64__)

/*
 * ChaCha20 SSE2 kernel, using the same intra-block layout as the NEON
 * kernel: the state matrix is held in four 128-bit registers, one per
 * row, so that a column round is one set of element-wise vector
 * operations.  Diagonal rounds are reached by left-rotating rows 1, 2
 * and 3 by 1, 2 and 3 lanes respectively with PSHUFD, then rotating
 * back.  SSE2 is part of the x86-64 baseline, so no runtime check is
 * needed.
 */

/* 32-bit left rotations.  Rotate-by-16 swaps the 16-bit halves of
 * each lane with PSHUFLW/PSHUFHW; the others are a shift-shift-or
 * pair.                                                             */
#define ROTL32_16(x) \
    _mm_shufflehi_epi16(_mm_shufflelo_epi16((x), 0xb1), 0xb1)
#define ROTL32_N(x, n) \
    _mm_or_si128(_mm_slli_epi32((x), (n)), _mm_srli_epi32((x), 32 - (n)))

#define QUARTER(v0, v1, v2, v3)                                 \
    do {                                                         \
        v0 = _mm_add_epi32(v0, v1);                              \
        v3 = _mm_xor_si128(v3, v0); v3 = ROTL32_16(v3);          \
        v2 = _mm_add_epi32(v2, v3);                              \
        v1 = _mm_xor_si128(v1, v2); v1 = ROTL32_N(v1, 12);       \
        v0 = _mm_add_epi32(v0, v1);                              \
        v3 = _mm_xor_si128(v3, v0); v3 = ROTL32_N(v3, 8);        \
        v2 = _mm_add_epi32(v2, v3);                              \
        v1 = _mm_xor_si128(v1, v2); v1 = ROTL32_N(v1, 7);        \
    } while (0)

/* ChaCha core: 'drounds' iterations of (column + diagonal), e.g.
 * 10 for ChaCha20. */
static inline void chacha20_core(__m128i *v0, __m128i *v1,
                                 __m128i *v2, __m128i *v3,
                                 __m128i s0, __m128i s1,
                                 __m128i s2, __m128i s3,
                                 int drounds) {
    __m128i a = s0, b = s1, c = s2, d = s3;
    for (int i = 0; i < drounds; i++) {
        QUARTER(a, b, c, d);
        /* shift rows: row 1 left 1, row 2 left 2, row 3 left 3.    */
        b = _mm_shuffle_epi32(b, _MM_SHUFFLE(0, 3, 2, 1));
        c = _mm_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
        d = _mm_shuffle_epi32(d, _MM_SHUFFLE(2, 1, 0, 3));
        QUARTER(a, b, c, d);
        /* shift back.                                              */
        b = _mm_shuffle_epi32(b, _MM_SHUFFLE(2, 1, 0, 3));
        c = _mm_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
        d = _mm_shuffle_epi32(d, _MM_SHUFFLE(0, 3, 2, 1));
    }
    *v0 = _mm_add_epi32(a, s0);
    *v1 = _mm_add_epi32(b, s1);
    *v2 = _mm_add_epi32(c, s2);
    *v3 = _mm_add_epi32(d, s3);
}

/* Set up the constant rows of the state from key + nonce.  s3
 * (counter + nonce) varies per block and is built inside the loop. */
static inline void chacha20_setup(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  __m128i *s0, __m128i *s1,
                                  __m128i *s2,
                                  uint32_t *n0, uint32_t *n1,
                                  uint32_t *n2) {
    *s0 = _mm_loadu_si128((const __m128i *)chacha_constants);
    *s1 = _mm_loadu_si128((const __m128i *)key);
    *s2 = _mm_loadu_si128((const __m128i *)(key + 16));
    memcpy(n0, nonce + 0, 4);
    memcpy(n1, nonce + 4, 4);
    memcpy(n2, nonce + 8, 4);
}

/* Build row 3 (counter + nonce) for one block. */
static inline __m128i chacha20_row3(uint32_t counter, uint32_t n0,
                                    uint32_t n1, uint32_t n2) {
    return _mm_setr_epi32((int)counter, (int)n0, (int)n1, (int)n2);
}

/*
 * ChaCha20 AVX2 kernel: two blocks at once, in the same row layout.
 * Each 256-bit register holds one row of the state for two
 * consecutive blocks, the low 128-bit lane for block n and the high
 * lane for block n + 1.  VPSHUFD and VPSHUFB act within each lane, so
 * the rounds are those of the SSE2 kernel on wider registers; only
 * row 3, whose counters differ, needs per-lane setup.
 *
 * Each round is one long dependency chain, so long inputs are
 * processed four blocks at a time, as two interleaved pairs, to keep
 * more of the vector units busy.
 *
 * AVX2 is not part of the x86-64 baseline, so the kernel is compiled
 * for it alone and selected at runtime by 'have_avx2'.
 */

/*
 * Return 1 if the CPU implements AVX2 and the OS saves and restores
 * the ymm registers, 0 otherwise.
 */
static int avx2_detect(void) {
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return 0;
    if (!(ecx & bit_OSXSAVE) || !(ecx & bit_AVX))
        return 0;
    /* XCR0 bits 1 and 2: xmm and ymm state enabled by the OS */
    unsigned int xcr0_lo, xcr0_hi;
    __asm__ volatile ("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
    if ((xcr0_lo & 6) != 6)
        return 0;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
        return 0;
    return (ebx & bit_AVX2) != 0;
}

/* 'avx2_detect', cached; CPUID can be slow, especially under a
 * hypervisor.  Concurrent first calls compute the same value.      */
static int have_avx2(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (v < 0) {
        v = avx2_detect();
        __atomic_store_n(&cached, v, __ATOMIC_RELAXED);
    }
    return v;
}

/* 32-bit left rotations.  Rotate-by-16 and rotate-by-8 move whole
 * bytes, so are single VPSHUFB byte permutations.                   */
__attribute__((target("avx2")))
static inline __m256i rotl32_16_avx2(__m256i x) {
    const __m256i idx = _mm256_setr_epi8(
        2, 3, 0, 1,  6, 7, 4, 5,  10, 11, 8, 9,  14, 15, 12, 13,
        2, 3, 0, 1,  6, 7, 4, 5,  10, 11, 8, 9,  14, 15, 12, 13);
    return _mm256_shuffle_epi8(x, idx);
}

__attribute__((target("avx2")))
static inline __m256i rotl32_8_avx2(__m256i x) {
    const __m256i idx = _mm256_setr_epi8(
        3, 0, 1, 2,  7, 4, 5, 6,  11, 8, 9, 10,  15, 12, 13, 14,
        3, 0, 1, 2,  7, 4, 5, 6,  11, 8, 9, 10,  15, 12, 13, 14);
    return _mm256_shuffle_epi8(x, idx);
}

#define ROTL32_N_AVX2(x, n) \
    _mm256_or_si256(_mm256_slli_epi32((x), (n)), \
                    _mm256_srli_epi32((x), 32 - (n)))

#define QUARTER_AVX2(v0, v1, v2, v3)                               \
    do {                                                            \
        v0 = _mm256_add_epi32(v0, v1);                              \
        v3 = _mm256_xor_si256(v3, v0); v3 = rotl32_16_avx2(v3);     \
        v2 = _mm256_add_epi32(v2, v3);                              \
        v1 = _mm256_xor_si256(v1, v2); v1 = ROTL32_N_AVX2(v1, 12);  \
        v0 = _mm256_add_epi32(v0, v1);                              \
        v3 = _mm256_xor_si256(v3, v0); v3 = rotl32_8_avx2(v3);      \
        v2 = _mm256_add_epi32(v2, v3);                              \
        v1 = _mm256_xor_si256(v1, v2); v1 = ROTL32_N_AVX2(v1, 7);   \
    } while (0)

/* ChaCha core over two blocks. */
__attribute__((target("avx2")))
static inline void chacha20_core_avx2(__m256i *v0, __m256i *v1,
                                      __m256i *v2, __m256i *v3,
                                      __m256i s0, __m256i s1,
                                      __m256i s2, __m256i s3,
                                      int drounds) {
    __m256i a = s0, b = s1, c = s2, d = s3;
    for (int i = 0; i < drounds; i++) {
        QUARTER_AVX2(a, b, c, d);
        b = _mm256_shuffle_epi32(b, _MM_SHUFFLE(0, 3, 2, 1));
        c = _mm256_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
        d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(2, 1, 0, 3));
        QUARTER_AVX2(a, b, c, d);
        b = _mm256_shuffle_epi32(b, _MM_SHUFFLE(2, 1, 0, 3));
        c = _mm256_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
        d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(0, 3, 2, 1));
    }
    *v0 = _mm256_add_epi32(a, s0);
    *v1 = _mm256_add_epi32(b, s1);
    *v2 = _mm256_add_epi32(c, s2);
    *v3 = _mm256_add_epi32(d, s3);
}

/* ChaCha core over four blocks, as two interleaved
 * pairs so that their independent dependency chains overlap.        */
__attribute__((target("avx2")))
static inline void chacha20_core4_avx2(__m256i v[8], const __m256i s[8],
                                       int drounds) {
    __m256i a = s[0], b = s[1], c = s[2], d = s[3];
    __m256i e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < drounds; i++) {
        QUARTER_AVX2(a, b, c, d);
        QUARTER_AVX2(e, f, g, h);
        b = _mm256_shuffle_epi32(b, _MM_SHUFFLE(0, 3, 2, 1));
        c = _mm256_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
        d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(2, 1, 0, 3));
        f = _mm256_shuffle_epi32(f, _MM_SHUFFLE(0, 3, 2, 1));
        g = _mm256_shuffle_epi32(g, _MM_SHUFFLE(1, 0, 3, 2));
        h = _mm256_shuffle_epi32(h, _MM_SHUFFLE(2, 1, 0, 3));
        QUARTER_AVX2(a, b, c, d);
        QUARTER_AVX2(e, f, g, h);
        b = _mm256_shuffle_epi32(b, _MM_SHUFFLE(2, 1, 0, 3));
        c = _mm256_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
        d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(0, 3, 2, 1));
        f = _mm256_shuffle_epi32(f, _MM_SHUFFLE(2, 1, 0, 3));
        g = _mm256_shuffle_epi32(g, _MM_SHUFFLE(1, 0, 3, 2));
        h = _mm256_shuffle_epi32(h, _MM_SHUFFLE(0, 3, 2, 1));
    }
    v[0] = _mm256_add_epi32(a, s[0]);
    v[1] = _mm256_add_epi32(b, s[1]);
    v[2] = _mm256_add_epi32(c, s[2]);
    v[3] = _mm256_add_epi32(d, s[3]);
    v[4] = _mm256_add_epi32(e, s[4]);
    v[5] = _mm256_add_epi32(f, s[5]);
    v[6] = _mm256_add_epi32(g, s[6]);
    v[7] = _mm256_add_epi32(h, s[7]);
}

/* XOR one block pair's keystream rows into 128 bytes of input. */
__attribute__((target("avx2")))
static inline void chacha20_xor2_avx2(const uint8_t *in, uint8_t *out,
                                      __m256i v0, __m256i v1,
                                      __m256i v2, __m256i v3) {
    /* gather each block's rows: block n from the low lanes,
     * block n + 1 from the high lanes                               */
    __m256i k0 = _mm256_permute2x128_si256(v0, v1, 0x20);
    __m256i k1 = _mm256_permute2x128_si256(v2, v3, 0x20);
    __m256i k2 = _mm256_permute2x128_si256(v0, v1, 0x31);
    __m256i k3 = _mm256_permute2x128_si256(v2, v3, 0x31);

    __m256i i0 = _mm256_loadu_si256((const __m256i *)(in +  0));
    __m256i i1 = _mm256_loadu_si256((const __m256i *)(in + 32));
    __m256i i2 = _mm256_loadu_si256((const __m256i *)(in + 64));
    __m256i i3 = _mm256_loadu_si256((const __m256i *)(in + 96));

    _mm256_storeu_si256((__m256i *)(out +  0), _mm256_xor_si256(i0, k0));
    _mm256_storeu_si256((__m256i *)(out + 32), _mm256_xor_si256(i1, k1));
    _mm256_storeu_si256((__m256i *)(out + 64), _mm256_xor_si256(i2, k2));
    _mm256_storeu_si256((__m256i *)(out + 96), _mm256_xor_si256(i3, k3));
}

/*
 * Encrypt/decrypt the longest prefix of 'in' that is a whole number
 * of 128-byte block pairs, starting at 'counter': four blocks at a
 * time while at least 256 bytes remain, then two.  Returns the number
 * of bytes processed.
 */
__attribute__((target("avx2")))
static size_t chacha20_cipher_avx2(const uint8_t key[32],
                                   uint32_t counter,
                                   const uint8_t nonce[12],
                                   const uint8_t *in, uint8_t *out,
                                   size_t inlen, int drounds) {
    __m256i s0 = _mm256_broadcastsi128_si256(
        _mm_loadu_si128((const __m128i *)chacha_constants));
    __m256i s1 = _mm256_broadcastsi128_si256(
        _mm_loadu_si128((const __m128i *)key));
    __m256i s2 = _mm256_broadcastsi128_si256(
        _mm_loadu_si128((const __m128i *)(key + 16)));
    uint32_t n0, n1, n2;
    memcpy(&n0, nonce + 0, 4);
    memcpy(&n1, nonce + 4, 4);
    memcpy(&n2, nonce + 8, 4);

    size_t pos = 0;
    while (pos + 256 <= inlen) {
        uint32_t c1 = counter + 1, c2 = counter + 2, c3 = counter + 3;
        __m256i s[8] = {
            s0, s1, s2,
            _mm256_setr_epi32((int)counter, (int)n0, (int)n1, (int)n2,
                              (int)c1,      (int)n0, (int)n1, (int)n2),
            s0, s1, s2,
            _mm256_setr_epi32((int)c2, (int)n0, (int)n1, (int)n2,
                              (int)c3, (int)n0, (int)n1, (int)n2)
        };
        __m256i v[8];
        chacha20_core4_avx2(v, s, drounds);
        chacha20_xor2_avx2(in + pos, out + pos, v[0], v[1], v[2], v[3]);
        chacha20_xor2_avx2(in + pos + 128, out + pos + 128,
                           v[4], v[5], v[6], v[7]);
        pos += 256;
        counter += 4;
    }
    while (pos + 128 <= inlen) {
        uint32_t c1 = counter + 1;
        __m256i s3 = _mm256_setr_epi32(
            (int)counter, (int)n0, (int)n1, (int)n2,
            (int)c1,      (int)n0, (int)n1, (int)n2);
        __m256i v0, v1, v2, v3;
        chacha20_core_avx2(&v0, &v1, &v2, &v3, s0, s1, s2, s3, drounds);
        chacha20_xor2_avx2(in + pos, out + pos, v0, v1, v2, v3);
        pos += 128;
        counter += 2;
    }
    return pos;
}

/*
 * Generate one 64-byte keystream block at 'out', using 'drounds'
 * double rounds (10 for ChaCha20).
 */
static __attribute__((noinline))
void chacha20_block_kernel(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64],
                           int drounds) {
    __m128i s0, s1, s2;
    uint32_t n0, n1, n2;
    chacha20_setup(key, nonce, &s0, &s1, &s2, &n0, &n1, &n2);

    __m128i s3 = chacha20_row3(counter, n0, n1, n2);
    __m128i v0, v1, v2, v3;
    chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3, drounds);

    _mm_storeu_si128((__m128i *)(out +  0), v0);
    _mm_storeu_si128((__m128i *)(out + 16), v1);
    _mm_storeu_si128((__m128i *)(out + 32), v2);
    _mm_storeu_si128((__m128i *)(out + 48), v3);
}

/*
 * Encrypt/decrypt 'inlen' bytes at 'in' into 'out' using ChaCha with
 * 'drounds' double rounds (10 for ChaCha20) and the given key,
 * starting counter, and nonce.  Stream cipher, so the same routine
 * decrypts.  'in' and 'out' may be the same buffer.
 */
static __attribute__((noinline))
void chacha20_cipher_kernel(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12],
                            const uint8_t *in, uint8_t *out,
                            size_t inlen, int drounds) {
    __m128i s0, s1, s2;
    uint32_t n0, n1, n2;
    chacha20_setup(key, nonce, &s0, &s1, &s2, &n0, &n1, &n2);

    /* block pairs via AVX2 where available, the rest via SSE2 */
    size_t pos = 0;
    if (inlen >= 128 && have_avx2()) {
        pos = chacha20_cipher_avx2(key, counter, nonce, in, out, inlen,
                                   drounds);
        counter += (uint32_t)(pos / 64);
    }

    while (pos + 64 <= inlen) {
        __m128i s3 = chacha20_row3(counter, n0, n1, n2);
        __m128i v0, v1, v2, v3;
        chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3, drounds);

        __m128i i0 = _mm_loadu_si128((const __m128i *)(in + pos +  0));
        __m128i i1 = _mm_loadu_si128((const __m128i *)(in + pos + 16));
        __m128i i2 = _mm_loadu_si128((const __m128i *)(in + pos + 32));
        __m128i i3 = _mm_loadu_si128((const __m128i *)(in + pos + 48));

        _mm_storeu_si128((__m128i *)(out + pos +  0),
                         _mm_xor_si128(i0, v0));
        _mm_storeu_si128((__m128i *)(out + pos + 16),
                         _mm_xor_si128(i1, v1));
        _mm_storeu_si128((__m128i *)(out + pos + 32),
                         _mm_xor_si128(i2, v2));
        _mm_storeu_si128((__m128i *)(out + pos + 48),
                         _mm_xor_si128(i3, v3));

        pos += 64;
        counter++;
    }

    /* trailing partial block (< 64 bytes) */
    if (pos < inlen) {
        __m128i s3 = chacha20_row3(counter, n0, n1, n2);
        __m128i v0, v1, v2, v3;
        chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3, drounds);

        uint8_t block[64];
        _mm_storeu_si128((__m128i *)(block +  0), v0);
        _mm_storeu_si128((__m128i *)(block + 16), v1);
        _mm_storeu_si128((__m128i *)(block + 32), v2);
        _mm_storeu_si128((__m128i *)(block + 48), v3);

        size_t remaining = inlen - pos;
        for (size_t i = 0; i < remaining; i++) {
            out[pos + i] = in[pos + i] ^ block[i];
        }
    }
}

/* ChaCha core over eight consecutive blocks, one state word per
 * register, as in the four-block SSE2 kernel on wider registers. */
__attribute__((target("avx2"), always_inline))
static inline void chacha20_core8v_avx2(__m256i x[16], int drounds) {
    for (int i = 0; i < drounds; i++) {
        QUARTER_AVX2(x[0], x[4], x[ 8], x[12]);
        QUARTER_AVX2(x[1], x[5], x[ 9], x[13]);
        QUARTER_AVX2(x[2], x[6], x[10], x[14]);
        QUARTER_AVX2(x[3], x[7], x[11], x[15]);
        QUARTER_AVX2(x[0], x[5], x[10], x[15]);
        QUARTER_AVX2(x[1], x[6], x[11], x[12]);
        QUARTER_AVX2(x[2], x[7], x[ 8], x[13]);
        QUARTER_AVX2(x[3], x[4], x[ 9], x[14]);
    }
}

/*
 * Write as many pairs of interleaved four-block groups as 'ngroups'
 * allows, eight blocks per pass: the low 128-bit lane of each
 * register holds the first group's word, the high lane the second's.
 * Returns the number of groups written.
 */
__attribute__((target("avx2"), noinline))
static size_t chacha20_interleaved_avx2(const uint8_t key[32],
                                        uint32_t counter,
                                        const uint8_t nonce[12],
                                        uint8_t *out, size_t ngroups,
                                        int drounds, int key_ff_only) {
    uint32_t k[8], n[3];
    memcpy(k, key, 32);
    memcpy(n, nonce, 12);

    __m256i s[16];
    for (int i = 0; i < 4; i++)
        s[i] = _mm256_set1_epi32((int)chacha_constants[i]);
    for (int i = 0; i < 8; i++) s[4 + i]  = _mm256_set1_epi32((int)k[i]);
    for (int i = 0; i < 3; i++) s[13 + i] = _mm256_set1_epi32((int)n[i]);
    const __m256i inc = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);

    size_t g = 0;
    for (; g + 2 <= ngroups; g += 2) {
        s[12] = _mm256_add_epi32(_mm256_set1_epi32((int)counter), inc);
        __m256i x[16];
        for (int i = 0; i < 16; i++) x[i] = s[i];
        chacha20_core8v_avx2(x, drounds);

        uint8_t *o = out + 256 * g;
        for (int i = 0; i < 16; i++) {
            int add = !key_ff_only || (i >= 4 && i < 12);
            __m256i v = add ? _mm256_add_epi32(x[i], s[i]) : x[i];
            _mm_storeu_si128((__m128i *)(o + 16 * i),
                             _mm256_castsi256_si128(v));
            _mm_storeu_si128((__m128i *)(o + 256 + 16 * i),
                             _mm256_extracti128_si256(v, 1));
        }
        counter += 8;
    }
    return g;
}

/*
 * ChaCha SSE2 kernel using inter-block parallelism, as in the NEON
 * kernel of the same name: register x[i] holds word i of each of
 * four consecutive blocks.
 */
static inline __attribute__((always_inline))
void chacha20_core4v(__m128i x[16], int drounds) {
    for (int i = 0; i < drounds; i++) {
        QUARTER(x[0], x[4], x[ 8], x[12]);
        QUARTER(x[1], x[5], x[ 9], x[13]);
        QUARTER(x[2], x[6], x[10], x[14]);
        QUARTER(x[3], x[7], x[11], x[15]);
        QUARTER(x[0], x[5], x[10], x[15]);
        QUARTER(x[1], x[6], x[11], x[12]);
        QUARTER(x[2], x[7], x[ 8], x[13]);
        QUARTER(x[3], x[4], x[ 9], x[14]);
    }
}

/* Transpose four registers, each holding one word of four blocks,
 * into four each holding four consecutive words of one block. */
static inline void chacha20_transpose4(__m128i *a, __m128i *b,
                                       __m128i *c, __m128i *d) {
    __m128i t0 = _mm_unpacklo_epi32(*a, *b);
    __m128i t1 = _mm_unpacklo_epi32(*c, *d);
    __m128i t2 = _mm_unpackhi_epi32(*a, *b);
    __m128i t3 = _mm_unpackhi_epi32(*c, *d);
    *a = _mm_unpacklo_epi64(t0, t1);
    *b = _mm_unpackhi_epi64(t0, t1);
    *c = _mm_unpacklo_epi64(t2, t3);
    *d = _mm_unpackhi_epi64(t2, t3);
}

/*
 * Encrypt/decrypt the longest prefix of 'in' that is a whole number of
 * 256-byte groups of four blocks, via the four-block SSE2 core,
 * transposing each group's rows back into block order.  Returns the
 * number of bytes processed.  'in' and 'out' may be the same buffer.
 */
static __attribute__((noinline))
size_t chacha20_cipher4_kernel(const uint8_t key[32], uint32_t counter,
                               const uint8_t nonce[12],
                               const uint8_t *in, uint8_t *out,
                               size_t inlen, int drounds) {
    uint32_t k[8], n[3];
    memcpy(k, key, 32);
    memcpy(n, nonce, 12);
    __m128i s[16];
    for (int i = 0; i < 4; i++)
        s[i] = _mm_set1_epi32((int)chacha_constants[i]);
    for (int i = 0; i < 8; i++) s[4 + i]  = _mm_set1_epi32((int)k[i]);
    for (int i = 0; i < 3; i++) s[13 + i] = _mm_set1_epi32((int)n[i]);
    const __m128i inc = _mm_setr_epi32(0, 1, 2, 3);

    size_t pos = 0;
    while (pos + 256 <= inlen) {
        s[12] = _mm_add_epi32(_mm_set1_epi32((int)counter), inc);
        __m128i x[16];
        for (int i = 0; i < 16; i++) x[i] = s[i];
        chacha20_core4v(x, drounds);
        for (int i = 0; i < 16; i++) x[i] = _mm_add_epi32(x[i], s[i]);

        for (int r = 0; r < 4; r++) {
            chacha20_transpose4(&x[4 * r], &x[4 * r + 1],
                                &x[4 * r + 2], &x[4 * r + 3]);
            for (int j = 0; j < 4; j++) {
                size_t o = pos + 64 * j + 16 * r;
                __m128i v = _mm_loadu_si128((const __m128i *)(in + o));
                _mm_storeu_si128((__m128i *)(out + o),
                                 _mm_xor_si128(v, x[4 * r + j]));
            }
        }
        pos += 256;
        counter += 4;
    }
    return pos;
}

/* chacha20_transpose4 within each 128-bit lane */
__attribute__((target("avx2")))
static inline void chacha20_transpose4_avx2(__m256i *a, __m256i *b,
                                            __m256i *c, __m256i *d) {
    __m256i t0 = _mm256_unpacklo_epi32(*a, *b);
    __m256i t1 = _mm256_unpacklo_epi32(*c, *d);
    __m256i t2 = _mm256_unpackhi_epi32(*a, *b);
    __m256i t3 = _mm256_unpackhi_epi32(*c, *d);
    *a = _mm256_unpacklo_epi64(t0, t1);
    *b = _mm256_unpackhi_epi64(t0, t1);
    *c = _mm256_unpacklo_epi64(t2, t3);
    *d = _mm256_unpackhi_epi64(t2, t3);
}

/*
 * As chacha20_cipher4_kernel, eight blocks at a time via the
 * eight-block AVX2 core, for groups of 512 bytes.  After transposing,
 * register 4 * r + j holds words 4r to 4r + 3 of block j in its low
 * lane and of block j + 4 in its high lane.
 */
__attribute__((target("avx2"), noinline))
static size_t chacha20_cipher8_avx2(const uint8_t key[32],
                                    uint32_t counter,
                                    const uint8_t nonce[12],
                                    const uint8_t *in, uint8_t *out,
                                    size_t inlen, int drounds) {
    uint32_t k[8], n[3];
    memcpy(k, key, 32);
    memcpy(n, nonce, 12);
    __m256i s[16];
    for (int i = 0; i < 4; i++)
        s[i] = _mm256_set1_epi32((int)chacha_constants[i]);
    for (int i = 0; i < 8; i++) s[4 + i]  = _mm256_set1_epi32((int)k[i]);
    for (int i = 0; i < 3; i++) s[13 + i] = _mm256_set1_epi32((int)n[i]);
    const __m256i inc = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);

    size_t pos = 0;
    while (pos + 512 <= inlen) {
        s[12] = _mm256_add_epi32(_mm256_set1_epi32((int)counter), inc);
        __m256i x[16];
        for (int i = 0; i < 16; i++) x[i] = s[i];
        chacha20_core8v_avx2(x, drounds);
        for (int i = 0; i < 16; i++) x[i] = _mm256_add_epi32(x[i], s[i]);
        for (int r = 0; r < 4; r++)
            chacha20_transpose4_avx2(&x[4 * r], &x[4 * r + 1],
                                     &x[4 * r + 2], &x[4 * r + 3]);

        for (int j = 0; j < 4; j++) {
            /* words 0-7 and 8-15 of blocks j and j + 4 */
            __m256i w[4] = {
                _mm256_permute2x128_si256(x[j], x[4 + j], 0x20),
                _mm256_permute2x128_si256(x[8 + j], x[12 + j], 0x20),
                _mm256_permute2x128_si256(x[j], x[4 + j], 0x31),
                _mm256_permute2x128_si256(x[8 + j], x[12 + j], 0x31)
            };
            size_t o[4] = {
                pos + 64 * j, pos + 64 * j + 32,
                pos + 64 * (j + 4), pos + 64 * (j + 4) + 32
            };
            for (int q = 0; q < 4; q++) {
                __m256i v =
                    _mm256_loadu_si256((const __m256i *)(in + o[q]));
                _mm256_storeu_si256((__m256i *)(out + o[q]),
                                    _mm256_xor_si256(v, w[q]));
            }
        }
        pos += 512;
        counter += 8;
    }
    return pos;
}

/*
 * Write 'ngroups' groups of four consecutive keystream blocks to
 * 'out', 256 bytes per group, using 'drounds' double rounds and
 * starting at block 'counter'.  Within a group the blocks are
 * interleaved word by word: word i of block j is at byte offset
 * 16 * i + 4 * j.  If 'key_ff_only' is nonzero, the final addition of
 * the input state is applied to the key words only, omitting the
 * public constant, counter, and nonce words, as in ChaCha8Rand.
 * 'out' must not overlap 'key' or 'nonce'.
 */
static __attribute__((noinline))
void chacha20_interleaved_kernel(const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12], uint8_t *out,
                                 size_t ngroups, int drounds,
                                 int key_ff_only) {
    uint32_t k[8], n[3];
    memcpy(k, key, 32);
    memcpy(n, nonce, 12);

    __m128i s[16];
    for (int i = 0; i < 4; i++)
        s[i] = _mm_set1_epi32((int)chacha_constants[i]);
    for (int i = 0; i < 8; i++) s[4 + i]  = _mm_set1_epi32((int)k[i]);
    for (int i = 0; i < 3; i++) s[13 + i] = _mm_set1_epi32((int)n[i]);
    const __m128i inc = _mm_setr_epi32(0, 1, 2, 3);

    for (size_t g = 0; g < ngroups; g++) {
        s[12] = _mm_add_epi32(_mm_set1_epi32((int)counter), inc);
        __m128i x[16];
        for (int i = 0; i < 16; i++) x[i] = s[i];
        chacha20_core4v(x, drounds);

        uint8_t *o = out + 256 * g;
        for (int i = 0; i < 16; i++) {
            int add = !key_ff_only || (i >= 4 && i < 12);
            __m128i v = add ? _mm_add_epi32(x[i], s[i]) : x[i];
            _mm_storeu_si128((__m128i *)(o + 16 * i), v);
        }
        counter += 4;
    }
}

/* exported entry points: run each kernel, then scrub the stack */

void chacha20_block_native(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64],
                           int drounds) {
    chacha20_block_kernel(key, counter, nonce, out, drounds);
    burn_stack_small();
}

void chacha20_cipher_native(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12],
                            const uint8_t *in, uint8_t *out,
                            size_t inlen, int drounds) {
    /* groups of eight blocks via AVX2, or of four via SSE2, in kernels
     * of their own, whose frames are deeper; the rest via the cipher
     * kernel */
    size_t done = 0;
    if (have_avx2()) {
        if (inlen >= 512)
            done = chacha20_cipher8_avx2(key, counter, nonce, in, out,
                                         inlen, drounds);
    } else if (inlen >= 256) {
        done = chacha20_cipher4_kernel(key, counter, nonce, in, out,
                                       inlen, drounds);
    }
    chacha20_cipher_kernel(key, counter + (uint32_t)(done / 64), nonce,
                           in + done, out + done, inlen - done, drounds);
    if (done)
        burn_stack_large();
    else
        burn_stack_small();
}

void chacha20_interleaved_native(const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12], uint8_t *out,
                                 size_t ngroups, int drounds,
                                 int key_ff_only) {
    /* pairs of groups via AVX2 where available, the rest via SSE2, each
     * kernel called from here so that their frames don't stack */
    size_t done = 0;
    if (ngroups >= 2 && have_avx2())
        done = chacha20_interleaved_avx2(key, counter, nonce, out,
                                         ngroups, drounds, key_ff_only);
    chacha20_interleaved_kernel(key, counter + (uint32_t)(4 * done),
                                nonce, out + 256 * done, ngroups - done,
                                drounds, key_ff_only);
    burn_stack_large();
}

int chacha20_native_available(void) {
    return 1;
}

#else

/* stubs for other architectures; never reached because dispatch is
 * gated on 'chacha20_native_available' returning 0                 */

void chacha20_block_native(const uint8_t *key, uint32_t counter,
                           const uint8_t *nonce, uint8_t *out,
                           int drounds) {
    (void)key; (void)counter; (void)nonce; (void)out; (void)drounds;
}

void chacha20_cipher_native(const uint8_t *key, uint32_t counter,
                            const uint8_t *nonce,
                            const uint8_t *in, uint8_t *out,
                            size_t inlen, int drounds) {
    (void)key; (void)counter; (void)nonce;
    (void)in; (void)out; (void)inlen; (void)drounds;
}

void chacha20_interleaved_native(const uint8_t *key, uint32_t counter,
                                 const uint8_t *nonce, uint8_t *out,
                                 size_t ngroups, int drounds,
                                 int key_ff_only) {
    (void)key; (void)counter; (void)nonce; (void)out;
    (void)ngroups; (void)drounds; (void)key_ff_only;
}

int chacha20_native_available(void) {
    return 0;
}

#endif
