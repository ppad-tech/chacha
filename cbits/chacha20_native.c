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
void chacha20_block_native(const uint8_t key[32], uint32_t counter,
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
 * Encrypt/decrypt 'inlen' bytes at 'in' into 'out' using ChaCha with
 * 'drounds' double rounds (10 for ChaCha20) and the given key,
 * starting counter, and nonce.  Stream cipher, so the same routine
 * decrypts.  'in' and 'out' may be the same buffer.
 */
void chacha20_cipher_native(const uint8_t key[32], uint32_t counter,
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
void chacha20_block_native(const uint8_t key[32], uint32_t counter,
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
void chacha20_cipher_native(const uint8_t key[32], uint32_t counter,
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

int chacha20_native_available(void) {
    return 0;
}

#endif
