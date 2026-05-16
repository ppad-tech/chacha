#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__aarch64__)

#include <arm_neon.h>

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

/* 20-round ChaCha20 core: 10 iterations of (column + diagonal). */
static inline void chacha20_core(uint32x4_t *v0, uint32x4_t *v1,
                                  uint32x4_t *v2, uint32x4_t *v3,
                                  uint32x4_t s0, uint32x4_t s1,
                                  uint32x4_t s2, uint32x4_t s3) {
    uint32x4_t a = s0, b = s1, c = s2, d = s3;
    for (int i = 0; i < 10; i++) {
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

static const uint32_t chacha_constants[4] = {
    0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
};

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
 * Generate one 64-byte ChaCha20 keystream block at 'out'.
 */
void chacha20_block_arm(const uint8_t key[32], uint32_t counter,
                        const uint8_t nonce[12], uint8_t out[64]) {
    uint32x4_t s0, s1, s2;
    uint32_t n0, n1, n2;
    chacha20_setup(key, nonce, &s0, &s1, &s2, &n0, &n1, &n2);

    uint32_t s3_in[4] = { counter, n0, n1, n2 };
    uint32x4_t s3 = vld1q_u32(s3_in);
    uint32x4_t v0, v1, v2, v3;
    chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3);

    vst1q_u8(out + 0,  vreinterpretq_u8_u32(v0));
    vst1q_u8(out + 16, vreinterpretq_u8_u32(v1));
    vst1q_u8(out + 32, vreinterpretq_u8_u32(v2));
    vst1q_u8(out + 48, vreinterpretq_u8_u32(v3));
}

/*
 * Encrypt/decrypt 'inlen' bytes at 'in' into 'out' using ChaCha20
 * with the given key, starting counter, and nonce.  Stream cipher,
 * so the same routine decrypts.
 */
void chacha20_cipher_arm(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out,
                         size_t inlen) {
    uint32x4_t s0, s1, s2;
    uint32_t n0, n1, n2;
    chacha20_setup(key, nonce, &s0, &s1, &s2, &n0, &n1, &n2);

    size_t pos = 0;
    while (pos + 64 <= inlen) {
        uint32_t s3_in[4] = { counter, n0, n1, n2 };
        uint32x4_t s3 = vld1q_u32(s3_in);
        uint32x4_t v0, v1, v2, v3;
        chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3);

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
        chacha20_core(&v0, &v1, &v2, &v3, s0, s1, s2, s3);

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

int chacha20_arm_available(void) {
    return 1;
}

#else

/* stubs for non-aarch64 builds; never reached because dispatch is
 * gated on 'chacha20_arm_available' returning 0                  */

void chacha20_block_arm(const uint8_t *key, uint32_t counter,
                        const uint8_t *nonce, uint8_t *out) {
    (void)key; (void)counter; (void)nonce; (void)out;
}

void chacha20_cipher_arm(const uint8_t *key, uint32_t counter,
                         const uint8_t *nonce,
                         const uint8_t *in, uint8_t *out,
                         size_t inlen) {
    (void)key; (void)counter; (void)nonce;
    (void)in; (void)out; (void)inlen;
}

int chacha20_arm_available(void) {
    return 0;
}

#endif
