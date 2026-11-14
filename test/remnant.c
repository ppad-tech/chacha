#include <stddef.h>
#include <stdint.h>
#include <string.h>

void chacha20_block_native(const uint8_t *key, uint32_t counter,
                           const uint8_t *nonce, uint8_t *out,
                           int drounds);
void chacha20_cipher_native(const uint8_t *key, uint32_t counter,
                            const uint8_t *nonce, const uint8_t *in,
                            uint8_t *out, size_t inlen, int drounds);
void chacha20_interleaved_native(const uint8_t *key, uint32_t counter,
                                 const uint8_t *nonce, uint8_t *out,
                                 size_t ngroups, int drounds,
                                 int key_ff_only);

#define SCAN 8192

/* the eight key words, distinct and without repeated bytes */
static const uint32_t key_words[8] = {
    0x1b2c3d4e, 0x5f607182, 0x93a4b5c6, 0xd7e8f90a,
    0x2b3c4d5e, 0x6f708192, 0xa3b4c5d6, 0xe7f8091a
};

/* Does the region contain a key half (four consecutive key words, as
 * a kernel holding a row of the state would store them) or a key word
 * repeated four times (as one holding a broadcast word would)? */
static int has_remnant(const volatile uint8_t *p, size_t n) {
    for (size_t i = 0; i + 16 <= n; i++) {
        uint32_t w[4];
        for (int j = 0; j < 4; j++) {
            uint8_t b[4];
            for (int k = 0; k < 4; k++) b[k] = p[i + 4 * j + k];
            memcpy(&w[j], b, 4);
        }
        for (int h = 0; h < 8; h += 4)
            if (w[0] == key_words[h]     && w[1] == key_words[h + 1] &&
                w[2] == key_words[h + 2] && w[3] == key_words[h + 3])
                return 1;
        for (int k = 0; k < 8; k++)
            if (w[0] == key_words[k] && w[1] == key_words[k] &&
                w[2] == key_words[k] && w[3] == key_words[k])
                return 1;
    }
    return 0;
}

/* Scan the stack region below this frame, where the kernel's frame
 * was, after calling it. */
__attribute__((noinline))
static int scan_below(void) {
    volatile uint8_t here = 0;
    const volatile uint8_t *top = &here;
    return has_remnant(top - SCAN, SCAN);
}

static uint8_t key[32], nonce[12], buf[1024];

__attribute__((noinline))
static void call_kernel(int which, int drounds) {
    switch (which) {
    case 0: chacha20_block_native(key, 1, nonce, buf, drounds); break;
    case 1: chacha20_cipher_native(key, 1, nonce, buf, buf, 100,
                                   drounds); break;
    case 2: chacha20_cipher_native(key, 1, nonce, buf, buf, 1024,
                                   drounds); break;
    case 3: chacha20_interleaved_native(key, 0, nonce, buf, 1, drounds,
                                        1); break;
    default: chacha20_interleaved_native(key, 0, nonce, buf, 4,
                                         drounds, 1); break;
    }
}

/*
 * Call the given kernel (0: block, 1: short cipher, 2: long cipher,
 * 3: one interleaved group, 4: four interleaved groups) with a known
 * key, and report whether any of the key remains on the stack
 * afterwards.  call_kernel and scan_below are called from the same
 * frame, so the scanned region covers the kernel's.
 */
int chacha_test_remnant(int which, int drounds) {
    memcpy(key, key_words, 32);
    memset(nonce, 0, sizeof nonce);
    memset(buf, 0, sizeof buf);
    call_kernel(which, drounds);
    return scan_below();
}
