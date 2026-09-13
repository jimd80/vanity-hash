#include "d2fastlib.h"

static inline void sha256_transform_blocks(int cpuMode, uint32_t digest[8], const void *data, uint64_t num_blks) {
    if (cpuMode == 5) {
        sha256_ni_transform(digest, data, num_blks);
    } else if (cpuMode == 3) {
        sha256_rorx((void*)data, digest, num_blks);
    } else if (cpuMode == 4) {
        sha256_rorx_x8ms((void*)data, digest, num_blks);
    } else if (cpuMode == 2) {
        sha256_avx((void*)data, digest, num_blks);
    } else {
        sha256_sse4((void*)data, digest, num_blks);
    }
}

// Compute full SHA256 of buffer in memory (used for verification)
void sha256_compute(const uint8_t *data, size_t len, uint32_t digest[8], int cpuMode) {
    digest[0] = 0x6a09e667;
    digest[1] = 0xbb67ae85;
    digest[2] = 0x3c6ef372;
    digest[3] = 0xa54ff53a;
    digest[4] = 0x510e527f;
    digest[5] = 0x9b05688c;
    digest[6] = 0x1f83d9ab;
    digest[7] = 0x5be0cd19;

    size_t rem = (len + 1) % 64;
    size_t pad_zeros = (rem <= 56) ? (56 - rem) : (56 + 64 - rem);
    size_t padded_len = len + 1 + pad_zeros + 8;
    size_t num_blocks = padded_len / 64;

    uint8_t *padded = (uint8_t*)calloc(num_blocks, 64);
    if (!padded) return;

    if (len > 0 && data) {
        memcpy(padded, data, len);
    }
    padded[len] = 0x80;

    uint64_t bit_len = (uint64_t)len * 8ULL;
    for (int i = 0; i < 8; i++) {
        padded[padded_len - 8 + i] = (uint8_t)(bit_len >> ((7 - i) * 8));
    }

    sha256_transform_blocks(cpuMode, digest, padded, num_blocks);
    free(padded);
}
