#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>

#define DEBUG 0
#define true 1
#define false 0

#ifdef _WIN32
	#define exportfunction __stdcall __declspec(dllexport)
#else
	#define exportfunction extern
#endif

// CPU capability detection APIs
exportfunction int GetFastestCpuMode(void);
exportfunction int IsCpuModeSupported(unsigned int cpuMode);
exportfunction const char* GetCpuModeName(int cpuMode);

// Time utility functions
exportfunction uint64_t GetTimeMs(void);
exportfunction uint64_t GetTimeUs(void);

// Assembly SHA-256 transformations
void sha256_sse4(void *input_data, uint32_t digest[8], uint64_t num_blks);
void sha256_avx(void *input_data, uint32_t digest[8], uint64_t num_blks);
void sha256_rorx(void *input_data, uint32_t digest[8], uint64_t num_blks);
void sha256_rorx_x8ms(void *input_data, uint32_t digest[8], uint64_t num_blks);
extern void sha256_ni_transform(uint32_t *digest, const void *data, uint64_t nblk);

// Hash matching filter
typedef struct {
    uint32_t prefix_mask[8];
    uint32_t prefix_val[8];
    uint32_t suffix_mask[8];
    uint32_t suffix_val[8];
    uint32_t combined_mask[8];
    uint32_t combined_val[8];
    char prefix_str[65];
    char suffix_str[65];
    int prefix_len;
    int suffix_len;
} HashFilter;

int init_hash_filter(HashFilter *filter, const char *prefix, const char *suffix);
void digest_to_hex(const uint32_t *d, char *hex);
void format_found_hash(const uint32_t *d, const HashFilter *filter, char *out);

// Nonce alphabet definitions
typedef enum {
    ALPHABET_BINARY = 0,
    ALPHABET_ASCII,
    ALPHABET_LOWER,
    ALPHABET_UPPER,
    ALPHABET_NUM,
    ALPHABET_ALPHANUM
} AlphabetType;

typedef struct {
    AlphabetType type;
    int is_binary;
    size_t size;
    uint8_t chars[256];
    char name[32];
} Alphabet;

int init_alphabet(Alphabet *alpha, const char *name);
