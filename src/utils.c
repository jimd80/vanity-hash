#include "d2fastlib.h"

uint64_t GetTimeUs(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (uint64_t)(tv.tv_sec) * 1000000ULL + (uint64_t)(tv.tv_usec);
}

uint64_t GetTimeMs(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (uint64_t)(tv.tv_sec) * 1000ULL + (uint64_t)(tv.tv_usec) / 1000ULL;
}

// Low-level helper to execute CPUID instruction
static inline void run_cpuid(uint32_t eax_in, uint32_t ecx_in, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx) {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuidex(cpuInfo, eax_in, ecx_in);
    *eax = cpuInfo[0];
    *ebx = cpuInfo[1];
    *ecx = cpuInfo[2];
    *edx = cpuInfo[3];
#else
    __asm__ __volatile__(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(eax_in), "c"(ecx_in)
    );
#endif
}

// Low-level helper to execute XGETBV (to verify OS saves YMM states)
static inline uint64_t run_xgetbv(uint32_t ecx_in) {
#if defined(_MSC_VER)
    return _xgetbv(ecx_in);
#else
    uint32_t eax, edx;
    __asm__ __volatile__(
        "xgetbv"
        : "=a"(eax), "=d"(edx)
        : "c"(ecx_in)
    );
    return ((uint64_t)edx << 32) | eax;
#endif
}

// Cached detection state (-1 means uninitialized)
static int cached_fastest_mode = -1;

exportfunction int IsCpuModeSupported(unsigned int cpuMode) {
#if !defined(__x86_64__) && !defined(_M_X64)
    return false; // Only x86_64 supports these instructions
#else
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    // Run basic feature flags (EAX=1)
    run_cpuid(1, 0, &eax, &ebx, &ecx, &edx);

    int has_sse41 = (ecx & (1 << 19)) != 0;
    int has_osxsave = (ecx & (1 << 27)) != 0;
    int has_avx = (ecx & (1 << 28)) != 0;

    // Verify OS saves/restores YMM registers during context switches
    int avx_os_support = 0;
    if (has_avx && has_osxsave) {
        uint64_t xcr0 = run_xgetbv(0);
        if ((xcr0 & 6) == 6) { // XMM (bit 1) and YMM (bit 2) are saved by OS
            avx_os_support = 1;
        }
    }

    if (cpuMode == 1) {
        return has_sse41;
    }

    if (cpuMode == 2) {
        return avx_os_support;
    }

    // Extended features check (EAX=7, ECX=0)
    uint32_t eax7 = 0, ebx7 = 0, ecx7 = 0, edx7 = 0;
    run_cpuid(7, 0, &eax7, &ebx7, &ecx7, &edx7);

    int has_avx2 = avx_os_support && ((ebx7 & (1 << 5)) != 0);
    int has_bmi2 = (ebx7 & (1 << 8)) != 0; // rorx is a BMI2 instruction

    if (cpuMode == 3 || cpuMode == 4) {
        return has_avx2 && has_bmi2;
    }

    if (cpuMode == 5) {
        int has_sha = (ebx7 & (1 << 29)) != 0;
        return has_sha && has_sse41; // SHA-NI relies on SSE pipeline
    }

    return false;
#endif
}

exportfunction int GetFastestCpuMode(void) {
    if (cached_fastest_mode != -1) {
        return cached_fastest_mode;
    }

    int selected = 1; // Default fallback to SSE4

    if (IsCpuModeSupported(5)) {
        selected = 5; // Intel/AMD SHA instruction set
    } else if (IsCpuModeSupported(3)) {
        selected = 3; // AVX2 with RORX optimizations
    } else if (IsCpuModeSupported(2)) {
        selected = 2; // AVX1
    } else if (IsCpuModeSupported(1)) {
        selected = 1; // SSE4.1
    }

    cached_fastest_mode = selected;
    return selected;
}

exportfunction const char* GetCpuModeName(int cpuMode) {
    switch (cpuMode) {
        case 5: return "sha";
        case 4: return "avx2xl";
        case 3: return "avx2";
        case 2: return "avx1";
        case 1: return "sse4";
        default: return "sse4";
    }
}

static inline int parse_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int init_hash_filter(HashFilter *filter, const char *prefix, const char *suffix) {
    memset(filter, 0, sizeof(HashFilter));

    if (prefix && prefix[0] != '\0') {
        filter->prefix_len = (int)strlen(prefix);
        if (filter->prefix_len > 64) return -1;
        strncpy(filter->prefix_str, prefix, 64);
        for (int i = 0; i < filter->prefix_len; i++) {
            int nib = parse_hex_digit(prefix[i]);
            if (nib < 0) return -1;
            int word_idx = i / 8;
            int nib_idx = i % 8;
            int shift = (7 - nib_idx) * 4;
            filter->prefix_mask[word_idx] |= (0xFU << shift);
            filter->prefix_val[word_idx]  |= ((uint32_t)nib << shift);
        }
    }

    if (suffix && suffix[0] != '\0') {
        filter->suffix_len = (int)strlen(suffix);
        if (filter->suffix_len > 64) return -1;
        strncpy(filter->suffix_str, suffix, 64);
        for (int i = 0; i < filter->suffix_len; i++) {
            int nib = parse_hex_digit(suffix[i]);
            if (nib < 0) return -1;
            int hash_pos = 64 - filter->suffix_len + i;
            int word_idx = hash_pos / 8;
            int nib_idx = hash_pos % 8;
            int shift = (7 - nib_idx) * 4;
            filter->suffix_mask[word_idx] |= (0xFU << shift);
            filter->suffix_val[word_idx]  |= ((uint32_t)nib << shift);
        }
    }

    // Check for conflicting constraints between prefix and suffix
    for (int i = 0; i < 8; i++) {
        uint32_t overlap = filter->prefix_mask[i] & filter->suffix_mask[i];
        if (overlap != 0) {
            if ((filter->prefix_val[i] & overlap) != (filter->suffix_val[i] & overlap)) {
                return -2; // Incompatible prefix and suffix
            }
        }
        filter->combined_mask[i] = filter->prefix_mask[i] | filter->suffix_mask[i];
        filter->combined_val[i]  = filter->prefix_val[i]  | filter->suffix_val[i];
    }

    return 0;
}

void digest_to_hex(const uint32_t *d, char *hex) {
    for (int i = 0; i < 8; i++) {
        sprintf(hex + i * 8, "%08x", d[i]);
    }
    hex[64] = '\0';
}

void format_found_hash(const uint32_t *d, const HashFilter *filter, char *out) {
    digest_to_hex(d, out);
    if (filter && filter->prefix_len > 0) {
        memcpy(out, filter->prefix_str, filter->prefix_len);
    }
    if (filter && filter->suffix_len > 0) {
        memcpy(out + 64 - filter->suffix_len, filter->suffix_str, filter->suffix_len);
    }
}

int init_alphabet(Alphabet *alpha, const char *name) {
    memset(alpha, 0, sizeof(Alphabet));

    if (!name || strcasecmp(name, "binary") == 0 || strcasecmp(name, "bin") == 0) {
        alpha->type = ALPHABET_BINARY;
        alpha->is_binary = 1;
        alpha->size = 256;
        for (int i = 0; i < 256; i++) {
            alpha->chars[i] = (uint8_t)i;
        }
        strncpy(alpha->name, "binary", sizeof(alpha->name) - 1);
        return 0;
    }

    if (strcasecmp(name, "ascii") == 0) {
        alpha->type = ALPHABET_ASCII;
        alpha->is_binary = 0;
        alpha->size = 0;
        for (int i = 32; i <= 127; i++) {
            alpha->chars[alpha->size++] = (uint8_t)i;
        }
        strncpy(alpha->name, "ascii", sizeof(alpha->name) - 1);
        return 0;
    }

    if (strcasecmp(name, "lower") == 0 || strcasecmp(name, "lowercase") == 0) {
        alpha->type = ALPHABET_LOWER;
        alpha->is_binary = 0;
        alpha->size = 0;
        for (int i = 'a'; i <= 'z'; i++) {
            alpha->chars[alpha->size++] = (uint8_t)i;
        }
        strncpy(alpha->name, "lower", sizeof(alpha->name) - 1);
        return 0;
    }

    if (strcasecmp(name, "upper") == 0 || strcasecmp(name, "uppercase") == 0) {
        alpha->type = ALPHABET_UPPER;
        alpha->is_binary = 0;
        alpha->size = 0;
        for (int i = 'A'; i <= 'Z'; i++) {
            alpha->chars[alpha->size++] = (uint8_t)i;
        }
        strncpy(alpha->name, "upper", sizeof(alpha->name) - 1);
        return 0;
    }

    if (strcasecmp(name, "num") == 0 || strcasecmp(name, "numeric") == 0 ||
        strcasecmp(name, "digits") == 0 || strcasecmp(name, "digit") == 0 ||
        strcasecmp(name, "numbers") == 0 || strcasecmp(name, "number") == 0) {
        alpha->type = ALPHABET_NUM;
        alpha->is_binary = 0;
        alpha->size = 0;
        for (int i = '0'; i <= '9'; i++) {
            alpha->chars[alpha->size++] = (uint8_t)i;
        }
        strncpy(alpha->name, "num", sizeof(alpha->name) - 1);
        return 0;
    }

    if (strcasecmp(name, "alphanum") == 0 || strcasecmp(name, "alphanumeric") == 0) {
        alpha->type = ALPHABET_ALPHANUM;
        alpha->is_binary = 0;
        alpha->size = 0;
        for (int i = 'a'; i <= 'z'; i++) {
            alpha->chars[alpha->size++] = (uint8_t)i;
        }
        for (int i = 'A'; i <= 'Z'; i++) {
            alpha->chars[alpha->size++] = (uint8_t)i;
        }
        for (int i = '0'; i <= '9'; i++) {
            alpha->chars[alpha->size++] = (uint8_t)i;
        }
        strncpy(alpha->name, "alphanum", sizeof(alpha->name) - 1);
        return 0;
    }

    return -1;
}
