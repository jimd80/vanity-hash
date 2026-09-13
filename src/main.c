#include "d2fastlib.h"
#include "utils.c"
#include "sha256.c"

#define VERSION "v0.0.0"

typedef enum {
    OFFSET_MODE_APPEND = 0,
    OFFSET_MODE_LAST,
    OFFSET_MODE_EXACT
} NonceOffsetMode;

static void print_help(void) {
    printf("vanity-hash %s Modifies a file with a nonce so its hash contains magic words\n\n", VERSION);
    printf("usage: vanity-hash <options> infile [outfile]\n\n");
    printf("remarks:\n");
    printf("  - when outfile is omitted, infile is overwritten!\n");
    printf("  - 4-bit boundaries are supported, like --start-with 123\n");
    printf("  - placing the nonce at the start of large files will make it unusably slow\n\n");
    printf("options:\n");
    printf("  -h --hash          Hashing algorithm to use. Default sha256 (only supported for now)\n");
    printf("  -s --start-with    Hash needs to start with (4-bit boundaries supported). Example: --start-with 123\n");
    printf("  -e --ends-with     Hash needs to end with (4-bit boundaries supported). Example: --ends-with cafe\n");
    printf("  -a --alphabet      Allowed characters in the nonce: ascii (32-127), lower (a-z), upper (A-Z),\n");
    printf("                     num (0-9), alphanum (a-Z,0-9), binary (default)\n");
    printf("  -t --timeout       Give up after a number of seconds (default infinite)\n");
    printf("  -o --nonce-offset  Nonce placement: 'append' (default), 'last' (overwrites the end of the file\n");
    printf("                     growing backwards), or a byte offset number to overwrite a section in the file\n");
    printf("  -n --nonce-size    Fixed size of the nonce in bytes. Default is a dynamic size.\n");
}

static int parse_offset_arg(const char *val, NonceOffsetMode *mode, int64_t *offset) {
    if (strcasecmp(val, "append") == 0) {
        *mode = OFFSET_MODE_APPEND;
        return 0;
    }
    if (strcasecmp(val, "last") == 0) {
        *mode = OFFSET_MODE_LAST;
        return 0;
    }
    char *endptr = NULL;
    errno = 0;
    long long num = strtoll(val, &endptr, 10);
    if (errno == 0 && endptr != val && *endptr == '\0' && num >= 0) {
        *mode = OFFSET_MODE_EXACT;
        *offset = (int64_t)num;
        return 0;
    }
    return -1;
}

static void format_approx_hashes(int hex_digits, char *buf, size_t size) {
    if (hex_digits == 0) {
        snprintf(buf, size, "1 hashes");
        return;
    }
    double val = pow(16.0, hex_digits);
    if (val < 1000.0) {
        snprintf(buf, size, "%.0f hashes", val);
    } else if (val < 1000000.0) {
        if (val < 10000.0)
            snprintf(buf, size, "%.1fK hashes", val / 1000.0);
        else
            snprintf(buf, size, "%.0fK hashes", val / 1000.0);
    } else if (val < 1000000000.0) {
        if (val < 10000000.0)
            snprintf(buf, size, "%.1fM hashes", val / 1000.0);
        else
            snprintf(buf, size, "%.0fM hashes", val / 1000.0);
    } else if (val < 1000000000000.0) {
        if (val < 10000000000.0)
            snprintf(buf, size, "%.1fG hashes", val / 1000000000.0);
        else
            snprintf(buf, size, "%.0fG hashes", val / 1000000000.0);
    } else {
        snprintf(buf, size, "%.1fT hashes", val / 1000000000000.0);
    }
}

static void format_count(uint64_t count, char *buf, size_t size) {
    double val = (double)count;
    if (val < 1000.0) {
        snprintf(buf, size, "%" PRIu64, count);
    } else if (val < 1000000.0) {
        if (val < 10000.0)
            snprintf(buf, size, "%.1fK", val / 1000.0);
        else
            snprintf(buf, size, "%.0fK", val / 1000.0);
    } else if (val < 1000000000.0) {
        if (val < 10000000.0)
            snprintf(buf, size, "%.1fM", val / 1000.0);
        else
            snprintf(buf, size, "%.0fM", val / 1000.0);
    } else if (val < 1000000000000.0) {
        if (val < 10000000000.0)
            snprintf(buf, size, "%.1fG", val / 1000000000.0);
        else
            snprintf(buf, size, "%.0fG", val / 1000000000.0);
    } else {
        snprintf(buf, size, "%.1fT", val / 1000000000.0);
    }
}

static inline void write_nonce_binary(uint8_t *dest, uint64_t nonce, int size) {
    if (size == 1) {
        dest[0] = (uint8_t)nonce;
    } else if (size == 2) {
        *(uint16_t*)dest = (uint16_t)nonce;
    } else if (size == 4) {
        *(uint32_t*)dest = (uint32_t)nonce;
    } else if (size == 8) {
        *(uint64_t*)dest = nonce;
    } else {
        for (int i = 0; i < size; i++) {
            dest[i] = (uint8_t)(nonce >> (8 * i));
        }
    }
}

static inline void write_nonce_custom(uint8_t *dest, uint64_t nonce, int size, const uint8_t *chars, size_t base) {
    uint64_t v = nonce;
    for (int i = 0; i < size; i++) {
        dest[i] = chars[v % base];
        v /= base;
    }
}

typedef struct {
    int thread_id;
    int cpu_mode;
    int nonce_size;
    size_t local_nonce_offset;
    size_t num_blocks;
    size_t template_len;
    const uint8_t *template_buf;
    const uint32_t *base_state;
    const HashFilter *filter;
    const Alphabet *alpha;
    volatile int *stop_flag;
    volatile int *found_flag;
    uint64_t *global_nonce_counter;
    uint64_t max_nonce;
    uint64_t winning_nonce;
    uint32_t winning_digest[8];
    int matched;
} WorkerContext;

static void *search_worker(void *arg) {
    WorkerContext *ctx = (WorkerContext*)arg;
    int cpu_mode = ctx->cpu_mode;
    int nonce_size = ctx->nonce_size;
    size_t local_nonce_offset = ctx->local_nonce_offset;
    size_t num_blocks = ctx->num_blocks;
    const HashFilter *filter = ctx->filter;
    const Alphabet *alpha = ctx->alpha;

    uint8_t *local_buf = NULL;
    if (posix_memalign((void**)&local_buf, 64, ctx->template_len) != 0) {
        local_buf = (uint8_t*)malloc(ctx->template_len);
    }
    if (!local_buf) return NULL;
    memcpy(local_buf, ctx->template_buf, ctx->template_len);

    uint32_t cm0 = filter->combined_mask[0], cv0 = filter->combined_val[0];
    uint32_t cm7 = filter->combined_mask[7], cv7 = filter->combined_val[7];

    uint64_t chunk_size = 32768;
    if (ctx->max_nonce < chunk_size) {
        chunk_size = (ctx->max_nonce < 256) ? ctx->max_nonce : 256;
        if (chunk_size == 0) chunk_size = 1;
    }

    if (alpha->is_binary) {
        while (!__atomic_load_n(ctx->stop_flag, __ATOMIC_RELAXED)) {
            uint64_t start_nonce = __atomic_fetch_add(ctx->global_nonce_counter, chunk_size, __ATOMIC_RELAXED);
            if (start_nonce >= ctx->max_nonce) {
                break;
            }
            uint64_t end_nonce = start_nonce + chunk_size;
            if (end_nonce > ctx->max_nonce || end_nonce < start_nonce) {
                end_nonce = ctx->max_nonce;
            }

            for (uint64_t nonce = start_nonce; nonce < end_nonce; nonce++) {
                write_nonce_binary(local_buf + local_nonce_offset, nonce, nonce_size);

                uint32_t digest[8];
                memcpy(digest, ctx->base_state, sizeof(digest));

                sha256_transform_blocks(cpu_mode, digest, local_buf, num_blocks);

                if ((digest[0] & cm0) != cv0) continue;
                if ((digest[7] & cm7) != cv7) continue;

                int match = 1;
                for (int w = 1; w < 7; w++) {
                    if ((digest[w] & filter->combined_mask[w]) != filter->combined_val[w]) {
                        match = 0;
                        break;
                    }
                }
                if (!match) continue;

                // String verification against prefix and suffix
                char hex[65];
                digest_to_hex(digest, hex);
                if (filter->prefix_len > 0 && strncasecmp(hex, filter->prefix_str, filter->prefix_len) != 0) {
                    continue;
                }
                if (filter->suffix_len > 0 && strncasecmp(hex + 64 - filter->suffix_len, filter->suffix_str, filter->suffix_len) != 0) {
                    continue;
                }

                // Match found
                ctx->winning_nonce = nonce;
                memcpy(ctx->winning_digest, digest, sizeof(digest));
                ctx->matched = 1;
                __atomic_store_n(ctx->found_flag, 1, __ATOMIC_RELAXED);
                __atomic_store_n(ctx->stop_flag, 1, __ATOMIC_RELAXED);
                break;
            }
        }
    } else {
        const uint8_t *chars = alpha->chars;
        size_t base = alpha->size;

        while (!__atomic_load_n(ctx->stop_flag, __ATOMIC_RELAXED)) {
            uint64_t start_nonce = __atomic_fetch_add(ctx->global_nonce_counter, chunk_size, __ATOMIC_RELAXED);
            if (start_nonce >= ctx->max_nonce) {
                break;
            }
            uint64_t end_nonce = start_nonce + chunk_size;
            if (end_nonce > ctx->max_nonce || end_nonce < start_nonce) {
                end_nonce = ctx->max_nonce;
            }

            for (uint64_t nonce = start_nonce; nonce < end_nonce; nonce++) {
                write_nonce_custom(local_buf + local_nonce_offset, nonce, nonce_size, chars, base);

                uint32_t digest[8];
                memcpy(digest, ctx->base_state, sizeof(digest));

                sha256_transform_blocks(cpu_mode, digest, local_buf, num_blocks);

                if ((digest[0] & cm0) != cv0) continue;
                if ((digest[7] & cm7) != cv7) continue;

                int match = 1;
                for (int w = 1; w < 7; w++) {
                    if ((digest[w] & filter->combined_mask[w]) != filter->combined_val[w]) {
                        match = 0;
                        break;
                    }
                }
                if (!match) continue;

                char hex[65];
                digest_to_hex(digest, hex);
                if (filter->prefix_len > 0 && strncasecmp(hex, filter->prefix_str, filter->prefix_len) != 0) {
                    continue;
                }
                if (filter->suffix_len > 0 && strncasecmp(hex + 64 - filter->suffix_len, filter->suffix_str, filter->suffix_len) != 0) {
                    continue;
                }

                ctx->winning_nonce = nonce;
                memcpy(ctx->winning_digest, digest, sizeof(digest));
                ctx->matched = 1;
                __atomic_store_n(ctx->found_flag, 1, __ATOMIC_RELAXED);
                __atomic_store_n(ctx->stop_flag, 1, __ATOMIC_RELAXED);
                break;
            }
        }
    }

    free(local_buf);
    return NULL;
}

int main(int argc, char *argv[]) {
    const char *hash_algo = "sha256";
    const char *start_with = NULL;
    const char *ends_with = NULL;
    const char *alphabet_name = "binary";
    double timeout_sec = -1.0;
    NonceOffsetMode offset_mode = OFFSET_MODE_APPEND;
    int64_t exact_offset = 0;
    int fixed_nonce_size = 0; // 0 means dynamic
    const char *infile = NULL;
    const char *outfile = NULL;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-?") == 0) {
            print_help();
            return 0;
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--hash") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                hash_algo = argv[++i];
            }
        } else if (strncmp(arg, "--hash=", 7) == 0) {
            hash_algo = arg + 7;
        } else if (strncmp(arg, "-h", 2) == 0 && strlen(arg) > 2) {
            hash_algo = arg + 2;
        } else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--start-with") == 0) {
            if (i + 1 < argc) start_with = argv[++i];
            else { print_help(); return 1; }
        } else if (strncmp(arg, "--start-with=", 13) == 0) {
            start_with = arg + 13;
        } else if (strncmp(arg, "-s", 2) == 0 && strlen(arg) > 2) {
            start_with = arg + 2;
        } else if (strcmp(arg, "-e") == 0 || strcmp(arg, "--ends-with") == 0) {
            if (i + 1 < argc) ends_with = argv[++i];
            else { print_help(); return 1; }
        } else if (strncmp(arg, "--ends-with=", 12) == 0) {
            ends_with = arg + 12;
        } else if (strncmp(arg, "-e", 2) == 0 && strlen(arg) > 2) {
            ends_with = arg + 2;
        } else if (strcmp(arg, "-a") == 0 || strcmp(arg, "--alphabet") == 0) {
            if (i + 1 < argc) alphabet_name = argv[++i];
            else { print_help(); return 1; }
        } else if (strncmp(arg, "--alphabet=", 11) == 0) {
            alphabet_name = arg + 11;
        } else if (strncmp(arg, "-a", 2) == 0 && strlen(arg) > 2) {
            alphabet_name = arg + 2;
        } else if (strcmp(arg, "-t") == 0 || strcmp(arg, "--timeout") == 0) {
            if (i + 1 < argc) timeout_sec = atof(argv[++i]);
            else { print_help(); return 1; }
        } else if (strncmp(arg, "--timeout=", 10) == 0) {
            timeout_sec = atof(arg + 10);
        } else if (strncmp(arg, "-t", 2) == 0 && strlen(arg) > 2) {
            timeout_sec = atof(arg + 2);
        } else if (strcmp(arg, "-o") == 0 || strcmp(arg, "--nonce-offset") == 0) {
            if (i + 1 < argc) {
                const char *val = argv[++i];
                if (parse_offset_arg(val, &offset_mode, &exact_offset) != 0) {
                    fprintf(stderr, "Error: Invalid nonce offset '%s'. Supported values: 'append', 'last', or a byte offset number.\n", val);
                    return 1;
                }
            } else {
                print_help();
                return 1;
            }
        } else if (strncmp(arg, "--nonce-offset=", 15) == 0) {
            const char *val = arg + 15;
            if (parse_offset_arg(val, &offset_mode, &exact_offset) != 0) {
                fprintf(stderr, "Error: Invalid nonce offset '%s'. Supported values: 'append', 'last', or a byte offset number.\n", val);
                return 1;
            }
        } else if (strncmp(arg, "-o", 2) == 0 && strlen(arg) > 2) {
            const char *val = arg + 2;
            if (parse_offset_arg(val, &offset_mode, &exact_offset) != 0) {
                fprintf(stderr, "Error: Invalid nonce offset '%s'. Supported values: 'append', 'last', or a byte offset number.\n", val);
                return 1;
            }
        } else if (strcmp(arg, "-n") == 0 || strcmp(arg, "--nonce-size") == 0) {
            if (i + 1 < argc) fixed_nonce_size = atoi(argv[++i]);
            else { print_help(); return 1; }
        } else if (strncmp(arg, "--nonce-size=", 13) == 0) {
            fixed_nonce_size = atoi(arg + 13);
        } else if (strncmp(arg, "-n", 2) == 0 && strlen(arg) > 2) {
            fixed_nonce_size = atoi(arg + 2);
        } else if (arg[0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", arg);
            print_help();
            return 1;
        } else {
            if (!infile) {
                infile = arg;
            } else if (!outfile) {
                outfile = arg;
            } else {
                fprintf(stderr, "Unexpected extra argument: %s\n", arg);
                print_help();
                return 1;
            }
        }
    }

    if (!infile) {
        print_help();
        return 1;
    }

    if (strcasecmp(hash_algo, "sha256") != 0) {
        fprintf(stderr, "Error: Unsupported hash algorithm '%s'. Only sha256 is supported.\n", hash_algo);
        return 1;
    }

    Alphabet alpha;
    if (init_alphabet(&alpha, alphabet_name) != 0) {
        fprintf(stderr, "Error: Unsupported alphabet '%s'. Supported values: ascii (32-127), lower (a-z), upper (A-Z), num (0-9), alphanum (a-Z,0-9), binary (default)\n", alphabet_name);
        return 1;
    }

    if (fixed_nonce_size < 0) {
        fprintf(stderr, "Error: Invalid nonce size %d.\n", fixed_nonce_size);
        return 1;
    }

    HashFilter filter;
    int filter_res = init_hash_filter(&filter, start_with, ends_with);
    if (filter_res == -1) {
        fprintf(stderr, "Error: Invalid hex pattern specified for --start-with or --ends-with.\n");
        return 1;
    } else if (filter_res == -2) {
        fprintf(stderr, "Error: Conflicting constraints in --start-with and --ends-with.\n");
        return 1;
    }

    // Read input file
    FILE *fin = fopen(infile, "rb");
    if (!fin) {
        fprintf(stderr, "Error: cannot open input file '%s': %s\n", infile, strerror(errno));
        return 1;
    }
    fseek(fin, 0, SEEK_END);
    long in_file_size_long = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    size_t in_file_size = (size_t)in_file_size_long;
    uint8_t *in_file_data = NULL;
    if (in_file_size > 0) {
        in_file_data = (uint8_t*)malloc(in_file_size);
        if (!in_file_data || fread(in_file_data, 1, in_file_size, fin) != in_file_size) {
            fprintf(stderr, "Error reading input file '%s'.\n", infile);
            fclose(fin);
            if (in_file_data) free(in_file_data);
            return 1;
        }
    }
    fclose(fin);

    int cpu_mode = GetFastestCpuMode();
    const char *cpu_mode_name = GetCpuModeName(cpu_mode);

    int total_vanity_hex = filter.prefix_len + filter.suffix_len;
    char approx_buf[64];
    format_approx_hashes(total_vanity_hex, approx_buf, sizeof(approx_buf));

    printf("vanity-hash %s started with cpu mode %s\n", VERSION, cpu_mode_name);
    printf("searching will take approx. %s\n", approx_buf);

    int num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads < 1) num_threads = 1;
    if (num_threads > 64) num_threads = 64;

    int min_size = (fixed_nonce_size > 0) ? fixed_nonce_size : 1;
    int max_size = (fixed_nonce_size > 0) ? fixed_nonce_size : 32;

    uint64_t start_time_ms = GetTimeMs();
    uint64_t timeout_end_ms = (timeout_sec > 0.0) ? (start_time_ms + (uint64_t)(timeout_sec * 1000.0)) : 0;
    uint64_t cumulative_hashes = 0;

    int match_found = 0;
    uint64_t winning_nonce = 0;
    int winning_nonce_size = 0;
    size_t winning_actual_offset = 0;
    size_t winning_mod_file_size = 0;
    uint32_t winning_digest[8];

    int is_tty = isatty(STDOUT_FILENO);
    int progress_lines_printed = 0;
    uint64_t last_progress_ms = 0;

    for (int curr_size = min_size; curr_size <= max_size && !match_found; curr_size++) {
        // Calculate file layout and nonce offset
        size_t actual_offset = 0;
        size_t mod_file_size = 0;

        if (offset_mode == OFFSET_MODE_APPEND) {
            actual_offset = in_file_size;
            mod_file_size = in_file_size + curr_size;
        } else if (offset_mode == OFFSET_MODE_LAST) {
            if (in_file_size >= (size_t)curr_size) {
                actual_offset = in_file_size - curr_size;
                mod_file_size = in_file_size;
            } else {
                actual_offset = 0;
                mod_file_size = curr_size;
            }
        } else {
            actual_offset = (size_t)exact_offset;
            size_t end_pos = actual_offset + curr_size;
            mod_file_size = (end_pos > in_file_size) ? end_pos : in_file_size;
        }

        // Construct modified file template
        uint8_t *mod_file = (uint8_t*)calloc(1, mod_file_size + 1);
        if (in_file_size > 0 && in_file_data) {
            memcpy(mod_file, in_file_data, in_file_size);
        }

        // SHA-256 padding layout
        size_t rem = (mod_file_size + 1) % 64;
        size_t pad_zeros = (rem <= 56) ? (56 - rem) : (56 + 64 - rem);
        size_t padded_len = mod_file_size + 1 + pad_zeros + 8;
        size_t total_blocks = padded_len / 64;

        uint8_t *full_padded = (uint8_t*)calloc(total_blocks, 64);
        memcpy(full_padded, mod_file, mod_file_size);
        full_padded[mod_file_size] = 0x80;
        uint64_t bit_len = (uint64_t)mod_file_size * 8ULL;
        for (int b = 0; b < 8; b++) {
            full_padded[padded_len - 8 + b] = (uint8_t)(bit_len >> ((7 - b) * 8));
        }

        // Pre-hash blocks before the nonce
        size_t pre_blocks = actual_offset / 64;
        uint32_t base_state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        if (pre_blocks > 0) {
            sha256_transform_blocks(cpu_mode, base_state, full_padded, pre_blocks);
        }

        size_t remaining_blocks = total_blocks - pre_blocks;
        size_t template_len = remaining_blocks * 64;
        uint8_t *template_buf = full_padded + (pre_blocks * 64);
        size_t local_nonce_offset = actual_offset - (pre_blocks * 64);

        uint64_t max_nonce_val = 1;
        int overflow = 0;
        for (int i = 0; i < curr_size; i++) {
            if (max_nonce_val > UINT64_MAX / alpha.size) {
                overflow = 1;
                break;
            }
            max_nonce_val *= alpha.size;
        }
        if (overflow) {
            max_nonce_val = UINT64_MAX;
        }

        volatile int stop_flag = 0;
        volatile int found_flag = 0;
        uint64_t stage_nonce_counter = 0;

        pthread_t threads[64];
        WorkerContext contexts[64];

        for (int t = 0; t < num_threads; t++) {
            contexts[t].thread_id = t;
            contexts[t].cpu_mode = cpu_mode;
            contexts[t].nonce_size = curr_size;
            contexts[t].local_nonce_offset = local_nonce_offset;
            contexts[t].num_blocks = remaining_blocks;
            contexts[t].template_len = template_len;
            contexts[t].template_buf = template_buf;
            contexts[t].base_state = base_state;
            contexts[t].filter = &filter;
            contexts[t].alpha = &alpha;
            contexts[t].stop_flag = &stop_flag;
            contexts[t].found_flag = &found_flag;
            contexts[t].global_nonce_counter = &stage_nonce_counter;
            contexts[t].max_nonce = max_nonce_val;
            contexts[t].matched = 0;
            pthread_create(&threads[t], NULL, search_worker, &contexts[t]);
        }

        // Monitor loop for progress and timeouts
        while (!found_flag && stage_nonce_counter < max_nonce_val) {
            usleep(50000); // 50ms
            uint64_t now_ms = GetTimeMs();

            if (timeout_end_ms > 0 && now_ms >= timeout_end_ms) {
                stop_flag = 1;
                break;
            }

            if (now_ms - last_progress_ms >= 500) {
                last_progress_ms = now_ms;
                uint64_t curr_stage_hashes = stage_nonce_counter;
                if (curr_stage_hashes > max_nonce_val) curr_stage_hashes = max_nonce_val;
                uint64_t total_done = cumulative_hashes + curr_stage_hashes;

                double elapsed_sec = (double)(now_ms - start_time_ms) / 1000.0;
                double rate = (elapsed_sec > 0.001) ? ((double)total_done / elapsed_sec) : 0.0;
                double mhash_sec = rate / 1000000.0;
                double approx_total = pow(16.0, total_vanity_hex);
                double est_sec = (rate > 0.0) ? (approx_total / rate) : 0.0;

                char searched_str[64];
                format_count(total_done, searched_str, sizeof(searched_str));

                if (is_tty) {
                    if (progress_lines_printed > 0) {
                        printf("\033[2A");
                    }
                    printf("\033[2Ktime running: %.0fs (estimated: %.0fs)\n\033[2Khashes searched: %s (%.1f MHash/sec)\n",
                           elapsed_sec, est_sec, searched_str, mhash_sec);
                    fflush(stdout);
                    progress_lines_printed = 1;
                }
            }
        }

        stop_flag = 1;
        for (int t = 0; t < num_threads; t++) {
            pthread_join(threads[t], NULL);
            if (contexts[t].matched) {
                match_found = 1;
                winning_nonce = contexts[t].winning_nonce;
                winning_nonce_size = curr_size;
                winning_actual_offset = actual_offset;
                winning_mod_file_size = mod_file_size;
                memcpy(winning_digest, contexts[t].winning_digest, sizeof(winning_digest));
            }
        }

        uint64_t stage_final_hashes = stage_nonce_counter;
        if (stage_final_hashes > max_nonce_val) stage_final_hashes = max_nonce_val;
        cumulative_hashes += stage_final_hashes;

        free(full_padded);
        free(mod_file);

        if (timeout_end_ms > 0 && GetTimeMs() >= timeout_end_ms && !match_found) {
            break;
        }
    }

    uint64_t end_time_ms = GetTimeMs();
    double total_elapsed_sec = (double)(end_time_ms - start_time_ms) / 1000.0;
    double final_rate = (total_elapsed_sec > 0.001) ? ((double)cumulative_hashes / total_elapsed_sec) : 0.0;
    double final_mhash_sec = final_rate / 1000000.0;
    double approx_total = pow(16.0, total_vanity_hex);
    double est_sec = (final_rate > 0.0) ? (approx_total / final_rate) : 0.0;

    char final_searched_str[64];
    format_count(cumulative_hashes, final_searched_str, sizeof(final_searched_str));

    if (is_tty && progress_lines_printed > 0) {
        printf("\033[2A\033[2Ktime running: %.0fs (estimated: %.0fs)\n\033[2Khashes searched: %s (%.1f MHash/sec)\n",
               total_elapsed_sec, est_sec, final_searched_str, final_mhash_sec);
    } else {
        printf("time running: %.0fs (estimated: %.0fs)\n", total_elapsed_sec, est_sec);
        printf("hashes searched: %s (%.1f MHash/sec)\n", final_searched_str, final_mhash_sec);
    }

    if (!match_found) {
        if (timeout_end_ms > 0 && end_time_ms >= timeout_end_ms) {
            printf("\nTimeout reached. No matching hash found.\n");
        } else {
            printf("\nSearch space exhausted. No matching hash found.\n");
        }
        if (in_file_data) free(in_file_data);
        return 1;
    }

    // Construct final modified file content
    uint8_t *out_data = (uint8_t*)calloc(1, winning_mod_file_size + 1);
    if (in_file_size > 0 && in_file_data) {
        memcpy(out_data, in_file_data, in_file_size);
    }
    if (alpha.is_binary) {
        write_nonce_binary(out_data + winning_actual_offset, winning_nonce, winning_nonce_size);
    } else {
        write_nonce_custom(out_data + winning_actual_offset, winning_nonce, winning_nonce_size, alpha.chars, alpha.size);
    }

    // Write to output file (or overwrite infile)
    const char *target_file = outfile ? outfile : infile;
    FILE *fout = fopen(target_file, "wb");
    if (!fout) {
        fprintf(stderr, "Error opening output file '%s' for writing: %s\n", target_file, strerror(errno));
        free(out_data);
        if (in_file_data) free(in_file_data);
        return 1;
    }
    if (winning_mod_file_size > 0) {
        if (fwrite(out_data, 1, winning_mod_file_size, fout) != winning_mod_file_size) {
            fprintf(stderr, "Error writing to output file '%s': %s\n", target_file, strerror(errno));
            fclose(fout);
            free(out_data);
            if (in_file_data) free(in_file_data);
            return 1;
        }
    }
    fclose(fout);

    char found_hash_str[65];
    format_found_hash(winning_digest, &filter, found_hash_str);
    printf("\nHash found: %s\n", found_hash_str);

    free(out_data);
    if (in_file_data) free(in_file_data);
    return 0;
}
