#include "d2fastlib.h"
#include "utils.c"
#include "sha256.c"

#define VERSION "v0.1.0"

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
    printf("  -m --magic         Magic string in the file to replace with nonce (can only occur once in the file)\n");
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
            snprintf(buf, size, "%.1fG hashes", val / 1000.0);
        else
            snprintf(buf, size, "%.0fG hashes", val / 1000.0);
    } else {
        snprintf(buf, size, "%.1fT hashes", val / 1000.0);
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
            snprintf(buf, size, "%.1fG", val / 1000.0);
        else
            snprintf(buf, size, "%.0fG", val / 1000.0);
    } else {
        snprintf(buf, size, "%.1fT", val / 1000.0);
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

static inline int digest_matches_filter(const uint32_t digest[8], const HashFilter *filter) {
    if ((digest[0] & filter->combined_mask[0]) != filter->combined_val[0]) return 0;
    if ((digest[7] & filter->combined_mask[7]) != filter->combined_val[7]) return 0;
    for (int w = 1; w < 7; w++) {
        if ((digest[w] & filter->combined_mask[w]) != filter->combined_val[w]) return 0;
    }
    char hex[65];
    digest_to_hex(digest, hex);
    if (filter->prefix_len > 0 && strncasecmp(hex, filter->prefix_str, filter->prefix_len) != 0) return 0;
    if (filter->suffix_len > 0 && strncasecmp(hex + 64 - filter->suffix_len, filter->suffix_str, filter->suffix_len) != 0) return 0;
    return 1;
}

// Search for a magic string in infile without loading entire file to RAM
static int find_magic_string(const char *infile, const char *magic, int64_t *out_offset) {
    size_t magic_len = strlen(magic);
    if (magic_len == 0) return -1;

    FILE *f = fopen(infile, "rb");
    if (!f) return -1;

    size_t chunk_size = (magic_len > 65536) ? (magic_len * 2) : 65536;
    uint8_t *buf = (uint8_t*)malloc(chunk_size + magic_len);
    if (!buf) {
        fclose(f);
        return -1;
    }

    int count = 0;
    int64_t first_offset = -1;
    int64_t stream_pos = 0;
    size_t overlap = 0;

    while (1) {
        size_t r = fread(buf + overlap, 1, chunk_size, f);
        size_t total_in_buf = overlap + r;
        if (total_in_buf < magic_len) {
            break;
        }

        size_t search_limit = total_in_buf - magic_len + 1;
        for (size_t i = 0; i < search_limit; i++) {
            if (memcmp(buf + i, magic, magic_len) == 0) {
                count++;
                if (count == 1) {
                    first_offset = stream_pos + (int64_t)i;
                }
            }
        }

        if (r < chunk_size) {
            break; // EOF reached
        }

        overlap = magic_len - 1;
        memmove(buf, buf + total_in_buf - overlap, overlap);
        stream_pos += (int64_t)(total_in_buf - overlap);
    }

    free(buf);
    fclose(f);

    if (count == 0) {
        return 0; // Not found
    } else if (count == 1) {
        *out_offset = first_offset;
        return 1; // Found exactly once
    } else {
        return count; // Found more than once (> 1)
    }
}

// Compute SHA-256 of file stream
static int sha256_file(FILE *fin, int64_t file_size, int cpu_mode, uint32_t digest[8]) {
    digest[0] = 0x6a09e667;
    digest[1] = 0xbb67ae85;
    digest[2] = 0x3c6ef372;
    digest[3] = 0xa54ff53a;
    digest[4] = 0x510e527f;
    digest[5] = 0x9b05688c;
    digest[6] = 0x1f83d9ab;
    digest[7] = 0x5be0cd19;

    if (fseeko(fin, 0, SEEK_SET) != 0) return -1;

    size_t full_blocks = (size_t)(file_size / 64);
    #define STREAM_CHUNK_BLOCKS 1024
    uint8_t chunk_buf[STREAM_CHUNK_BLOCKS * 64] __attribute__((aligned(64)));

    size_t blocks_remaining = full_blocks;
    while (blocks_remaining > 0) {
        size_t blocks_to_read = blocks_remaining > STREAM_CHUNK_BLOCKS ? STREAM_CHUNK_BLOCKS : blocks_remaining;
        size_t bytes_to_read = blocks_to_read * 64;
        if (fread(chunk_buf, 1, bytes_to_read, fin) != bytes_to_read) {
            return -1;
        }
        sha256_transform_blocks(cpu_mode, digest, chunk_buf, blocks_to_read);
        blocks_remaining -= blocks_to_read;
    }

    size_t tail_len = (size_t)(file_size % 64);
    uint8_t tail_buf[128] __attribute__((aligned(64)));
    memset(tail_buf, 0, sizeof(tail_buf));

    if (tail_len > 0) {
        if (fread(tail_buf, 1, tail_len, fin) != tail_len) {
            return -1;
        }
    }
    tail_buf[tail_len] = 0x80;

    size_t rem = (file_size + 1) % 64;
    size_t pad_zeros = (rem <= 56) ? (56 - rem) : (56 + 64 - rem);
    size_t tail_total = (file_size + 1 + pad_zeros + 8) - (full_blocks * 64);
    size_t tail_blocks = tail_total / 64;

    uint64_t bit_len = (uint64_t)file_size * 8ULL;
    for (int i = 0; i < 8; i++) {
        tail_buf[tail_total - 8 + i] = (uint8_t)(bit_len >> ((7 - i) * 8));
    }

    sha256_transform_blocks(cpu_mode, digest, tail_buf, tail_blocks);
    return 0;
}

// Copy file helper
static int copy_file(const char *src, const char *dst) {
    FILE *fsrc = fopen(src, "rb");
    if (!fsrc) return -1;
    FILE *fdst = fopen(dst, "wb");
    if (!fdst) { fclose(fsrc); return -1; }
    uint8_t buf[65536];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), fsrc)) > 0) {
        if (fwrite(buf, 1, r, fdst) != r) {
            fclose(fsrc);
            fclose(fdst);
            return -1;
        }
    }
    fclose(fsrc);
    fclose(fdst);
    return 0;
}

typedef struct {
    int thread_id;
    int cpu_mode;
    int nonce_size;
    size_t local_nonce_offset;
    size_t nonce_num_blocks;
    uint8_t nonce_template[128];
    const uint8_t *shared_trail_buf;
    size_t trail_blocks;
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
    size_t nonce_num_blocks = ctx->nonce_num_blocks;
    const uint8_t *shared_trail_buf = ctx->shared_trail_buf;
    size_t trail_blocks = ctx->trail_blocks;
    const HashFilter *filter = ctx->filter;
    const Alphabet *alpha = ctx->alpha;

    // Fixed 128-byte aligned local buffer on the stack (L1 cache resident, 0 heap RAM)
    uint8_t local_buf[128] __attribute__((aligned(64)));
    memcpy(local_buf, ctx->nonce_template, nonce_num_blocks * 64);

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

                sha256_transform_blocks(cpu_mode, digest, local_buf, nonce_num_blocks);
                if (trail_blocks > 0) {
                    sha256_transform_blocks(cpu_mode, digest, shared_trail_buf, trail_blocks);
                }

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

                sha256_transform_blocks(cpu_mode, digest, local_buf, nonce_num_blocks);
                if (trail_blocks > 0) {
                    sha256_transform_blocks(cpu_mode, digest, shared_trail_buf, trail_blocks);
                }

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

    return NULL;
}

// Incrementally stream prefix blocks from disk into base_state
static int update_base_state(FILE *fin, int cpu_mode,
                             size_t pre_blocks,
                             size_t *cached_pre_blocks,
                             uint32_t base_state[8]) {
    const uint32_t sha256_iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    if (pre_blocks == *cached_pre_blocks) {
        return 0;
    }

    size_t start_blk = 0;
    if (pre_blocks > *cached_pre_blocks && *cached_pre_blocks != (size_t)-1) {
        start_blk = *cached_pre_blocks;
    } else {
        memcpy(base_state, sha256_iv, sizeof(sha256_iv));
        start_blk = 0;
    }

    if (pre_blocks > start_blk) {
        if (fseeko(fin, (off_t)(start_blk * 64), SEEK_SET) != 0) {
            return -1;
        }

        #define STREAM_CHUNK_BLOCKS 1024
        uint8_t chunk_buf[STREAM_CHUNK_BLOCKS * 64] __attribute__((aligned(64)));

        size_t blocks_remaining = pre_blocks - start_blk;
        while (blocks_remaining > 0) {
            size_t blocks_to_read = blocks_remaining > STREAM_CHUNK_BLOCKS ? STREAM_CHUNK_BLOCKS : blocks_remaining;
            size_t bytes_to_read = blocks_to_read * 64;
            size_t bytes_read = fread(chunk_buf, 1, bytes_to_read, fin);
            if (bytes_read != bytes_to_read) {
                return -1;
            }
            sha256_transform_blocks(cpu_mode, base_state, chunk_buf, blocks_to_read);
            blocks_remaining -= blocks_to_read;
        }
        #undef STREAM_CHUNK_BLOCKS
    }

    *cached_pre_blocks = pre_blocks;
    return 0;
}

// Low-memory streaming writer for output file
static int write_output_file(const char *infile, const char *outfile,
                             int64_t in_file_size,
                             size_t actual_offset,
                             int nonce_size,
                             uint64_t winning_nonce,
                             const Alphabet *alpha,
                             size_t mod_file_size) {
    uint8_t nonce_bytes[32];
    if (alpha->is_binary) {
        write_nonce_binary(nonce_bytes, winning_nonce, nonce_size);
    } else {
        write_nonce_custom(nonce_bytes, winning_nonce, nonce_size, alpha->chars, alpha->size);
    }

    // Fast in-place overwrite when file size doesn't change
    if (!outfile && mod_file_size == (size_t)in_file_size) {
        FILE *f = fopen(infile, "r+b");
        if (!f) return -1;
        if (fseeko(f, (off_t)actual_offset, SEEK_SET) != 0) { fclose(f); return -1; }
        if (fwrite(nonce_bytes, 1, nonce_size, f) != (size_t)nonce_size) { fclose(f); return -1; }
        fclose(f);
        return 0;
    }

    // Fast in-place append when appending to infile
    if (!outfile && actual_offset == (size_t)in_file_size && mod_file_size == (size_t)in_file_size + nonce_size) {
        FILE *f = fopen(infile, "a+b");
        if (!f) return -1;
        if (fseeko(f, (off_t)in_file_size, SEEK_SET) != 0) { fclose(f); return -1; }
        if (fwrite(nonce_bytes, 1, nonce_size, f) != (size_t)nonce_size) { fclose(f); return -1; }
        fclose(f);
        return 0;
    }

    char temp_dest[1024];
    int use_temp = 0;
    const char *dest_path = outfile;

    if (!outfile) {
        use_temp = 1;
        snprintf(temp_dest, sizeof(temp_dest), "%s.vanity_tmp_%d", infile, (int)getpid());
        dest_path = temp_dest;
    }

    FILE *fin = NULL;
    if (in_file_size > 0) {
        fin = fopen(infile, "rb");
        if (!fin) return -1;
    }

    FILE *fout = fopen(dest_path, "wb");
    if (!fout) {
        if (fin) fclose(fin);
        return -1;
    }

    uint8_t copy_buf[65536];
    size_t written = 0;

    // 1. Stream prefix before nonce
    while (written < actual_offset) {
        size_t to_write = actual_offset - written;
        if (to_write > sizeof(copy_buf)) to_write = sizeof(copy_buf);

        if (fin && written < (size_t)in_file_size) {
            size_t from_file = (size_t)in_file_size - written;
            if (from_file > to_write) from_file = to_write;
            size_t r = fread(copy_buf, 1, from_file, fin);
            if (r < from_file) {
                if (fin) fclose(fin);
                fclose(fout);
                if (use_temp) unlink(temp_dest);
                return -1;
            }
            if (from_file < to_write) {
                memset(copy_buf + from_file, 0, to_write - from_file);
            }
        } else {
            memset(copy_buf, 0, to_write);
        }

        if (fwrite(copy_buf, 1, to_write, fout) != to_write) {
            if (fin) fclose(fin);
            fclose(fout);
            if (use_temp) unlink(temp_dest);
            return -1;
        }
        written += to_write;
    }

    // 2. Write nonce
    if (nonce_size > 0) {
        if (fwrite(nonce_bytes, 1, nonce_size, fout) != (size_t)nonce_size) {
            if (fin) fclose(fin);
            fclose(fout);
            if (use_temp) unlink(temp_dest);
            return -1;
        }
        written += nonce_size;
    }

    // 3. Stream remainder of original file if any
    if (fin && written < (size_t)in_file_size) {
        fseeko(fin, (off_t)written, SEEK_SET);
    }

    while (written < mod_file_size) {
        size_t to_write = mod_file_size - written;
        if (to_write > sizeof(copy_buf)) to_write = sizeof(copy_buf);

        if (fin && written < (size_t)in_file_size) {
            size_t from_file = (size_t)in_file_size - written;
            if (from_file > to_write) from_file = to_write;
            size_t r = fread(copy_buf, 1, from_file, fin);
            if (r < from_file) {
                if (fin) fclose(fin);
                fclose(fout);
                if (use_temp) unlink(temp_dest);
                return -1;
            }
            if (from_file < to_write) {
                memset(copy_buf + from_file, 0, to_write - from_file);
            }
        } else {
            memset(copy_buf, 0, to_write);
        }

        if (fwrite(copy_buf, 1, to_write, fout) != to_write) {
            if (fin) fclose(fin);
            fclose(fout);
            if (use_temp) unlink(temp_dest);
            return -1;
        }
        written += to_write;
    }

    if (fin) fclose(fin);
    fclose(fout);

    if (use_temp) {
        if (rename(temp_dest, infile) != 0) {
            unlink(temp_dest);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    const char *hash_algo = "sha256";
    const char *start_with = NULL;
    const char *ends_with = NULL;
    const char *alphabet_name = "binary";
    const char *magic_str = NULL;
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
        } else if (strcmp(arg, "-m") == 0 || strcmp(arg, "--magic") == 0) {
            if (i + 1 < argc) magic_str = argv[++i];
            else { print_help(); return 1; }
        } else if (strncmp(arg, "--magic=", 8) == 0) {
            magic_str = arg + 8;
        } else if (strncmp(arg, "-m", 2) == 0 && strlen(arg) > 2) {
            magic_str = arg + 2;
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

    // Process magic string option if specified
    if (magic_str) {
        if (magic_str[0] == '\0') {
            fprintf(stderr, "Error: Magic string cannot be empty.\n");
            return 1;
        }
        int64_t magic_offset = 0;
        int magic_res = find_magic_string(infile, magic_str, &magic_offset);
        if (magic_res == 0) {
            fprintf(stderr, "Error: Magic string '%s' not found in file '%s'.\n", magic_str, infile);
            return 1;
        } else if (magic_res > 1) {
            fprintf(stderr, "Error: Magic string '%s' occurs more than once in file '%s'.\n", magic_str, infile);
            return 1;
        } else if (magic_res < 0) {
            fprintf(stderr, "Error reading file '%s': %s\n", infile, strerror(errno));
            return 1;
        }
        offset_mode = OFFSET_MODE_EXACT;
        exact_offset = magic_offset;
        fixed_nonce_size = (int)strlen(magic_str);
    }

    // Open input file and determine size (streamed, not loaded into RAM)
    FILE *fin = fopen(infile, "rb");
    if (!fin) {
        fprintf(stderr, "Error: cannot open input file '%s': %s\n", infile, strerror(errno));
        return 1;
    }
    fseeko(fin, 0, SEEK_END);
    int64_t in_file_size = (int64_t)ftello(fin);
    fseeko(fin, 0, SEEK_SET);

    int cpu_mode = GetFastestCpuMode();
    const char *cpu_mode_name = GetCpuModeName(cpu_mode);

    printf("vanity-hash %s started with cpu mode %s\n", VERSION, cpu_mode_name);

    // Check if the input file already matches the required hash
    uint32_t initial_digest[8];
    if (sha256_file(fin, in_file_size, cpu_mode, initial_digest) == 0) {
        if (digest_matches_filter(initial_digest, &filter)) {
            printf("File already matches the required hash\n\n");
            char found_hash_str[65];
            format_found_hash(initial_digest, &filter, found_hash_str);
            printf("Hash found: %s\n", found_hash_str);

            if (outfile && strcmp(infile, outfile) != 0) {
                if (copy_file(infile, outfile) != 0) {
                    fprintf(stderr, "Error copying infile to outfile: %s\n", strerror(errno));
                    fclose(fin);
                    return 1;
                }
            }
            fclose(fin);
            return 0;
        }
    }

    int total_vanity_hex = filter.prefix_len + filter.suffix_len;
    char approx_buf[64];
    format_approx_hashes(total_vanity_hex, approx_buf, sizeof(approx_buf));

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

    size_t cached_pre_blocks = (size_t)-1;
    uint32_t base_state[8];

    for (int curr_size = min_size; curr_size <= max_size && !match_found; curr_size++) {
        int64_t actual_offset = 0;
        int64_t mod_file_size = 0;

        if (offset_mode == OFFSET_MODE_APPEND) {
            actual_offset = in_file_size;
            mod_file_size = in_file_size + curr_size;
        } else if (offset_mode == OFFSET_MODE_LAST) {
            if (in_file_size >= (int64_t)curr_size) {
                actual_offset = in_file_size - curr_size;
                mod_file_size = in_file_size;
            } else {
                actual_offset = 0;
                mod_file_size = curr_size;
            }
        } else {
            actual_offset = exact_offset;
            int64_t end_pos = actual_offset + curr_size;
            mod_file_size = (end_pos > in_file_size) ? end_pos : in_file_size;
        }

        size_t rem = (mod_file_size + 1) % 64;
        size_t pad_zeros = (rem <= 56) ? (56 - rem) : (56 + 64 - rem);
        size_t padded_len = mod_file_size + 1 + pad_zeros + 8;
        size_t total_blocks = padded_len / 64;

        size_t nonce_start_block = (size_t)(actual_offset / 64);
        size_t nonce_end_block = (size_t)((actual_offset + curr_size - 1) / 64);
        size_t pre_blocks = nonce_start_block;
        size_t nonce_num_blocks = nonce_end_block - nonce_start_block + 1;
        size_t trail_start_block = nonce_end_block + 1;
        size_t trail_blocks = (total_blocks > trail_start_block) ? (total_blocks - trail_start_block) : 0;

        // Stream and pre-hash prefix blocks into base_state
        if (in_file_size > 0 && fin) {
            if (update_base_state(fin, cpu_mode, pre_blocks, &cached_pre_blocks, base_state) != 0) {
                fprintf(stderr, "Error reading prefix blocks from input file.\n");
                break;
            }
        } else {
            const uint32_t sha256_iv[8] = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };
            memcpy(base_state, sha256_iv, sizeof(sha256_iv));
            cached_pre_blocks = 0;
        }

        // Prepare nonce block template (max 128 bytes)
        uint8_t nonce_template[128] __attribute__((aligned(64)));
        memset(nonce_template, 0, sizeof(nonce_template));

        size_t template_start_byte = nonce_start_block * 64;
        size_t template_end_byte = (nonce_end_block + 1) * 64;

        if (fin && in_file_size > (int64_t)template_start_byte) {
            int64_t avail = in_file_size - (int64_t)template_start_byte;
            size_t copy_bytes = (size_t)((avail > (int64_t)(nonce_num_blocks * 64)) ? (int64_t)(nonce_num_blocks * 64) : avail);
            if (fseeko(fin, (off_t)template_start_byte, SEEK_SET) == 0) {
                size_t r = fread(nonce_template, 1, copy_bytes, fin);
                (void)r;
            }
        }

        size_t local_nonce_offset = (size_t)(actual_offset - template_start_byte);

        if ((size_t)mod_file_size >= template_start_byte && (size_t)mod_file_size < template_end_byte) {
            size_t pad_offset = (size_t)mod_file_size - template_start_byte;
            nonce_template[pad_offset] = 0x80;

            if (trail_blocks == 0) {
                uint64_t bit_len = (uint64_t)mod_file_size * 8ULL;
                size_t len_offset = nonce_num_blocks * 64 - 8;
                for (int b = 0; b < 8; b++) {
                    nonce_template[len_offset + b] = (uint8_t)(bit_len >> ((7 - b) * 8));
                }
            }
        }

        // Prepare shared trailing blocks if any (only when nonce is placed before the end)
        uint8_t *shared_trail_buf = NULL;
        if (trail_blocks > 0) {
            size_t trail_bytes = trail_blocks * 64;
            if (posix_memalign((void**)&shared_trail_buf, 64, trail_bytes) != 0) {
                shared_trail_buf = (uint8_t*)malloc(trail_bytes);
            }
            if (shared_trail_buf) {
                memset(shared_trail_buf, 0, trail_bytes);
                size_t trail_start_byte = trail_start_block * 64;

                if (fin && in_file_size > (int64_t)trail_start_byte) {
                    int64_t avail = in_file_size - (int64_t)trail_start_byte;
                    size_t copy_bytes = (size_t)((avail > (int64_t)(trail_bytes)) ? (int64_t)(trail_bytes) : avail);
                    if (fseeko(fin, (off_t)trail_start_byte, SEEK_SET) == 0) {
                        size_t r = fread(shared_trail_buf, 1, copy_bytes, fin);
                        (void)r;
                    }
                }

                if ((size_t)mod_file_size >= trail_start_byte) {
                    size_t pad_offset = (size_t)mod_file_size - trail_start_byte;
                    shared_trail_buf[pad_offset] = 0x80;
                }

                uint64_t bit_len = (uint64_t)mod_file_size * 8ULL;
                size_t len_offset = trail_bytes - 8;
                for (int b = 0; b < 8; b++) {
                    shared_trail_buf[len_offset + b] = (uint8_t)(bit_len >> ((7 - b) * 8));
                }
            }
        }

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
            contexts[t].nonce_num_blocks = nonce_num_blocks;
            memcpy(contexts[t].nonce_template, nonce_template, sizeof(nonce_template));
            contexts[t].shared_trail_buf = shared_trail_buf;
            contexts[t].trail_blocks = trail_blocks;
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
                winning_actual_offset = (size_t)actual_offset;
                winning_mod_file_size = (size_t)mod_file_size;
                memcpy(winning_digest, contexts[t].winning_digest, sizeof(winning_digest));
            }
        }

        uint64_t stage_final_hashes = stage_nonce_counter;
        if (stage_final_hashes > max_nonce_val) stage_final_hashes = max_nonce_val;
        cumulative_hashes += stage_final_hashes;

        if (shared_trail_buf) {
            free(shared_trail_buf);
            shared_trail_buf = NULL;
        }

        if (timeout_end_ms > 0 && GetTimeMs() >= timeout_end_ms && !match_found) {
            break;
        }
    }

    if (fin) {
        fclose(fin);
        fin = NULL;
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
        return 1;
    }

    // Write result via streaming (low RAM)
    if (write_output_file(infile, outfile, in_file_size, winning_actual_offset,
                          winning_nonce_size, winning_nonce, &alpha, winning_mod_file_size) != 0) {
        fprintf(stderr, "Error writing output file.\n");
        return 1;
    }

    char found_hash_str[65];
    format_found_hash(winning_digest, &filter, found_hash_str);
    printf("\nHash found: %s\n", found_hash_str);

    return 0;
}