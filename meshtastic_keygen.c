/*
                        DO WHAT THE F*CK YOU WANT TO PUBLIC LICENSE
                                                Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

                        DO WHAT THE F*CK YOU WANT TO PUBLIC LICENSE
     TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

    0. You just DO WHAT THE F*CK YOU WANT TO.
*/

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>

#define DEFAULT_NUM_THREADS 4
#define BASE64_LEN 44  // 32 bytes base64 encoded

// Runtime-configurable settings
static int g_num_threads = DEFAULT_NUM_THREADS;
static char *g_target_prefix = NULL;
static char *g_target_suffix = NULL; // prefix with '=' appended
static size_t g_prefix_len = 0;
static size_t g_suffix_len = 0;

static _Atomic unsigned long long g_key_count = 0; // total generated/checked keys
static _Atomic unsigned long long g_found_count = 0; // total matches found
static unsigned long long g_found_target = 1;        // stop after this many matches
static _Atomic int g_stop = 0;                       // global stop flag

static void human_readable_ull(unsigned long long v, char *out, size_t outsz) {
    const char *suffixes[] = {"", "K", "M", "G", "T", "P", "E"};
    int s = 0;
    double dv = (double)v;
    while (dv >= 1000.0 && s < (int)(sizeof(suffixes)/sizeof(suffixes[0])) - 1) {
        dv /= 1000.0;
        s++;
    }
    // Keep 1 decimal for non-integers when dv < 100 or when fractional part is meaningful
    if (dv < 10.0 && v >= 1000ULL) {
        snprintf(out, outsz, "%.2f%s", dv, suffixes[s]);
    } else if (dv < 100.0 && v >= 1000ULL) {
        snprintf(out, outsz, "%.1f%s", dv, suffixes[s]);
    } else {
        snprintf(out, outsz, "%.0f%s", dv, suffixes[s]);
    }
}

static void *reporter(void *arg) {
    (void)arg;
    unsigned long long last = 0;
    while (!atomic_load(&g_stop)) {
        sleep(1);
        unsigned long long total = atomic_load(&g_key_count);
        unsigned long long delta = total - last;
        last = total;
        char total_str[32];
        char rate_str[32];
        human_readable_ull(total, total_str, sizeof total_str);
        human_readable_ull(delta, rate_str, sizeof rate_str);
        printf("Keys: total=%s, %s/s\n", total_str, rate_str);
        fflush(stdout);
    }
    return NULL;
}

unsigned char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    
    unsigned char *buff = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return NULL;

    // Avoid newline insertion to keep output length predictable
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new(BIO_s_mem());
    if (!bmem) { BIO_free(b64); return NULL; }

    b64 = BIO_push(b64, bmem);
    if (!b64) { BIO_free_all(bmem); return NULL; }

    if (BIO_write(b64, input, length) <= 0) {
        BIO_free_all(b64);
        return NULL;
    }
    if (BIO_flush(b64) <= 0) {
        BIO_free_all(b64);
        return NULL;
    }
    BIO_get_mem_ptr(b64, &bptr);
    if (!bptr || !bptr->data || bptr->length == 0) {
        BIO_free_all(b64);
        return NULL;
    }

    buff = (unsigned char *)malloc(bptr->length + 1);
    if (!buff) {
        BIO_free_all(b64);
        return NULL;
    }
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';
    
    BIO_free_all(b64);
    return buff;
}

void *generate_keys(void *arg) {
    EVP_PKEY_CTX *ctx;
    unsigned char priv_key[32];
    char *encoded;
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return NULL;
    
    while (!atomic_load(&g_stop)) {
        EVP_PKEY *pkey = NULL; // Ensure pkey is NULL for each iteration

        // Generate key directly
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            continue;
        }
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            if (pkey) EVP_PKEY_free(pkey);
            continue;
        }
        
        // Extract private key (last 32 bytes)
        size_t len = 32;
        if (EVP_PKEY_get_raw_private_key(pkey, priv_key, &len) <= 0) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }
        
        // Base64 encode
        encoded = (char *)base64_encode(priv_key, 32);
        if (!encoded) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }
        // Count this generated key regardless of match
        atomic_fetch_add(&g_key_count, 1ULL);
        
        // Check if it starts with the prefix or ends with prefix + '='
        size_t enc_len = strlen(encoded);
        if ((g_prefix_len > 0 && strncmp(encoded, g_target_prefix, g_prefix_len) == 0) ||
            (g_suffix_len > 0 && enc_len >= g_suffix_len && strcmp(encoded + enc_len - g_suffix_len, g_target_suffix) == 0)) {
            printf("FOUND: %s\n", encoded);
            fflush(stdout);
            unsigned long long cur = atomic_fetch_add(&g_found_count, 1ULL) + 1ULL;
            if (cur >= g_found_target) {
                atomic_store(&g_stop, 1);
            }
        }
        
        free(encoded);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static int search_has_only_b64_chars(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        unsigned char c = *p;
        if (isalnum(c) || c == '+' || c == '/') {
            continue;
        }
        // '=' not allowed in search (we add it for suffix)
        return 0;
    }
    return 1;
}

static int set_search_string(const char *s) {
    if (!s) return -1;
    // Free existing
    if (g_target_prefix) { free(g_target_prefix); g_target_prefix = NULL; }
    if (g_target_suffix) { free(g_target_suffix); g_target_suffix = NULL; }

    g_target_prefix = strdup(s);
    if (!g_target_prefix) return -1;
    g_prefix_len = strlen(g_target_prefix);

    // suffix is prefix + '='
    g_target_suffix = (char *)malloc(g_prefix_len + 2);
    if (!g_target_suffix) { free(g_target_prefix); g_target_prefix = NULL; g_prefix_len = 0; return -1; }
    memcpy(g_target_suffix, g_target_prefix, g_prefix_len);
    g_target_suffix[g_prefix_len] = '=';
    g_target_suffix[g_prefix_len + 1] = '\0';
    g_suffix_len = g_prefix_len + 1;
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-t N|--threads N] [-s STR|--search STR] [-c N|--count N]\n", prog);
    fprintf(stderr, "  -s STR: required. STR must contain only Base64 characters [A-Za-z0-9+/] (no '=').\n");
    fprintf(stderr, "  -t N  : optional. Number of threads (default %d).\n", DEFAULT_NUM_THREADS);
    fprintf(stderr, "  -c N  : optional. Stop after finding N matches (default 1).\n");
}

int main(int argc, char **argv) {
    pthread_t *threads = NULL;
    pthread_t rpt;
    // Defaults: no search string, require via CLI; threads default to DEFAULT_NUM_THREADS

    // Parse options
    static struct option long_opts[] = {
        {"threads", required_argument, 0, 't'},
        {"search",  required_argument, 0, 's'},
        {"count",   required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    int opt, idx;
    while ((opt = getopt_long(argc, argv, "t:s:c:", long_opts, &idx)) != -1) {
        switch (opt) {
            case 't': {
                long n = strtol(optarg, NULL, 10);
                if (n > 0 && n <= 65535) {
                    g_num_threads = (int)n;
                } else {
                    fprintf(stderr, "Invalid thread count: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
            } break;
            case 's':
                if (!search_has_only_b64_chars(optarg)) {
                    fprintf(stderr, "Invalid search string: must contain only Base64 characters [A-Za-z0-9+/] and no '='.\n");
                    print_usage(argv[0]);
                    return 1;
                }
                if (set_search_string(optarg) != 0) { fprintf(stderr, "Failed to set search string\n"); return 1; }
                break;
            case 'c': {
                long long n = strtoll(optarg, NULL, 10);
                if (n <= 0) {
                    fprintf(stderr, "Invalid count: %s (must be > 0)\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                g_found_target = (unsigned long long)n;
            } break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Require search string
    if (!g_target_prefix || g_prefix_len == 0) {
        fprintf(stderr, "Error: missing required --search|-s STRING option.\n");
        print_usage(argv[0]);
        return 1;
    }

    threads = (pthread_t *)malloc(sizeof(pthread_t) * (size_t)g_num_threads);
    if (!threads) {
        fprintf(stderr, "Failed to allocate thread handles\n");
        return 1;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    printf("Starting key generation with %d threads...\n", g_num_threads);
    
    // Create reporter thread
    pthread_create(&rpt, NULL, reporter, NULL);

    // Create worker threads
    for (int i = 0; i < g_num_threads; i++) {
        pthread_create(&threads[i], NULL, generate_keys, NULL);
    }
    
    // Wait for threads (they exit on stop)
    for (int i = 0; i < g_num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_join(rpt, NULL);
    free(threads);
    // Free search strings (unreachable in normal run)
    free(g_target_prefix);
    free(g_target_suffix);
    
    return 0;
}
