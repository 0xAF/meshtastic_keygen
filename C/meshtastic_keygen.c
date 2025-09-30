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

// Enable GNU extensions for CPU affinity and ensure CLOCK_MONOTONIC availability
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>

#define DEFAULT_NUM_THREADS 4
#define BASE64_LEN 44  // 32 bytes base64 encoded

// Runtime-configurable settings
static int g_num_threads = DEFAULT_NUM_THREADS;
static char *g_target_prefix = NULL;
static char *g_target_suffix = NULL; // prefix with '=' appended
static size_t g_prefix_len = 0;
static size_t g_suffix_len = 0;
static size_t g_suffix_off = 0; // BASE64_LEN - g_suffix_len
static int g_affinity = 0; // pin worker threads to CPUs
static int g_quiet = 0;    // disable periodic reporting

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
		sleep(5);
		unsigned long long total = atomic_load_explicit(&g_key_count, memory_order_relaxed);
		unsigned long long delta = total - last;
		last = total;
		char total_str[32];
		char rate_str[32];
		human_readable_ull(total, total_str, sizeof total_str);
		unsigned long long per_sec = delta / 5ULL;
		human_readable_ull(per_sec, rate_str, sizeof rate_str);
	fprintf(stderr, "Keys: total=%s, %s/s\n", total_str, rate_str);
	fflush(stderr);
	}
	return NULL;
}

// Fast fixed-size Base64 for 32-byte input. Produces 44 chars + NUL.
static inline void base64_encode_32(const unsigned char in[32], char out[45]) {
	int n = EVP_EncodeBlock((unsigned char *)out, in, 32);
	// EVP_EncodeBlock never fails for valid args; n should be 44
	if (n < 0) n = 0;
	out[n] = '\0';
}

void *generate_keys(void *arg) {
	// Optional: pin thread to a CPU for better cache locality
	long tid = (long)(intptr_t)arg;
#ifdef __linux__
	if (g_affinity) {
		int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
		if (ncpu > 0) {
			cpu_set_t set;
			CPU_ZERO(&set);
			CPU_SET((unsigned)(tid % ncpu), &set);
			(void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
		}
	}
#endif

	unsigned char priv_key[32];
	unsigned char pub_key[32];
	char b64_pub[BASE64_LEN + 1];  // 44 + 1
	char b64_priv[BASE64_LEN + 1]; // 44 + 1
	unsigned long long local_cnt = 0;

	while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
		// Generate random private key bytes
		if (RAND_bytes(priv_key, sizeof priv_key) != 1) {
			continue; // try next
		}

	// Clamp private key per X25519 spec
	priv_key[0] &= 248;
	priv_key[31] &= 127;
	priv_key[31] |= 64;

	// Derive public key from private using EVP (lighter than full keygen)
		EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_key, 32);
		if (!pkey) continue;
		size_t len = 32;
		if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &len) <= 0) {
			EVP_PKEY_free(pkey);
			continue;
		}
		EVP_PKEY_free(pkey);

		// Base64 encode public and check match
		base64_encode_32(pub_key, b64_pub);

		// Count this generated key regardless of match (batch to reduce contention)
		if (++local_cnt >= 1024) {
			atomic_fetch_add_explicit(&g_key_count, local_cnt, memory_order_relaxed);
			local_cnt = 0;
		}

		if ((g_prefix_len > 0 && memcmp(b64_pub, g_target_prefix, g_prefix_len) == 0) ||
			(g_suffix_len > 0 && memcmp(b64_pub + g_suffix_off, g_target_suffix, g_suffix_len) == 0)) {
			// Encode private key only when we have a match
			base64_encode_32(priv_key, b64_priv);
			printf("FOUND: pub=%s priv=%s\n", b64_pub, b64_priv);
			fprintf(stderr, "FOUND: pub=%s priv=%s\n", b64_pub, b64_priv);
			fflush(stdout);
			fflush(stderr);
			unsigned long long cur = atomic_fetch_add_explicit(&g_found_count, 1ULL, memory_order_relaxed) + 1ULL;
			if (cur >= g_found_target) {
				atomic_store_explicit(&g_stop, 1, memory_order_relaxed);
			}
		}
	}

	// Flush any remaining counts
	if (local_cnt) {
		atomic_fetch_add_explicit(&g_key_count, local_cnt, memory_order_relaxed);
	}
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
	g_suffix_off = (g_suffix_len <= BASE64_LEN) ? (BASE64_LEN - g_suffix_len) : 0;
	return 0;
}

static void print_usage(const char *prog) {
	fprintf(stderr, "Usage: %s [-t N|--threads N] [-s STR|--search STR] [-c N|--count N] [--affinity] [-q|--quiet]\n", prog);
	fprintf(stderr, "  -s STR: required. STR must contain only Base64 characters [A-Za-z0-9+/] (no '=').\n");
	fprintf(stderr, "  -t N  : optional. Number of threads (default %d).\n", DEFAULT_NUM_THREADS);
	fprintf(stderr, "  -c N  : optional. Stop after finding N matches (default 1).\n");
	fprintf(stderr, "  -q, --quiet: optional. Disable periodic reporting.\n");
	fprintf(stderr, "  --affinity: optional. Pin worker threads to CPU cores (Linux).\n");
}

void *generate_keys(void *arg);

static void handle_signal(int sig) {
	(void)sig;
	atomic_store(&g_stop, 1);
}

int main(int argc, char **argv) {
	pthread_t *threads = NULL;
	pthread_t rpt;
	// Defaults: no search string, require via CLI; threads default to DEFAULT_NUM_THREADS
	struct timespec ts_start;
	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	// Install signal handlers for graceful shutdown (Ctrl-C)
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	// Print start wall-clock timestamp
	{
		time_t now = time(NULL);
		struct tm tm;
		char buf[64];
		localtime_r(&now, &tm);
		strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S%z", &tm);
	fprintf(stderr, "Start: %s\n", buf);
	fflush(stderr);
	}

	// Parse options
	static struct option long_opts[] = {
		{"threads", required_argument, 0, 't'},
		{"search",  required_argument, 0, 's'},
		{"count",   required_argument, 0, 'c'},
		{"affinity", no_argument,       0,  1 },
		{"quiet",    no_argument,       0, 'q'},
		{0, 0, 0, 0}
	};
	int opt, idx;
	while ((opt = getopt_long(argc, argv, "t:s:c:q", long_opts, &idx)) != -1) {
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
			case 1: // --affinity
				g_affinity = 1;
				break;
			case 'q':
				g_quiet = 1;
				break;
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
    
	// Initialize OpenSSL PRNG (modern OpenSSL auto-inits). Keep for compatibility.
	OPENSSL_init_crypto(0, NULL);
    
	fprintf(stderr, "Starting key generation with %d threads...\n", g_num_threads);
    
	// Create reporter thread unless quiet
	if (!g_quiet) {
		pthread_create(&rpt, NULL, reporter, NULL);
	}

	// Create worker threads
	for (int i = 0; i < g_num_threads; i++) {
		pthread_create(&threads[i], NULL, generate_keys, (void*)(intptr_t)i);
	}
    
	// Wait for threads (they exit on stop)
	for (int i = 0; i < g_num_threads; i++) {
		pthread_join(threads[i], NULL);
	}
	if (!g_quiet) {
		pthread_join(rpt, NULL);
	}
	free(threads);
	// Free search strings (unreachable in normal run)
	free(g_target_prefix);
	free(g_target_suffix);
    
	// Final summary
	struct timespec ts_end;
	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	double secs = (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
	if (secs < 0) secs = 0;
	unsigned long long total_final = atomic_load_explicit(&g_key_count, memory_order_relaxed);
	unsigned long long found_final = atomic_load_explicit(&g_found_count, memory_order_relaxed);
	unsigned long long rate_ull = (unsigned long long)((total_final / (secs > 1e-9 ? secs : 1e-9)) + 0.5);
	char total_str[32];
	char rate_str[32];
	human_readable_ull(total_final, total_str, sizeof total_str);
	human_readable_ull(rate_ull, rate_str, sizeof rate_str);
    fprintf(stderr, "Done. Elapsed: %.3fs | total keys: %s | found: %llu | rate: %s/s\n",
	    secs, total_str, found_final, rate_str);
    fflush(stderr);
    
	return 0;
}
