#pragma once
#include <stddef.h>

struct ocl_pattern {
    const unsigned char *prefix; size_t prefix_len; unsigned int suffix_off;
    const unsigned char *suffix; size_t suffix_len;
};

struct ocl_inputs {
    const char *kernel_path;
    const struct ocl_pattern *patterns; size_t patterns_count;
    unsigned int target_count;
    size_t global_size; size_t local_size; unsigned int iters_per_wi;
    unsigned long long seed;
};

struct ocl_match {
    char pub_b64[45];
    char priv_b64[45];
};

struct ocl_outputs {
    unsigned int found;
    struct ocl_match *matches;
};

int ocl_is_available(void);
int ocl_run_batch(const struct ocl_inputs *in, struct ocl_outputs *out);
int ocl_cpu_gpu_consistency_test(const struct ocl_inputs *in, int (*cpu_gen)(unsigned long long seed, unsigned count, unsigned char *out_pub_priv));

// Dump clamped secret base64 strings for deterministic RNG consistency tests.
// Writes count entries of 45 bytes (44 chars + NUL) into out_priv_b64.
int ocl_rng_dump(const char *kernel_path, size_t global_size, size_t local_size, unsigned long long seed,
                 char *out_priv_b64, size_t count);

// Dump raw 32-byte public keys computed from Philox-derived secrets (same RNG as rng_dump)
// Writes count entries of 32 bytes into out_pub (no padding or base64)
int ocl_pubkey_dump(const char *kernel_path, size_t global_size, size_t local_size, unsigned long long seed,
                    unsigned char *out_pub, size_t count);

// Compute public keys from host-provided clamped secrets (count entries of 32 bytes)
// Writes count entries of 32 bytes into out_pub.
int ocl_pub_from_secrets(const char *kernel_path,
                         const unsigned char *secrets, size_t count,
                         unsigned char *out_pub);

// Debug: dump post-ladder intermediates and final bytes for a single secret
// out_limbs: 40 ints -> x2[10], z2[10], zinv[10], x[10]; out_bytes: 32-byte serialized x
// Also returns the final swap bit and the pre-final-cswap X2/Z2 limbs (20 ints)
int ocl_debug_final(const char *kernel_path,
                    const unsigned char sk[32],
                    int out_limbs[40], unsigned char out_bytes[32],
                    int *out_swap_bit, int out_pre_limbs[20]);

// Trace the Montgomery ladder for a single secret (clamped) and dump X2,Z2,X3,Z3 limbs per iteration.
// out_limbs length must be iters*40 ints.
int ocl_trace_ladder(const char *kernel_path,
                     const unsigned char sk[32], unsigned iters,
                     int *out_limbs);
