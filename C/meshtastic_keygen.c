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
#include <stdint.h>
#include <dlfcn.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

#ifdef ME_KEYGEN_OPENCL
#include "opencl_keygen.h"
#endif

#define DEFAULT_NUM_THREADS 4
#define BASE64_LEN 44  // 32 bytes base64 encoded

// Runtime-configurable settings
static int g_num_threads = DEFAULT_NUM_THREADS;
// Multiple search patterns support
struct search_pattern {
	char *prefix;
	char *suffix; // prefix + '='
	size_t prefix_len;
	size_t suffix_len;
	size_t suffix_off; // BASE64_LEN - suffix_len
};
static struct search_pattern *g_patterns = NULL;
static size_t g_patterns_count = 0;
static size_t g_patterns_cap = 0;
static int g_affinity = 0; // pin worker threads to CPUs
static int g_quiet = 0;    // disable periodic reporting
static int g_better = 0;   // add visually better variants for patterns
static int g_use_gpu = 0;  // use OpenCL GPU path
static int g_test_rng = 0; // internal: run RNG consistency test (CPU vs GPU)
static int g_test_pub = 0; // internal: run pubkey consistency test (CPU vs GPU)
static int g_test_rfc = 0; // internal: validate RFC 7748 X25519 basepoint vectors
static int g_test_trace = 0; // internal: dump CPU vs GPU ladder state for RFC Alice
static int g_test_fe = 0;    // internal: validate field ops via big-int reference
// Try to use X25519_public_from_private via dynamic lookup if available in libcrypto
static int x25519_pub_from_priv_dyn(unsigned char out[32], const unsigned char priv[32]) {
	typedef void (*x25519_pub_from_priv_fn)(unsigned char out[32], const unsigned char private_key[32]);
	static x25519_pub_from_priv_fn fn = NULL;
	static int resolved = 0;
	if (!resolved) {
		resolved = 1;
		// Since we link with -lcrypto, RTLD_DEFAULT search should find it if present
		void *sym = dlsym(RTLD_DEFAULT, "X25519_public_from_private");
		if (sym) fn = (x25519_pub_from_priv_fn)sym;
	}
	if (fn) { fn(out, priv); return 1; }
	return 0;
}

// ---- CPU feature detection (x86/x64) ----
static int g_has_bmi2 = 0;
static int g_has_adx = 0;
static int g_has_avx2 = 0;
static int g_has_avx512ifma = 0;

static void cpu_detect_features(void) {
#if defined(__x86_64__) || defined(__i386__)
	unsigned int eax=0, ebx=0, ecx=0, edx=0;
	unsigned int max_leaf = __get_cpuid_max(0, NULL);
	if (max_leaf >= 7) {
		// Leaf 7, subleaf 0
		__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
		// Bits from CPUID.(EAX=07H, ECX=0):EBX
		// AVX2 = bit 5, BMI2 = bit 8, ADX = bit 19, AVX-512 IFMA = bit 21 (if supported)
		g_has_avx2 = (ebx >> 5) & 1U;
		g_has_bmi2 = (ebx >> 8) & 1U;
		g_has_adx  = (ebx >> 19) & 1U;
		g_has_avx512ifma = (ebx >> 21) & 1U; // presence only; OS XSAVE checks omitted for now
	}
#else
	// Non-x86: leave all zeros
#endif
}

#ifdef ME_KEYGEN_OPENCL
// --- Minimal CPU ref10-style field ops for ladder tracing ---
typedef struct { int v[10]; } fe;
static inline void fe0(fe *h){ for(int i=0;i<10;++i) h->v[i]=0; }
static inline void fe1(fe *h){ fe0(h); h->v[0]=1; }
static inline void fec(fe *h,const fe *f){ for(int i=0;i<10;++i) h->v[i]=f->v[i]; }
// Forward declaration for BN-based reference multiply (defined later)
static inline void fem_ref(fe *h,const fe *f,const fe *g);
static inline void fea(fe *h,const fe *f,const fe *g){
	// ref10 semantics: limb-wise add without immediate reduction; later ops or fetobytes will reduce
	for (int i = 0; i < 10; ++i) {
		h->v[i] = f->v[i] + g->v[i];
	}
}
static inline void fes(fe *h,const fe *f,const fe *g){
	// ref10 semantics: limb-wise sub without immediate reduction; later ops or fetobytes will reduce
	for (int i = 0; i < 10; ++i) {
		h->v[i] = f->v[i] - g->v[i];
	}
}
static inline void fex(fe *f,fe *g,int b){ int m=-b; for(int i=0;i<10;++i){ int x=m & (f->v[i]^g->v[i]); f->v[i]^=x; g->v[i]^=x; } }
// Reduce limbs to ref10 canonical carry form (same logic as fetobytes without serializing)
static inline void fe_reduce_canonical(fe *h){
	long long h0=h->v[0], h1=h->v[1], h2=h->v[2], h3=h->v[3], h4=h->v[4];
	long long h5=h->v[5], h6=h->v[6], h7=h->v[7], h8=h->v[8], h9=h->v[9];
	long long q = (19 * h9 + (1LL<<24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	h0 += 19 * q;
	long long carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	long long carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	long long carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
	long long carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
	long long carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
	long long carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
	long long carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
	long long carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
	long long carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
	long long carry9 = h9 >> 25; h9 -= carry9 << 25; h0 += carry9 * 19;
	carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	h->v[0]=(int)h0; h->v[1]=(int)h1; h->v[2]=(int)h2; h->v[3]=(int)h3; h->v[4]=(int)h4;
	h->v[5]=(int)h5; h->v[6]=(int)h6; h->v[7]=(int)h7; h->v[8]=(int)h8; h->v[9]=(int)h9;
}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
// Baseline 5x51 multiply (kept as a concrete implementation)
static inline void fem_baseline(fe *h,const fe *f,const fe *g){
	// Native field multiplication using 5x51 representation with ref10-style reduction.
	// Convert inputs directly (without serialize-time q-reduction) to avoid unintended mod-p wraps.
	long long f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
	long long f5 = f->v[5], f6 = f->v[6], f7 = f->v[7], f8 = f->v[8], f9 = f->v[9];
	long long g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4];
	long long g5 = g->v[5], g6 = g->v[6], g7 = g->v[7], g8 = g->v[8], g9 = g->v[9];

	// Convert to 5x51 limbs (pair 26+25 bits)
	long long F0 = f0 + (f1 << 26);
	long long F1 = f2 + (f3 << 26);
	long long F2 = f4 + (f5 << 26);
	long long F3 = f6 + (f7 << 26);
	long long F4 = f8 + (f9 << 26);

	long long G0 = g0 + (g1 << 26);
	long long G1 = g2 + (g3 << 26);
	long long G2 = g4 + (g5 << 26);
	long long G3 = g6 + (g7 << 26);
	long long G4 = g8 + (g9 << 26);

	__int128 G1_19 = (__int128)G1 * 19;
	__int128 G2_19 = (__int128)G2 * 19;
	__int128 G3_19 = (__int128)G3 * 19;
	__int128 G4_19 = (__int128)G4 * 19;

	__int128 H0 = (__int128)F0 * G0 + (__int128)F1 * G4_19 + (__int128)F2 * G3_19 + (__int128)F3 * G2_19 + (__int128)F4 * G1_19;
	__int128 H1 = (__int128)F0 * G1 + (__int128)F1 * G0 + (__int128)F2 * G4_19 + (__int128)F3 * G3_19 + (__int128)F4 * G2_19;
	__int128 H2 = (__int128)F0 * G2 + (__int128)F1 * G1 + (__int128)F2 * G0 + (__int128)F3 * G4_19 + (__int128)F4 * G3_19;
	__int128 H3 = (__int128)F0 * G3 + (__int128)F1 * G2 + (__int128)F2 * G1 + (__int128)F3 * G0 + (__int128)F4 * G4_19;
	__int128 H4 = (__int128)F0 * G4 + (__int128)F1 * G3 + (__int128)F2 * G2 + (__int128)F3 * G1 + (__int128)F4 * G0;

	// Carry reduce to keep each limb < 2^51 and fold top carry via *19
	const __int128 MASK51 = (((__int128)1) << 51) - 1;
	__int128 c0 = H0 >> 51; H1 += c0; H0 &= MASK51;
	__int128 c1 = H1 >> 51; H2 += c1; H1 &= MASK51;
	__int128 c2 = H2 >> 51; H3 += c2; H2 &= MASK51;
	__int128 c3 = H3 >> 51; H4 += c3; H3 &= MASK51;
	__int128 c4 = H4 >> 51; H4 &= MASK51; H0 += c4 * 19; // fold via 19
	c0 = H0 >> 51; H1 += c0; H0 &= MASK51;

	// Convert back to 10x(26/25) limbs by splitting each 51-bit limb into 26 + 25 bits
	unsigned long long T0 = (unsigned long long)H0;
	unsigned long long T1 = (unsigned long long)H1;
	unsigned long long T2 = (unsigned long long)H2;
	unsigned long long T3 = (unsigned long long)H3;
	unsigned long long T4 = (unsigned long long)H4;

	int h0_i = (int)(T0 & 0x3ffffffULL);
	int h1_i = (int)(T0 >> 26);               // 25 bits
	int h2_i = (int)(T1 & 0x3ffffffULL);
	int h3_i = (int)(T1 >> 26);               // 25 bits
	int h4_i = (int)(T2 & 0x3ffffffULL);
	int h5_i = (int)(T2 >> 26);               // 25 bits
	int h6_i = (int)(T3 & 0x3ffffffULL);
	int h7_i = (int)(T3 >> 26);               // 25 bits
	int h8_i = (int)(T4 & 0x3ffffffULL);
	int h9_i = (int)(T4 >> 26);               // 25 bits

	h->v[0] = h0_i; h->v[1] = h1_i; h->v[2] = h2_i; h->v[3] = h3_i; h->v[4] = h4_i;
	h->v[5] = h5_i; h->v[6] = h6_i; h->v[7] = h7_i; h->v[8] = h8_i; h->v[9] = h9_i;
}
#pragma GCC diagnostic pop

// Function-pointer based FE backend (scaffolding for future ADX/BMI2/AVX*)
typedef void (*fe_mul_fn)(fe *h, const fe *f, const fe *g);
typedef void (*fe_sq_fn)(fe *h, const fe *f);
static void fesq_baseline(fe *h, const fe *f) { fem_baseline(h, f, f); }
static fe_mul_fn g_fe_mul = fem_baseline;
static fe_sq_fn  g_fe_sq  = fesq_baseline;
static inline void fem(fe *h, const fe *f, const fe *g) { g_fe_mul(h, f, g); }
static inline void fesq(fe *h, const fe *f) { g_fe_sq(h, f); }

// In FE test mode, cross-check fem via BN to ensure correctness, then map back to limbs
// fem_ref declared later after helpers
static inline void fea24(fe *h,const fe *f){
	// Use a24 = (A-2)/4 = 121665 per RFC 7748 with z2 = E*(AA + a24*E)
	fe a24c; fe0(&a24c); a24c.v[0] = 121665; fem(h, f, &a24c);
}

static inline void feinvert(fe *out, const fe *z){
	fe t0,t1,t2,t3; int i;
	// Based on SUPERCOP ref10: compute z^(p-2) = z^(2^255 - 21)
	fesq(&t0, z);                  // t0 = z^2
	fesq(&t1, &t0);                // t1 = z^4
	fesq(&t1, &t1);                // t1 = z^8
	fem(&t1, &t1, z);              // t1 = z^9
	fem(&t0, &t0, &t1);            // t0 = z^11
	fesq(&t2, &t0);                // t2 = z^22
	fem(&t1, &t1, &t2);            // t1 = z^31
	// t1 = z^(2^5 - 1)
	fesq(&t2, &t1);                // t2 = z^62
	for (i = 0; i < 4; ++i) fesq(&t2, &t2); // t2 = z^992
	fem(&t1, &t2, &t1);            // t1 = z^1023 = 2^10 - 1
	fesq(&t2, &t1);                // t2 = z^2046
	for (i = 0; i < 9; ++i) fesq(&t2, &t2); // t2 = z^(2^20 - 2^10)
	fem(&t2, &t2, &t1);            // t2 = z^(2^20 - 1)
	fesq(&t3, &t2);                // t3 = z^(2^21 - 2)
	for (i = 0; i < 19; ++i) fesq(&t3, &t3); // t3 = z^(2^40 - 2^20)
	fem(&t2, &t3, &t2);            // t2 = z^(2^40 - 1)
	fesq(&t2, &t2);                // t2 = z^(2^41 - 2)
	for (i = 0; i < 9; ++i) fesq(&t2, &t2); // t2 = z^(2^50 - 2^10)
	fem(&t1, &t2, &t1);            // t1 = z^(2^50 - 1)
	fesq(&t2, &t1);                // t2 = z^(2^51 - 2)
	for (i = 0; i < 49; ++i) fesq(&t2, &t2); // t2 = z^(2^100 - 2^50)
	fem(&t2, &t2, &t1);            // t2 = z^(2^100 - 1)
	fesq(&t3, &t2);                // t3 = z^(2^101 - 2)
	for (i = 0; i < 99; ++i) fesq(&t3, &t3); // t3 = z^(2^200 - 2^100)
	fem(&t2, &t3, &t2);            // t2 = z^(2^200 - 1)
	for (i = 0; i < 50; ++i) fesq(&t2, &t2); // t2 = z^(2^250 - 2^50)
	fem(&t2, &t2, &t1);            // t2 = z^(2^250 - 1)
	for (i = 0; i < 5; ++i) fesq(&t2, &t2);  // t2 = z^(2^255 - 32)
	fem(out, &t2, &t0);            // out = z^(2^255 - 21)
}

static inline void fetobytes(unsigned char s[32], const fe *h){
	long long h0=h->v[0], h1=h->v[1], h2=h->v[2], h3=h->v[3], h4=h->v[4];
	long long h5=h->v[5], h6=h->v[6], h7=h->v[7], h8=h->v[8], h9=h->v[9];
	// ref10: compute q accumulator to ensure 0 <= result < p, then carry
	long long q = (19 * h9 + (1LL<<24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	h0 += 19 * q;
	long long carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	long long carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	long long carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
	long long carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
	long long carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
	long long carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
	long long carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
	long long carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
	long long carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
	// Final wrap like ref10: fold carry9 back into h0 as 19*carry9, then do closing carries
	long long carry9 = h9 >> 25; h9 -= carry9 << 25; h0 += carry9 * 19;
	carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	long long t0=h0,t1=h1,t2=h2,t3=h3,t4=h4,t5=h5,t6=h6,t7=h7,t8=h8,t9=h9;
	s[0]=t0; s[1]=t0>>8; s[2]=t0>>16; s[3]=(t0>>24)|(t1<<2);
	s[4]=t1>>6; s[5]=t1>>14; s[6]=(t1>>22)|(t2<<3);
	s[7]=t2>>5; s[8]=t2>>13; s[9]=(t2>>21)|(t3<<5);
	s[10]=t3>>3; s[11]=t3>>11; s[12]=(t3>>19)|(t4<<6);
	s[13]=t4>>2; s[14]=t4>>10; s[15]=t4>>18;
	s[16]=t5; s[17]=t5>>8; s[18]=t5>>16; s[19]=(t5>>24)|(t6<<1);
	s[20]=t6>>7; s[21]=t6>>15; s[22]=(t6>>23)|(t7<<3);
	s[23]=t7>>5; s[24]=t7>>13; s[25]=(t7>>21)|(t8<<4);
	s[26]=t8>>4; s[27]=t8>>12; s[28]=(t8>>20)|(t9<<6);
	s[29]=t9>>2; s[30]=t9>>10; s[31]=t9>>18;
}

static inline long long load3(const unsigned char *s){
	return ((long long)s[0]) | ((long long)s[1] << 8) | ((long long)s[2] << 16);
}
static inline long long load4(const unsigned char *s){
	return ((long long)s[0]) | ((long long)s[1] << 8) | ((long long)s[2] << 16) | ((long long)s[3] << 24);
}
static inline void fe_frombytes(fe *h, const unsigned char s[32]){
	// Canonical ref10 loader: 10 limbs with 26/25-bit widths from N >> {0,26,51,77,102,128,153,179,204,230}
	long long h0 = 0x3ffffff & (load4(s + 0) >> 0);
	long long h1 = 0x1ffffff & (load4(s + 3) >> 2);
	long long h2 = 0x3ffffff & (load4(s + 6) >> 3);
	long long h3 = 0x1ffffff & (load4(s + 9) >> 5);
	long long h4 = 0x3ffffff & (load4(s + 12) >> 6);
	long long h5 = 0x1ffffff & (load4(s + 16) >> 0);
	long long h6 = 0x3ffffff & (load4(s + 19) >> 1);
	long long h7 = 0x1ffffff & (load4(s + 22) >> 3);
	long long h8 = 0x3ffffff & (load4(s + 25) >> 4);
	long long h9 = 0x1ffffff & (load4(s + 28) >> 6);


	// Carry propagation to canonical radix form (standard ref10 no-bias carries)
	long long carry9 = h9 >> 25;              h9 -= carry9 << 25; h0 += carry9 * 19;

	long long carry1 = h1 >> 25;              h1 -= carry1 << 25; h2 += carry1;
	long long carry3 = h3 >> 25;              h3 -= carry3 << 25; h4 += carry3;
	long long carry5 = h5 >> 25;              h5 -= carry5 << 25; h6 += carry5;
	long long carry7 = h7 >> 25;              h7 -= carry7 << 25; h8 += carry7;

	long long carry0 = h0 >> 26;              h0 -= carry0 << 26; h1 += carry0;
	long long carry2 = h2 >> 26;              h2 -= carry2 << 26; h3 += carry2;
	long long carry4 = h4 >> 26;              h4 -= carry4 << 26; h5 += carry4;
	long long carry6 = h6 >> 26;              h6 -= carry6 << 26; h7 += carry6;
	long long carry8 = h8 >> 26;              h8 -= carry8 << 26; h9 += carry8;

	h->v[0] = (int)h0; h->v[1] = (int)h1; h->v[2] = (int)h2; h->v[3] = (int)h3; h->v[4] = (int)h4;
	h->v[5] = (int)h5; h->v[6] = (int)h6; h->v[7] = (int)h7; h->v[8] = (int)h8; h->v[9] = (int)h9;
}

// BN-based reference X25519 basepoint ladder (for diagnostics only)
static void x25519_basepoint_mul_bn(const unsigned char sk[32], unsigned char out[32]){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *p = BN_new(); BN_zero(p); BN_set_bit(p, 255); BN_sub_word(p, 19);
	BIGNUM *x1 = BN_new(); BN_set_word(x1, 9);
	BIGNUM *x2 = BN_new(); BIGNUM *z2 = BN_new(); BIGNUM *x3 = BN_new(); BIGNUM *z3 = BN_new();
	BN_one(x2); BN_zero(z2); BN_copy(x3, x1); BN_one(z3);
	BIGNUM *a = BN_new(), *aa = BN_new(), *b = BN_new(), *bb = BN_new(), *e = BN_new();
	BIGNUM *c = BN_new(), *d = BN_new(), *da = BN_new(), *cb = BN_new();
	BIGNUM *tmp = BN_new(), *inv = BN_new();
	BIGNUM *a24 = BN_new(); BN_set_word(a24, 121665);
	int swap = 0;
	// Clamp scalar copy
	unsigned char k[32]; memcpy(k, sk, 32); k[0] &= 248; k[31] &= 127; k[31] |= 64;
	for (int pos = 254; pos >= 0; --pos) {
		int bit = (k[pos>>3] >> (pos & 7)) & 1;
		int newswap = swap ^ bit;
		if (newswap) { // conditional swap (diagnostic path; branching OK)
			BIGNUM *tx = x2; x2 = x3; x3 = tx;
			BIGNUM *tz = z2; z2 = z3; z3 = tz;
		}
		swap = bit;
		// A = x2+z2; AA = A^2
		BN_mod_add(a, x2, z2, p, ctx); BN_mod_sqr(aa, a, p, ctx);
		// B = x2-z2; BB = B^2
		BN_mod_sub(b, x2, z2, p, ctx); BN_mod_sqr(bb, b, p, ctx);
		// E = AA-BB
		BN_mod_sub(e, aa, bb, p, ctx);
		// C = x3+z3; D = x3-z3
		BN_mod_add(c, x3, z3, p, ctx); BN_mod_sub(d, x3, z3, p, ctx);
		// DA = D*A; CB = C*B
		BN_mod_mul(da, d, a, p, ctx); BN_mod_mul(cb, c, b, p, ctx);
		// x3' = (DA+CB)^2; z3' = x1*(DA-CB)^2
		BN_mod_add(tmp, da, cb, p, ctx); BN_mod_sqr(x3, tmp, p, ctx);
		BN_mod_sub(tmp, da, cb, p, ctx); BN_mod_sqr(tmp, tmp, p, ctx); BN_mod_mul(z3, tmp, x1, p, ctx);
		// x2' = AA*BB; z2' = E*(AA + a24*E)
		BN_mod_mul(x2, aa, bb, p, ctx);
		BN_mod_mul(tmp, a24, e, p, ctx); BN_mod_add(tmp, aa, tmp, p, ctx); BN_mod_mul(z2, e, tmp, p, ctx);
	}
	if (swap) { BIGNUM *tx = x2; x2 = x3; x3 = tx; BIGNUM *tz = z2; z2 = z3; z3 = tz; }
	inv = BN_mod_inverse(NULL, z2, p, ctx);
	BN_mod_mul(x2, x2, inv, p, ctx);
	// serialize little-endian 32 bytes
	unsigned char be[32]; BN_bn2binpad(x2, be, 32);
	for (int i=0;i<32;++i) out[i] = be[31-i];
	// free
	BN_free(a24); BN_free(inv); BN_free(tmp); BN_free(cb); BN_free(da); BN_free(d); BN_free(c); BN_free(e); BN_free(bb); BN_free(b); BN_free(aa); BN_free(a);
	BN_free(x1); BN_free(x2); BN_free(z2); BN_free(x3); BN_free(z3); BN_free(p); BN_CTX_free(ctx);
}

// BN-based reference multiply (used only in tests/diagnostics)
static inline void fem_ref(fe *h,const fe *f,const fe *g){
	unsigned char fb[32], gb[32]; fetobytes(fb, f); fetobytes(gb, g);
	BN_CTX *ctx = BN_CTX_new(); BIGNUM *p = BN_new(); BN_zero(p); BN_set_bit(p,255); BN_sub_word(p,19);
	BIGNUM *fbn = BN_lebin2bn(fb, 32, NULL); BIGNUM *gbn = BN_lebin2bn(gb, 32, NULL); BIGNUM *rbn = BN_new();
	BN_mod_mul(rbn, fbn, gbn, p, ctx);
	unsigned char rb_be[32]; BN_bn2binpad(rbn, rb_be, 32); // big-endian
	unsigned char rb[32]; for(int i=0;i<32;++i) rb[i] = rb_be[31 - i]; // to little-endian
	fe_frombytes(h, rb);
	BN_free(rbn); BN_free(fbn); BN_free(gbn); BN_free(p); BN_CTX_free(ctx);
}

// Helpers for FE self-tests (random sampling)
static inline uint32_t rand_u32_be(void){ unsigned char b[4]; RAND_bytes(b,4); return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|((uint32_t)b[3]); }
static inline void fe_sample_random(fe *h){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *p = BN_new(); BN_zero(p); BN_set_bit(p,255); BN_sub_word(p,19);
	BIGNUM *r = BN_new(); BN_rand_range(r, p);
	unsigned char be[32]; BN_bn2binpad(r, be, 32);
	unsigned char le[32]; for(int i=0;i<32;++i) le[i] = be[31-i];
	fe_frombytes(h, le);
	BN_free(r); BN_free(p); BN_CTX_free(ctx);
}

static void x25519_basepoint_mul_cpu(const unsigned char sk[32], unsigned char out[32]){
	fe x1; fe0(&x1); x1.v[0]=9;
	fe x2,z2,x3,z3,a,aa,b,bb,e,c,d,da,cb,tmp; fe1(&x2); fe0(&z2); fec(&x3,&x1); fe1(&z3);
	int swap=0; for(int pos=254; pos>=0; --pos){ int bit=(sk[pos>>3]>>(pos&7))&1; swap^=bit; fex(&x2,&x3,swap); fex(&z2,&z3,swap); swap=bit; fea(&a,&x2,&z2); fesq(&aa,&a); fes(&b,&x2,&z2); fesq(&bb,&b); fes(&e,&aa,&bb); fea(&c,&x3,&z3); fes(&d,&x3,&z3); fem(&da,&d,&a); fem(&cb,&c,&b); fea(&tmp,&da,&cb); fesq(&x3,&tmp); fes(&tmp,&da,&cb); fesq(&tmp,&tmp); fem(&z3,&tmp,&x1); fem(&x2,&aa,&bb); fea24(&tmp,&e); fea(&tmp,&aa,&tmp); fem(&z2,&e,&tmp); }
	fex(&x2,&x3,swap); fex(&z2,&z3,swap);
	fe zinv; feinvert(&zinv,&z2); fem(&x2,&x2,&zinv); fetobytes(out,&x2);
}

// Diagnostic: CPU ladder using BN-backed fem_ref/fesq_ref to isolate mul/sq issues
static void x25519_basepoint_mul_cpu_refmul(const unsigned char sk[32], unsigned char out[32]){
	fe x1; fe0(&x1); x1.v[0]=9;
	fe x2,z2,x3,z3,a,aa,b,bb,e,c,d,da,cb,tmp; fe1(&x2); fe0(&z2); fec(&x3,&x1); fe1(&z3);
	int swap=0;
	for(int pos=254; pos>=0; --pos){
		int bit=(sk[pos>>3]>>(pos&7))&1;
		swap^=bit; fex(&x2,&x3,swap); fex(&z2,&z3,swap); swap=bit;
		fea(&a,&x2,&z2);
		fem_ref(&aa,&a,&a);           // AA = A^2
		fes(&b,&x2,&z2);
		fem_ref(&bb,&b,&b);           // BB = B^2
		fes(&e,&aa,&bb);
		fea(&c,&x3,&z3); fes(&d,&x3,&z3);
		fem_ref(&da,&d,&a);           // DA = D*A
		fem_ref(&cb,&c,&b);           // CB = C*B
		fea(&tmp,&da,&cb); fem_ref(&x3,&tmp,&tmp); // x3' = (DA+CB)^2
		fes(&tmp,&da,&cb); fem_ref(&tmp,&tmp,&tmp); fem_ref(&z3,&tmp,&x1); // z3' = x1*(DA-CB)^2
		fem_ref(&x2,&aa,&bb);         // x2' = AA*BB
		// z2' = E*(AA + a24*E), a24 = 121665
		fe a24c; fe0(&a24c); a24c.v[0] = 121665;
		fem_ref(&tmp,&e,&a24c); fea(&tmp,&aa,&tmp); fem_ref(&z2,&e,&tmp);
	}
	fex(&x2,&x3,swap); fex(&z2,&z3,swap);
	fe zinv; feinvert(&zinv,&z2); fem_ref(&x2,&x2,&zinv); fetobytes(out,&x2);
}

static void ladder_get_x2z2(const unsigned char sk[32], fe *out_x2, fe *out_z2){
	fe x1; fe0(&x1); x1.v[0]=9;
	fe x2,z2,x3,z3,a,aa,b,bb,e,c,d,da,cb,tmp; fe1(&x2); fe0(&z2); fec(&x3,&x1); fe1(&z3);
	int swap=0; for(int pos=254; pos>=0; --pos){ int bit=(sk[pos>>3]>>(pos&7))&1; swap^=bit; fex(&x2,&x3,swap); fex(&z2,&z3,swap); swap=bit; fea(&a,&x2,&z2); fesq(&aa,&a); fes(&b,&x2,&z2); fesq(&bb,&b); fes(&e,&aa,&bb); fea(&c,&x3,&z3); fes(&d,&x3,&z3); fem(&da,&d,&a); fem(&cb,&c,&b); fea(&tmp,&da,&cb); fesq(&x3,&tmp); fes(&tmp,&da,&cb); 
	// Update z3' = x1*(DA-CB)^2
	fesq(&tmp,&tmp); fem(&z3,&tmp,&x1);
	// X2' = AA*BB
	fem(&x2,&aa,&bb);
	// Z2' = E * (AA + a24*E), a24 = 121665
	fe a24c; fe0(&a24c); a24c.v[0] = 121665; fem(&tmp,&e,&a24c); fea(&tmp,&aa,&tmp); fem(&z2,&e,&tmp); }
	fex(&x2,&x3,swap); fex(&z2,&z3,swap);
	fec(out_x2, &x2); fec(out_z2, &z2);
}
#endif

// Normalize fe to ref10 carry form and build BIGNUM directly from limbs
#ifdef ME_KEYGEN_OPENCL
static void fe_to_canonical_limbs(const fe *h, long long t[10]) __attribute__((unused));
static void fe_to_canonical_limbs(const fe *h, long long t[10]){
	// Mirror fetobytes' ref10 q-based canonicalization
	long long h0=h->v[0], h1=h->v[1], h2=h->v[2], h3=h->v[3], h4=h->v[4];
	long long h5=h->v[5], h6=h->v[6], h7=h->v[7], h8=h->v[8], h9=h->v[9];
	long long q = (19 * h9 + (1LL<<24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	h0 += 19 * q;
	long long carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	long long carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	long long carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
	long long carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
	long long carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
	long long carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
	long long carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
	long long carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
	long long carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
	// Final wrap and closing carries per ref10
	long long carry9 = h9 >> 25; h9 -= carry9 << 25; h0 += carry9 * 19;
	carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	t[0]=h0; t[1]=h1; t[2]=h2; t[3]=h3; t[4]=h4;
	t[5]=h5; t[6]=h6; t[7]=h7; t[8]=h8; t[9]=h9;
}
static BIGNUM* BN_from_fe_limbs(const fe *h){
	// Reconstruct big integer directly from limbs, then reduce mod p
	// N = sum_{i=0..9} h[i] * 2^{shift[i]}, shift widths: [0,26,51,77,102,128,153,179,204,230]
	static const int shifts[10] = {0,26,51,77,102,128,153,179,204,230};
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *r = BN_new(); BN_zero(r);
	BIGNUM *tmp = BN_new();
	for (int i = 0; i < 10; ++i) {
		long long vi = (long long)h->v[i];
		if (vi == 0) continue;
		BN_set_word(tmp, (vi < 0) ? (unsigned long long)(-vi) : (unsigned long long)vi);
		if (shifts[i] > 0) BN_lshift(tmp, tmp, shifts[i]);
		if (vi < 0) BN_sub(r, r, tmp); else BN_add(r, r, tmp);
	}
	// Reduce modulo p = 2^255 - 19 to obtain canonical representative in [0,p)
	BIGNUM *p = BN_new(); BN_zero(p); BN_set_bit(p, 255); BN_sub_word(p, 19);
	BN_mod(r, r, p, ctx);
	BN_free(p); BN_free(tmp); BN_CTX_free(ctx);
	return r;
}
#endif
// --- CPU Philox4x32-10 (matches OpenCL kernel constants) ---
static inline uint32_t mulhi32_u32(uint32_t a, uint32_t b) {
	uint64_t w = (uint64_t)a * (uint64_t)b;
	return (uint32_t)(w >> 32);
}

static inline void philox4x32_round_u32(uint32_t ctr[4], uint32_t key[2]) {
	const uint32_t MUL0 = 0xD2511F53U;
	const uint32_t MUL1 = 0xCD9E8D57U;
	uint32_t hi0 = mulhi32_u32(ctr[0], MUL0);
	uint32_t lo0 = ctr[0] * MUL0;
	uint32_t hi1 = mulhi32_u32(ctr[2], MUL1);
	uint32_t lo1 = ctr[2] * MUL1;
	uint32_t n0 = hi1 ^ ctr[1] ^ key[0];
	uint32_t n1 = lo1;
	uint32_t n2 = hi0 ^ ctr[3] ^ key[1];
	uint32_t n3 = lo0;
	ctr[0] = n0; ctr[1] = n1; ctr[2] = n2; ctr[3] = n3;
	const uint32_t W0 = 0x9E3779B9U;
	const uint32_t W1 = 0xBB67AE85U;
	key[0] += W0; key[1] += W1;
}

static inline void philox4x32_10_u32(uint32_t ctr[4], uint32_t key[2]) {
	for (int i = 0; i < 10; ++i) philox4x32_round_u32(ctr, key);
}

#ifdef ME_KEYGEN_OPENCL
static void philox_fill32_for_gid(uint64_t seed, uint32_t gid, unsigned char out32[32]) {
	// Build key per ocl host seeds generation in ocl_rng_dump
	uint32_t k0 = (uint32_t)(seed ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(gid + 1)));
	uint32_t k1 = (uint32_t)(gid * 0xD2511F53U + 1U);
	uint32_t key0[2] = { k0, k1 };
	uint32_t key1[2] = { k0, k1 };
	uint32_t c0[4] = { gid, 0u, 0u, 0u };
	uint32_t c1[4] = { gid, 1u, 0u, 0u };
	philox4x32_10_u32(c0, key0);
	philox4x32_10_u32(c1, key1);
	uint32_t words[8] = { c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2], c1[3] };
	int bi = 0;
	for (int i = 0; i < 8; ++i) {
		uint32_t w = words[i];
		out32[bi++] = (unsigned char)(w & 0xFF);
		out32[bi++] = (unsigned char)((w >> 8) & 0xFF);
		out32[bi++] = (unsigned char)((w >> 16) & 0xFF);
		out32[bi++] = (unsigned char)((w >> 24) & 0xFF);
	}
}
#endif


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

	// Batch RNG to reduce RAND_bytes overhead and locking
	enum { RAND_KEYS_BATCH = 4096 };
	unsigned char rand_buf[RAND_KEYS_BATCH * 32];
	size_t rand_off = RAND_KEYS_BATCH * 32; // force initial refill

	while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
		// Generate random private key bytes (buffered)
		if (rand_off >= sizeof(rand_buf)) {
			if (RAND_bytes(rand_buf, sizeof(rand_buf)) != 1) {
				continue; // try next
			}
			rand_off = 0;
		}
		memcpy(priv_key, rand_buf + rand_off, 32);
		rand_off += 32;

	// Clamp private key per X25519 spec
	priv_key[0] &= 248;
	priv_key[31] &= 127;
	priv_key[31] |= 64;

	// Derive public key: try fast X25519_public_from_private if available, else EVP fallback
		if (!x25519_pub_from_priv_dyn(pub_key, priv_key)) {
			EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_key, 32);
			if (!pkey) continue;
			size_t len = 32;
			if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &len) <= 0) { EVP_PKEY_free(pkey); continue; }
			EVP_PKEY_free(pkey);
		}

		// Base64 encode public and check match
		base64_encode_32(pub_key, b64_pub);

		// Count this generated key regardless of match (batch to reduce contention)
		if (++local_cnt >= 1024) {
			atomic_fetch_add_explicit(&g_key_count, local_cnt, memory_order_relaxed);
			local_cnt = 0;
		}

		int matched = 0;
		for (size_t i = 0; i < g_patterns_count; ++i) {
			struct search_pattern *sp = &g_patterns[i];
			if ((sp->prefix_len > 0 && memcmp(b64_pub, sp->prefix, sp->prefix_len) == 0) ||
				(sp->suffix_len > 0 && memcmp(b64_pub + sp->suffix_off, sp->suffix, sp->suffix_len) == 0)) {
				matched = 1;
				break;
			}
		}
		if (matched) {
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

static int add_pattern(const char *prefix_opt, const char *suffix_opt) {
	if (!prefix_opt && !suffix_opt) return -1;
	if (g_patterns_count == g_patterns_cap) {
		size_t new_cap = g_patterns_cap ? g_patterns_cap * 2 : 4;
		void *np = realloc(g_patterns, new_cap * sizeof(*g_patterns));
		if (!np) return -1;
		g_patterns = (struct search_pattern *)np;
		g_patterns_cap = new_cap;
	}
	struct search_pattern *p = &g_patterns[g_patterns_count];
	memset(p, 0, sizeof(*p));
	if (prefix_opt) {
		p->prefix = strdup(prefix_opt);
		if (!p->prefix) return -1;
		p->prefix_len = strlen(p->prefix);
	}
	if (suffix_opt) {
		p->suffix = strdup(suffix_opt);
		if (!p->suffix) return -1;
		p->suffix_len = strlen(p->suffix);
		p->suffix_off = (p->suffix_len <= BASE64_LEN) ? (BASE64_LEN - p->suffix_len) : 0;
	}
	g_patterns_count++;
	return 0;
}

static int add_search_string(const char *s) {
	if (!s) return -1;
	size_t slen = strlen(s);
	int rc = 0;
	if (!g_better) {
		// Base pattern: prefix=s, suffix=s"="
		char *suf = (char *)malloc(slen + 2);
		if (!suf) return -1;
		memcpy(suf, s, slen);
		suf[slen] = '=';
		suf[slen + 1] = '\0';
		rc = add_pattern(s, suf);
		free(suf);
		if (rc != 0) return rc;
	} else {
		// Only add visually-better variants
		// Prefix variants: s+"/" and s"+"
		char *pre1 = (char *)malloc(slen + 2);
		char *pre2 = (char *)malloc(slen + 2);
		if (!pre1 || !pre2) { free(pre1); free(pre2); return -1; }
		memcpy(pre1, s, slen); pre1[slen] = '/'; pre1[slen + 1] = '\0';
		memcpy(pre2, s, slen); pre2[slen] = '+'; pre2[slen + 1] = '\0';
		rc = add_pattern(pre1, NULL); if (rc == 0) rc = add_pattern(pre2, NULL);
		free(pre1); free(pre2);
		if (rc != 0) return rc;

		// Suffix variants: "/"+s+"=" and "+"+s+"="
		char *suf1 = (char *)malloc(slen + 2 + 1);
		char *suf2 = (char *)malloc(slen + 2 + 1);
		if (!suf1 || !suf2) { free(suf1); free(suf2); return -1; }
		suf1[0] = '/'; memcpy(suf1 + 1, s, slen); suf1[1 + slen] = '='; suf1[1 + slen + 1] = '\0';
		suf2[0] = '+'; memcpy(suf2 + 1, s, slen); suf2[1 + slen] = '='; suf2[1 + slen + 1] = '\0';
		rc = add_pattern(NULL, suf1); if (rc == 0) rc = add_pattern(NULL, suf2);
		free(suf1); free(suf2);
		if (rc != 0) return rc;
	}
	return 0;
}

static void print_usage(const char *prog) {
	fprintf(stderr, "Usage: %s [-t N|--threads N] [-s STR|--search STR]... [-c N|--count N] [--affinity] [-q|--quiet] [-b|--better] [-g|--gpu]\n", prog);
	fprintf(stderr, "  -s STR: required (can be repeated). STR must contain only Base64 characters [A-Za-z0-9+/] (no '=').\n");
	fprintf(stderr, "  -t N  : optional. Number of threads (default %d).\n", DEFAULT_NUM_THREADS);
	fprintf(stderr, "  -c N  : optional. Stop after finding N matches (default 1).\n");
	fprintf(stderr, "  -q, --quiet: optional. Disable periodic reporting.\n");
	fprintf(stderr, "  --affinity: optional. Pin worker threads to CPU cores (Linux).\n");
	fprintf(stderr, "  -b, --better: optional. Only match visually tighter variants: prefix STR/ and STR+; suffix /STR= and +STR=. (Base STR/STR= are skipped.)\n");
	fprintf(stderr, "  -g, --gpu: optional. Use OpenCL GPU implementation (experimental). Requires OpenCL runtime and kernel file opencl_keygen.cl.\n");
	fprintf(stderr, "  GPU tuning flags (CLI overrides env MEKG_OCL_*):\n");
	fprintf(stderr, "    --gpu-gsize N     : Global work size (default 16384)\n");
	fprintf(stderr, "    --gpu-lsize N     : Local work-group size (default 128)\n");
	fprintf(stderr, "    --gpu-iters N     : Iterations per work-item (default 64, capped at 512)\n");
	fprintf(stderr, "    --gpu-autotune    : Enable OpenCL autotune to select parameters within a time budget\n");
	fprintf(stderr, "    --gpu-budget-ms N : Autotune per-dispatch time budget in ms (default 30)\n");
	fprintf(stderr, "    --gpu-max-keys N  : Cap keys per dispatch (global*iters) to avoid desktop freezes (default 1048576)\n");
	// Hidden: set MEKG_TEST_RNG=1 to run RNG consistency test instead of keygen
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

	// Detect CPU features and select FE backend (baseline for now; ADX/BMI2 coming next)
	cpu_detect_features();
	// Future: if (g_has_adx && g_has_bmi2) g_fe_mul = fem_adx; g_fe_sq = fesq_adx;

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
	// Collect search strings first to apply -b consistently regardless of option order
	char **searches = NULL;
	size_t searches_count = 0, searches_cap = 0;
	static struct option long_opts[] = {
		{"threads", required_argument, 0, 't'},
		{"search",  required_argument, 0, 's'},
		{"count",   required_argument, 0, 'c'},
		{"affinity", no_argument,       0,  1 },
		{"quiet",    no_argument,       0, 'q'},
		{"better",   no_argument,       0, 'b'},
		{"gpu",      no_argument,       0, 'g'},
		{"gpu-gsize", required_argument, 0,  2 },
		{"gpu-lsize", required_argument, 0,  3 },
		{"gpu-iters", required_argument, 0,  4 },
		{"gpu-autotune", no_argument,    0,  5 },
		{"gpu-budget-ms", required_argument, 0, 6 },
		{"gpu-max-keys", required_argument, 0, 7 },
		{0, 0, 0, 0}
	};
	int opt, idx;
	// Capture CLI GPU tuning values
	size_t cli_gsize = 0, cli_lsize = 0; unsigned int cli_iters = 0; int cli_autotune = -1; unsigned int cli_budget_ms = 0; unsigned long long cli_max_keys = 0ULL;
	while ((opt = getopt_long(argc, argv, "t:s:c:qbg", long_opts, &idx)) != -1) {
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
				if (searches_count == searches_cap) {
					size_t new_cap = searches_cap ? searches_cap * 2 : 4;
					char **tmp = (char **)realloc(searches, new_cap * sizeof(*searches));
					if (!tmp) { fprintf(stderr, "Out of memory\n"); return 1; }
					searches = tmp; searches_cap = new_cap;
				}
				searches[searches_count] = strdup(optarg);
				if (!searches[searches_count]) { fprintf(stderr, "Out of memory\n"); return 1; }
				searches_count++;
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
			case 'b':
				g_better = 1;
				break;
			case 'g':
				g_use_gpu = 1;
				break;
			case 2: { // --gpu-gsize
				unsigned long long v = strtoull(optarg, NULL, 10);
				if (v == 0) { fprintf(stderr, "Invalid --gpu-gsize\n"); return 1; }
				cli_gsize = (size_t)v;
				g_use_gpu = 1;
			} break;
			case 3: { // --gpu-lsize
				unsigned long long v = strtoull(optarg, NULL, 10);
				if (v == 0) { fprintf(stderr, "Invalid --gpu-lsize\n"); return 1; }
				cli_lsize = (size_t)v;
				g_use_gpu = 1;
			} break;
			case 4: { // --gpu-iters
				unsigned long v = strtoul(optarg, NULL, 10);
				if (v == 0) { fprintf(stderr, "Invalid --gpu-iters\n"); return 1; }
				cli_iters = (unsigned int)v;
				g_use_gpu = 1;
			} break;
			case 5: { // --gpu-autotune
				cli_autotune = 1; g_use_gpu = 1;
			} break;
			case 6: { // --gpu-budget-ms
				unsigned long v = strtoul(optarg, NULL, 10);
				if (v == 0) { fprintf(stderr, "Invalid --gpu-budget-ms\n"); return 1; }
				cli_budget_ms = (unsigned int)v; g_use_gpu = 1;
			} break;
			case 7: { // --gpu-max-keys
				unsigned long long v = strtoull(optarg, NULL, 10);
				if (v == 0) { fprintf(stderr, "Invalid --gpu-max-keys\n"); return 1; }
				cli_max_keys = v; g_use_gpu = 1;
			} break;
			default:
				print_usage(argv[0]);
				return 1;
		}
	}

	if (!g_quiet) {
		fprintf(stderr, "CPU features: BMI2=%d ADX=%d AVX2=%d AVX512IFMA=%d\n", g_has_bmi2, g_has_adx, g_has_avx2, g_has_avx512ifma);
		fflush(stderr);
	}

#ifndef ME_KEYGEN_OPENCL
	// When built without OpenCL, GPU-related CLI values are parsed but unused; mark them used to avoid warnings.
	(void)cli_gsize; (void)cli_lsize; (void)cli_iters; (void)cli_autotune; (void)cli_budget_ms; (void)cli_max_keys;
#endif

	// Read hidden test env flags early so we can skip required -s in test modes
	const char *env_test = getenv("MEKG_TEST_RNG");
	if (env_test && *env_test == '1') { g_test_rng = 1; }
	const char *env_pub = getenv("MEKG_TEST_PUB");
	if (env_pub && *env_pub == '1') { g_test_pub = 1; }
	const char *env_rfc = getenv("MEKG_TEST_RFC");
	if (env_rfc && *env_rfc == '1') { g_test_rfc = 1; }
	const char *env_trace = getenv("MEKG_TEST_TRACE");
	const char *env_fe = getenv("MEKG_TEST_FE");
	if (env_fe && atoi(env_fe) != 0) g_test_fe = 1;
	if (env_trace && *env_trace == '1') { g_test_trace = 1; }
	// Hidden CPU benchmark: MEKG_BENCH_MS=duration_ms runs CPU-only for duration and prints keys/s
	const char *env_bench_ms = getenv("MEKG_BENCH_MS");
	unsigned int bench_ms = env_bench_ms ? (unsigned int)strtoul(env_bench_ms, NULL, 10) : 0U;
	const char *env_one = getenv("MEKG_TEST_ONE_SK_HEX");
	int any_test_mode = g_test_rng || g_test_pub || g_test_rfc || g_test_trace || g_test_fe || (env_one && *env_one) || (bench_ms > 0);

	// After parsing, create search patterns from collected strings (respects -b), unless in test mode
	if (!any_test_mode) {
		if (searches_count == 0) {
			fprintf(stderr, "Error: missing required --search|-s STRING option (can be specified multiple times).\n");
			print_usage(argv[0]);
			return 1;
		}
		for (size_t i = 0; i < searches_count; ++i) {
			if (add_search_string(searches[i]) != 0) { fprintf(stderr, "Failed to add search string\n"); return 1; }
		}
		for (size_t i = 0; i < searches_count; ++i) free(searches[i]);
		free(searches);

		// (duplicate print of search patterns removed)
	} else {
		// In test mode, free any collected search strings and skip building patterns
		for (size_t i = 0; i < searches_count; ++i) free(searches[i]);
		free(searches);
	}

	// Print search patterns (prefixes and suffixes)
	{
		// Count and print prefixes
		size_t pcount = 0, scount = 0;
		for (size_t i = 0; i < g_patterns_count; ++i) {
			if (g_patterns[i].prefix_len > 0) pcount++;
			if (g_patterns[i].suffix_len > 0) scount++;
		}
		fprintf(stderr, "Search patterns:\n");
		fprintf(stderr, "  Prefixes (%zu): ", pcount);
		{
			int first = 1;
			for (size_t i = 0; i < g_patterns_count; ++i) {
				if (g_patterns[i].prefix_len > 0 && g_patterns[i].prefix) {
					if (!first) fprintf(stderr, ", ");
					fwrite(g_patterns[i].prefix, 1, g_patterns[i].prefix_len, stderr);
					first = 0;
				}
			}
			fprintf(stderr, "\n");
		}
		fprintf(stderr, "  Suffixes (%zu): ", scount);
		{
			int first = 1;
			for (size_t i = 0; i < g_patterns_count; ++i) {
				if (g_patterns[i].suffix_len > 0 && g_patterns[i].suffix) {
					if (!first) fprintf(stderr, ", ");
					fwrite(g_patterns[i].suffix, 1, g_patterns[i].suffix_len, stderr);
					first = 0;
				}
			}
			fprintf(stderr, "\n");
		}
		fflush(stderr);
	}

    // env flags already read above; proceed to optional test blocks

	// Hidden: MEKG_TEST_ONE_SK_HEX=hex32: compute pub on CPU and GPU from this scalar
	{
		const char *one_sk_hex = getenv("MEKG_TEST_ONE_SK_HEX");
		if (one_sk_hex && one_sk_hex[0]) {
#ifdef ME_KEYGEN_OPENCL
			unsigned char sk[32];
			if (strlen(one_sk_hex) != 64) { fprintf(stderr, "MEKG_TEST_ONE_SK_HEX must be 64 hex chars (32 bytes)\n"); return 2; }
			for (int i=0;i<32;++i) {
				char hi = one_sk_hex[i*2], lo = one_sk_hex[i*2+1];
				int vh = (hi >= '0' && hi <= '9') ? (hi - '0') : (hi >= 'a' && hi <= 'f') ? (hi - 'a' + 10) : (hi >= 'A' && hi <= 'F') ? (hi - 'A' + 10) : -1;
				int vl = (lo >= '0' && lo <= '9') ? (lo - '0') : (lo >= 'a' && lo <= 'f') ? (lo - 'a' + 10) : (lo >= 'A' && lo <= 'F') ? (lo - 'A' + 10) : -1;
				if (vh < 0 || vl < 0) { fprintf(stderr, "Invalid hex in MEKG_TEST_ONE_SK_HEX\n"); return 2; }
				sk[i] = (unsigned char)((vh << 4) | vl);
			}
			// Clamp per X25519
			sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
			// CPU pub (OpenSSL)
			unsigned char cpu_pub[32]; size_t len=32;
			EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
			if (!pkey) { fprintf(stderr, "OpenSSL private key creation failed\n"); return 3; }
			if (EVP_PKEY_get_raw_public_key(pkey, cpu_pub, &len) <= 0 || len != 32) { EVP_PKEY_free(pkey); fprintf(stderr, "OpenSSL pubkey derivation failed\n"); return 3; }
			EVP_PKEY_free(pkey);
			// BN reference pub via diagnostic ladder
			{
				unsigned char bn_pub[32];
				x25519_basepoint_mul_bn(sk, bn_pub);
				char bn_b64[45]; base64_encode_32(bn_pub, bn_b64);
				fprintf(stderr, "ONE-SK BN  pub: %s\n", bn_b64);
			}
			// GPU pub via direct kernel
			unsigned char gpu_pub[32];
			int got = ocl_pub_from_secrets("opencl_keygen.cl", sk, 1, gpu_pub);
			if (got != 1) { fprintf(stderr, "ocl_pub_from_secrets failed (%d)\n", got); return 4; }
			char cpu_b64[45], gpu_b64[45];
			base64_encode_32(cpu_pub, cpu_b64);
			base64_encode_32(gpu_pub, gpu_b64);
			fprintf(stderr, "ONE-SK CPU pub: %s\nONE-SK GPU pub: %s\n", cpu_b64, gpu_b64);
			if (memcmp(cpu_pub, gpu_pub, 32) != 0) {
				// Deep debug: call GPU debug kernel to dump x2,z2,zinv,x and bytes
				int limbs[40]; unsigned char dbg_bytes[32]; int swap_bit=0; int pre_limbs[80];
				int drc = ocl_debug_final("opencl_keygen.cl", sk, limbs, dbg_bytes, &swap_bit, pre_limbs);
				if (drc != 0) { fprintf(stderr, "ocl_debug_final failed (%d)\n", drc); return 5; }
				// Reproduce CPU ladder to x2/z2 and compute zinv and x, then compare limbs
				fe cx2, cz2; unsigned char skc[32]; memcpy(skc, sk, 32); skc[0]&=248; skc[31]&=127; skc[31]|=64; ladder_get_x2z2(skc, &cx2, &cz2);
				fe czi, cx; feinvert(&czi, &cz2); fem(&cx, &cx2, &czi);
				// Print first mismatch stage
				int mismatch_stage = 0; // 1=x2,2=z2,3=zinv,4=x,5=bytes
				for (int i=0;i<10;++i) if (cx2.v[i] != limbs[i]) { mismatch_stage = 1; break; }
				if (mismatch_stage==0) for (int i=0;i<10;++i) if (cz2.v[i] != limbs[10+i]) { mismatch_stage = 2; break; }
				if (mismatch_stage==0) for (int i=0;i<10;++i) if (czi.v[i] != limbs[20+i]) { mismatch_stage = 3; break; }
				if (mismatch_stage==0) for (int i=0;i<10;++i) if (cx.v[i]  != limbs[30+i]) { mismatch_stage = 4; break; }
				unsigned char cx_b[32]; fetobytes(cx_b, &cx);
				if (mismatch_stage==0 && memcmp(cx_b, dbg_bytes, 32) != 0) mismatch_stage = 5;
				fprintf(stderr, "DEBUG: mismatch stage = %d (1=x2 2=z2 3=zinv 4=x 5=bytes)\n", mismatch_stage);
				// Provide compact dumps
				if (mismatch_stage>=1) { fprintf(stderr, "CPU x2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cx2.v[i]); fprintf(stderr, "\nGPU x2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", limbs[i]); fprintf(stderr, "\n"); }
				if (mismatch_stage>=2 || mismatch_stage==0) { fprintf(stderr, "CPU z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cz2.v[i]); fprintf(stderr, "\nGPU z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", limbs[10+i]); fprintf(stderr, "\n"); }
				if (mismatch_stage>=3 || mismatch_stage==0) { fprintf(stderr, "CPU zinv:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", czi.v[i]); fprintf(stderr, "\nGPU zinv:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", limbs[20+i]); fprintf(stderr, "\n"); }
				if (mismatch_stage>=4 || mismatch_stage==0) { fprintf(stderr, "CPU x:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cx.v[i]); fprintf(stderr, "\nGPU x:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", limbs[30+i]); fprintf(stderr, "\n"); }
				char cx_b64[45], dbg_b64[45]; base64_encode_32(cx_b, cx_b64); base64_encode_32(dbg_bytes, dbg_b64);
				// Also compute using our CPU mirror ladder to verify host FE pipeline
					unsigned char cpu_mir_pk[32]; x25519_basepoint_mul_cpu(skc, cpu_mir_pk);
					unsigned char cpu_refmul_pk[32]; x25519_basepoint_mul_cpu_refmul(skc, cpu_refmul_pk);
					char cpu_mir_b64[45], cpu_refmul_b64[45]; base64_encode_32(cpu_mir_pk, cpu_mir_b64); base64_encode_32(cpu_refmul_pk, cpu_refmul_b64);
					fprintf(stderr, "CPU bytes (from x2/z2): %s\nCPU mirror pub      : %s\nCPU refmul pub      : %s\nGPU bytes           : %s\n", cx_b64, cpu_mir_b64, cpu_refmul_b64, dbg_b64);
				// Print final swap bit and pre-final-cswap limbs from GPU, and compute CPU pre/post for comparison
				// Derive CPU pre-final-cswap by replaying ladder and capturing before last cswap
				{
					fe tx1; fe0(&tx1); tx1.v[0]=9;
					fe tx2, tz2, tx3, tz3, a, aa, b, bb, e, c, d, da, cb, ttmp; fe1(&tx2); fe0(&tz2); fec(&tx3,&tx1); fe1(&tz3);
					int tswap=0; for(int pos=254; pos>=0; --pos){ int bit=(skc[pos>>3]>>(pos&7))&1; tswap^=bit; fex(&tx2,&tx3,tswap); fex(&tz2,&tz3,tswap); tswap=bit; fea(&a,&tx2,&tz2); fesq(&aa,&a); fes(&b,&tx2,&tz2); fesq(&bb,&b); fes(&e,&aa,&bb); fea(&c,&tx3,&tz3); fes(&d,&tx3,&tz3); fem(&da,&d,&a); fem(&cb,&c,&b); fea(&ttmp,&da,&cb); fesq(&tx3,&ttmp); fes(&ttmp,&da,&cb); fesq(&ttmp,&ttmp); fem(&tz3,&ttmp,&tx1); fem(&tx2,&aa,&bb); fea24(&ttmp,&e); fea(&ttmp,&aa,&ttmp); fem(&tz2,&e,&ttmp); }
					// At loop end, before final cswap is applied in our CPU helpers, tx2/tz2 represent pre-final-cswap state
					fprintf(stderr, "GPU swap bit: %d\n", swap_bit);
					fprintf(stderr, "GPU pre X2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", pre_limbs[i]); fprintf(stderr, "\n");
					fprintf(stderr, "GPU pre Z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", pre_limbs[10+i]); fprintf(stderr, "\n");
					// If available, print last-iter intermediates from GPU
					fprintf(stderr, "GPU last aa :"); for(int i=0;i<10;++i) fprintf(stderr, " %d", pre_limbs[20+i]); fprintf(stderr, "\n");
					fprintf(stderr, "GPU last bb :"); for(int i=0;i<10;++i) fprintf(stderr, " %d", pre_limbs[30+i]); fprintf(stderr, "\n");
					fprintf(stderr, "GPU last e  :"); for(int i=0;i<10;++i) fprintf(stderr, " %d", pre_limbs[40+i]); fprintf(stderr, "\n");
					fprintf(stderr, "GPU last x2':"); for(int i=0;i<10;++i) fprintf(stderr, " %d", pre_limbs[50+i]); fprintf(stderr, "\n");
					fprintf(stderr, "GPU last z2':"); for(int i=0;i<10;++i) fprintf(stderr, " %d", pre_limbs[60+i]); fprintf(stderr, "\n");
					fprintf(stderr, "CPU pre X2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", tx2.v[i]); fprintf(stderr, "\n");
					fprintf(stderr, "CPU pre Z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", tz2.v[i]); fprintf(stderr, "\n");
					fprintf(stderr, "CPU swap bit: %d\n", tswap);
					fe tx2_post=tx2, tz2_post=tz2; fex(&tx2_post,&tx3,tswap); fex(&tz2_post,&tz3,tswap);
					fprintf(stderr, "CPU post X2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", tx2_post.v[i]); fprintf(stderr, "\n");
					fprintf(stderr, "CPU post Z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", tz2_post.v[i]); fprintf(stderr, "\n");
					// Now compute CPU zinv/x from the pre/post state (post state should be used for final X)
					fe czi2, cx2p; feinvert(&czi2, &tz2_post); fem(&cx2p, &tx2_post, &czi2);
					fprintf(stderr, "CPU zinv from post Z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", czi2.v[i]); fprintf(stderr, "\n");
					fprintf(stderr, "CPU x from post:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cx2p.v[i]); fprintf(stderr, "\n");
					unsigned char cx2p_b[32]; fetobytes(cx2p_b, &cx2p); char cx2p_b64[45]; base64_encode_32(cx2p_b, cx2p_b64);
					fprintf(stderr, "CPU bytes (post state): %s\n", cx2p_b64);
					// Compare with GPU zinv/x limbs from debug
					fprintf(stderr, "GPU zinv:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", limbs[20+i]); fprintf(stderr, "\n");
					fprintf(stderr, "GPU x   :"); for(int i=0;i<10;++i) fprintf(stderr, " %d", limbs[30+i]); fprintf(stderr, "\n");
				}
				// Also run per-step trace for this scalar to locate first divergence
				const unsigned K=255; int cpu_step[40*K]; int gpu_step[40*K];
				// CPU trace loop (mirrors g_test_trace but with provided scalar)
				{
					fe x1; fe0(&x1); x1.v[0]=9;
					fe tx2,tz2,tx3,tz3,a,aa,b,bb,e,c,d,da,cb,tmp; fe1(&tx2); fe0(&tz2); fec(&tx3,&x1); fe1(&tz3);
					int swap=0; unsigned step=0; for (int pos=254; pos>=0 && step<K; --pos,++step){ int bit=(skc[pos>>3]>>(pos&7))&1; swap^=bit; fex(&tx2,&tx3,swap); fex(&tz2,&tz3,swap); swap=bit; fea(&a,&tx2,&tz2); fesq(&aa,&a); fes(&b,&tx2,&tz2); fesq(&bb,&b); fes(&e,&aa,&bb); fea(&c,&tx3,&tz3); fes(&d,&tx3,&tz3); fem(&da,&d,&a); fem(&cb,&c,&b); fea(&tmp,&da,&cb); fesq(&tx3,&tmp); fes(&tmp,&da,&cb); fesq(&tmp,&tmp); fem(&tz3,&tmp,&x1); fem(&tx2,&aa,&bb); fea24(&tmp,&e); fea(&tmp,&aa,&tmp); fem(&tz2,&e,&tmp); int base=step*40; for(int i=0;i<10;++i) cpu_step[base+i]=tx2.v[i]; for(int i=0;i<10;++i) cpu_step[base+10+i]=tz2.v[i]; for(int i=0;i<10;++i) cpu_step[base+20+i]=tx3.v[i]; for(int i=0;i<10;++i) cpu_step[base+30+i]=tz3.v[i]; }
				}
				int got = ocl_trace_ladder("opencl_keygen.cl", skc, K, gpu_step);
				if (got < 0) { fprintf(stderr, "ocl_trace_ladder failed (%d)\n", got); }
				else {
					for (unsigned st=0; st<K; ++st){ int base=st*40; int mismatch=-1; for(int i=0;i<40;++i){ if(cpu_step[base+i]!=gpu_step[base+i]){ mismatch=i; break; }} if(mismatch>=0){ const char* which = (mismatch<10)?"X2":(mismatch<20)?"Z2":(mismatch<30)?"X3":"Z3"; int idx = mismatch%10; fprintf(stderr, "TRACE DIVERGE at step %u: %s limb %d: CPU=%d GPU=%d\n", st, which, idx, cpu_step[base+mismatch], gpu_step[base+mismatch]); break; } }
				}
				return 5;
			}
			return 0;
#else
			fprintf(stderr, "Built without OpenCL; MEKG_TEST_ONE_SK_HEX unavailable.\n");
			return 2;
#endif
		}
	}

	if (g_test_rng) {
#ifdef ME_KEYGEN_OPENCL
		// Deterministic RNG consistency test: compare GPU base64(clamped secret) vs CPU for N samples
		size_t N = 1024;
		char *gpu_out = (char*)malloc(45 * N);
		unsigned long long seed = (unsigned long long)0xA5A5A5A5A5A5A5A5ULL;
		int got = ocl_rng_dump("opencl_keygen.cl", N, 256, seed, gpu_out, N);
		if (got <= 0) { fprintf(stderr, "RNG dump failed (%d)\n", got); free(gpu_out); return 2; }
		// CPU mirror RNG for philox mapping used in rng_dump_kernel (two blocks per gid: (gid,0) and (gid,1))
		for (size_t gid = 0; gid < (size_t)got; ++gid) {
			unsigned char sk[32];
			philox_fill32_for_gid(seed, (uint32_t)gid, sk);
			sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
			char cpu_b64[45]; base64_encode_32(sk, cpu_b64);
			if (memcmp(cpu_b64, gpu_out + gid*45, 44) != 0) {
				fprintf(stderr, "RNG mismatch at %zu\n", gid);
				fwrite(cpu_b64, 1, 44, stderr); fputc('\n', stderr);
				fwrite(gpu_out + gid*45, 1, 44, stderr); fputc('\n', stderr);
				free(gpu_out);
				return 3;
			}
		}
		fprintf(stderr, "RNG CPU==GPU: %d samples matched.\n", got);
		free(gpu_out);
		return 0;
#else
		fprintf(stderr, "Built without OpenCL; RNG test unavailable.\n");
		return 2;
#endif
	} else if (g_test_pub) {
#ifdef ME_KEYGEN_OPENCL
		// Compare GPU pubkeys vs OpenSSL for the same RNG-derived secrets
		size_t N = 256;
		unsigned long long seed = (unsigned long long)0xA5A5A5A5A5A5A5A5ULL;
		unsigned char *gpu_pub = (unsigned char*)malloc(32 * N);
		int got = ocl_pubkey_dump("opencl_keygen.cl", N, 256, seed, gpu_pub, N);
		if (got <= 0) { fprintf(stderr, "PUB dump failed (%d)\n", got); free(gpu_pub); return 2; }
		for (size_t gid = 0; gid < (size_t)got; ++gid) {
			unsigned char sk[32]; philox_fill32_for_gid(seed, (uint32_t)gid, sk);
			sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
			// Compute CPU pub via OpenSSL
			unsigned char pub[32]; size_t len = 32;
			EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
			if (!pkey) { fprintf(stderr, "EVP_PKEY_new_raw_private_key failed\n"); free(gpu_pub); return 3; }
			int ok = EVP_PKEY_get_raw_public_key(pkey, pub, &len);
			EVP_PKEY_free(pkey);
			if (ok <= 0 || len != 32) { fprintf(stderr, "EVP_PKEY_get_raw_public_key failed\n"); free(gpu_pub); return 3; }
			if (memcmp(pub, gpu_pub + gid*32, 32) != 0) {
				fprintf(stderr, "PUB mismatch at %zu\n", gid);
				char cpu_b64[45], gpu_b64[45];
				base64_encode_32(pub, cpu_b64);
				base64_encode_32(gpu_pub + gid*32, gpu_b64);
				// Print the scalar used (pre-clamp printed for transparency, but we clamp before use)
				unsigned char sk[32]; philox_fill32_for_gid(seed, (uint32_t)gid, sk);
				sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
				static const char hex[] = "0123456789abcdef";
				char sk_hex[65]; for (int i=0;i<32;++i) { sk_hex[i*2] = hex[sk[i]>>4]; sk_hex[i*2+1] = hex[sk[i]&0xF]; }
				sk_hex[64] = '\0';
				fprintf(stderr, "CPU pub: %s\nGPU pub: %s\nSK(hex, clamped): %s\n", cpu_b64, gpu_b64, sk_hex);
				free(gpu_pub);
				return 3;
			}
		}
		fprintf(stderr, "PUB CPU==GPU: %d samples matched.\n", got);
		free(gpu_pub);
		return 0;
#else
		fprintf(stderr, "Built without OpenCL; PUB test unavailable.\n");
		return 2;
#endif
	} else if (g_test_fe) {
#ifdef ME_KEYGEN_OPENCL
		// Field operations self-test vs OpenSSL BN mod p
		BN_CTX *ctx = BN_CTX_new();
		BIGNUM *p = BN_new(); BN_zero(p); BN_set_bit(p, 255); BN_sub_word(p, 19);
		// First, precise mapping sanity: single-bit round-trip for bits 0..254
		for (int k = 0; k < 255; ++k) {
			unsigned char le[32] = {0};
			int byte = k >> 3, bit = k & 7;
			le[byte] = (unsigned char)(1u << bit);
			fe a; fe_frombytes(&a, le);
			unsigned char out[32]; fetobytes(out, &a);
			if (memcmp(le, out, 32) != 0) {
				char le_b64[45], out_b64[45];
				base64_encode_32(le, le_b64); base64_encode_32(out, out_b64);
				fprintf(stderr, "BIT-RT mismatch at bit %d\nIN :%s\nOUT:%s\n", k, le_b64, out_b64);
				// Extra diagnostics: hex dump and limb values
				fprintf(stderr, "IN hex :");
				for (int i=31;i>=0;--i) fprintf(stderr, "%02x", le[i]);
				fprintf(stderr, "\nOUT hex:");
				for (int i=31;i>=0;--i) fprintf(stderr, "%02x", out[i]);
				fprintf(stderr, "\nLIMBS :");
				for (int i=0;i<10;++i) fprintf(stderr, " %d", a.v[i]);
				fprintf(stderr, "\n");
				BN_free(p); BN_CTX_free(ctx);
				return 3;
			}
		}
		const int N = 500; // number of random trials per op
		for (int trial = 0; trial < N; ++trial) {
			// Sample A,B uniformly from [0,p) as BN, convert to fe via fe_frombytes
			BIGNUM *Abn = BN_new(); BN_rand_range(Abn, p);
			BIGNUM *Bbn = BN_new(); BN_rand_range(Bbn, p);
			unsigned char Abe[32], Bbe[32]; BN_bn2binpad(Abn, Abe, 32); BN_bn2binpad(Bbn, Bbe, 32);
			unsigned char Ale[32], Ble[32]; for (int i=0;i<32;++i){ Ale[i]=Abe[31-i]; Ble[i]=Bbe[31-i]; }
			fe a,b; fe_frombytes(&a, Ale); fe_frombytes(&b, Ble);
			// Verify conversion round-trip equals original BN
			BIGNUM *abn = BN_from_fe_limbs(&a);
			BIGNUM *bbn = BN_from_fe_limbs(&b);
			if (BN_cmp(abn, Abn) != 0 || BN_cmp(bbn, Bbn) != 0){
				unsigned char ar[32], br[32]; fetobytes(ar, &a); fetobytes(br, &b);
				char Ale_b64[45], Ble_b64[45], Ar_b64[45], Br_b64[45];
				base64_encode_32(Ale, Ale_b64); base64_encode_32(Ble, Ble_b64);
				base64_encode_32(ar, Ar_b64); base64_encode_32(br, Br_b64);
				unsigned char abe_be[32], bbe_be[32]; BN_bn2binpad(abn, abe_be, 32); BN_bn2binpad(bbn, bbe_be, 32);
				unsigned char Abn_be[32], Bbn_be[32]; BN_bn2binpad(Abn, Abn_be, 32); BN_bn2binpad(Bbn, Bbn_be, 32);
				char abe_b64[45], bbe_b64[45], Abn_b64_be[45], Bbn_b64_be[45];
				base64_encode_32(abe_be, abe_b64); base64_encode_32(bbe_be, bbe_b64);
				base64_encode_32(Abn_be, Abn_b64_be); base64_encode_32(Bbn_be, Bbn_b64_be);
				fprintf(stderr, "FE-CONV mismatch at trial %d\nAle:%s\nBle:%s\nfe->bytes(A):%s\nfe->bytes(B):%s\nBN_from_fe(A):%s\nBN_from_fe(B):%s\nBN_orig(A):%s\nBN_orig(B):%s\n", trial, Ale_b64, Ble_b64, Ar_b64, Br_b64, abe_b64, bbe_b64, Abn_b64_be, Bbn_b64_be);
				BN_free(abn); BN_free(bbn); BN_free(Abn); BN_free(Bbn); BN_free(p); BN_CTX_free(ctx);
				return 3;
			}
			// add
			{
				fe r; fea(&r, &a, &b);
				BIGNUM *rbn = BN_new(); BN_mod_add(rbn, abn, bbn, p, ctx);
				BIGNUM *rfe = BN_from_fe_limbs(&r);
				// Prefer modular equality check to avoid representation hiccups
				BIGNUM *delta = BN_new(); BN_mod_sub(delta, rfe, rbn, p, ctx);
				int equal_mod_p = BN_is_zero(delta);
				if (!equal_mod_p) {
					unsigned char a_b[32], b_b[32], rf_b[32], rb_b[32];
					fetobytes(a_b, &a); fetobytes(b_b, &b); fetobytes(rf_b, &r); BN_bn2binpad(rbn, rb_b, 32);
					char a_b64[45], b_b64[45], fe_b64[45], bn_b64[45]; base64_encode_32(a_b, a_b64); base64_encode_32(b_b, b_b64); base64_encode_32(rf_b, fe_b64); base64_encode_32(rb_b, bn_b64);
					fprintf(stderr, "FE-ADD mismatch at trial %d\nA:%s\nB:%s\nFE:%s\nBN:%s\n", trial, a_b64, b_b64, fe_b64, bn_b64);
					unsigned char dbe[32]; BN_bn2binpad(delta, dbe, 32);
					char d_b64[45]; base64_encode_32(dbe, d_b64);
					fprintf(stderr, "DELTA (rfe-rbn mod p): %s\n", d_b64);
					int rfe_ge_p = BN_cmp(rfe, p) >= 0;
					int rbn_ge_p = BN_cmp(rbn, p) >= 0;
					fprintf(stderr, "rfe>=p? %s, rbn>=p? %s, BN_cmp(rfe,rbn)=%d\n",
						rfe_ge_p?"yes":"no", rbn_ge_p?"yes":"no", BN_cmp(rfe, rbn));
					BN_free(delta);
					fprintf(stderr, "r limbs:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", r.v[i]); fprintf(stderr, "\n");
					BN_free(rfe); BN_free(rbn); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx);
					return 3;
				}
				BN_free(delta);
				BN_free(rfe); BN_free(rbn);
			}
			// sub
			{
				fe r; fes(&r, &a, &b);
				BIGNUM *rbn = BN_new(); BN_mod_sub(rbn, abn, bbn, p, ctx);
				BIGNUM *rfe = BN_from_fe_limbs(&r);
				BIGNUM *delta = BN_new(); BN_mod_sub(delta, rfe, rbn, p, ctx);
				int equal_mod_p = BN_is_zero(delta);
				if (!equal_mod_p) {
					unsigned char a_b[32], b_b[32], rf_b[32], rb_b[32];
					fetobytes(a_b, &a); fetobytes(b_b, &b); fetobytes(rf_b, &r); BN_bn2binpad(rbn, rb_b, 32);
					char a_b64[45], b_b64[45], fe_b64[45], bn_b64[45]; base64_encode_32(a_b, a_b64); base64_encode_32(b_b, b_b64); base64_encode_32(rf_b, fe_b64); base64_encode_32(rb_b, bn_b64);
					fprintf(stderr, "FE-SUB mismatch at trial %d\nA:%s\nB:%s\nFE:%s\nBN:%s\n", trial, a_b64, b_b64, fe_b64, bn_b64);
					unsigned char dbe[32]; BN_bn2binpad(delta, dbe, 32);
					char d_b64[45]; base64_encode_32(dbe, d_b64);
					fprintf(stderr, "DELTA (rfe-rbn mod p): %s\n", d_b64);
					int rfe_ge_p = BN_cmp(rfe, p) >= 0;
					int rbn_ge_p = BN_cmp(rbn, p) >= 0;
					fprintf(stderr, "rfe>=p? %s, rbn>=p? %s, BN_cmp(rfe,rbn)=%d\n",
						rfe_ge_p?"yes":"no", rbn_ge_p?"yes":"no", BN_cmp(rfe, rbn));
					BN_free(delta);
					fprintf(stderr, "r limbs:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", r.v[i]); fprintf(stderr, "\n");
					BN_free(rfe); BN_free(rbn); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx);
					return 3;
				}
				BN_free(delta);
				BN_free(rfe); BN_free(rbn);
			}
			// mul
			{
				fe r; fem(&r, &a, &b);
				fe rr; fem_ref(&rr, &a, &b);
				BIGNUM *rbn = BN_new(); BN_mod_mul(rbn, abn, bbn, p, ctx);
				BIGNUM *rfe = BN_from_fe_limbs(&r);
				int bad = BN_cmp(rfe, rbn) != 0;
				if (bad) {
					BIGNUM *rrbn = BN_from_fe_limbs(&rr);
					unsigned char a_b[32], b_b[32], rf_b[32], rr_b[32], rb_b[32];
					fetobytes(a_b, &a); fetobytes(b_b, &b); fetobytes(rf_b, &r); fetobytes(rr_b, &rr); BN_bn2binpad(rbn, rb_b, 32);
					char a_b64[45], b_b64[45], fe_b64[45], rr_b64[45], bn_b64[45];
					base64_encode_32(a_b, a_b64); base64_encode_32(b_b, b_b64); base64_encode_32(rf_b, fe_b64); base64_encode_32(rr_b, rr_b64); base64_encode_32(rb_b, bn_b64);
					fprintf(stderr, "FE-MUL mismatch at trial %d\nA:%s\nB:%s\nFE:%s\nREF:%s (BN-eq:%s)\nBN:%s\n", trial, a_b64, b_b64, fe_b64, rr_b64, BN_cmp(rrbn, rbn)==0?"yes":"no", bn_b64);
					fprintf(stderr, "r limbs :"); for(int i=0;i<10;++i) fprintf(stderr, " %d", r.v[i]); fprintf(stderr, "\n");
					fprintf(stderr, "rr limbs:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", rr.v[i]); fprintf(stderr, "\n");
					BN_free(rrbn); BN_free(rfe); BN_free(rbn); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx); return 3;
				}
				if (bad) {
					unsigned char a_b[32], b_b[32], rf_b[32], rb_b[32];
					fetobytes(a_b, &a); fetobytes(b_b, &b); fetobytes(rf_b, &r); BN_bn2binpad(rbn, rb_b, 32);
					char a_b64[45], b_b64[45], fe_b64[45], bn_b64[45]; base64_encode_32(a_b, a_b64); base64_encode_32(b_b, b_b64); base64_encode_32(rf_b, fe_b64); base64_encode_32(rb_b, bn_b64);
					fprintf(stderr, "FE-MUL mismatch at trial %d\nA:%s\nB:%s\nFE:%s\nBN:%s\n", trial, a_b64, b_b64, fe_b64, bn_b64);
					BN_free(rfe); BN_free(rbn); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx);
					return 3;
				}
				BN_free(rfe); BN_free(rbn);
			}
			// sq
			{
				fe r; fesq(&r, &a);
				// Reference square via BN-backed multiply (fem_ref with a,a)
				fe rr; fem_ref(&rr, &a, &a);
				BIGNUM *rbn = BN_new(); BN_mod_sqr(rbn, abn, p, ctx);
				BIGNUM *rfe = BN_from_fe_limbs(&r);
				BIGNUM *delta = BN_new(); BN_mod_sub(delta, rfe, rbn, p, ctx);
				int equal_mod_p = BN_is_zero(delta);
				if (!equal_mod_p) {
					unsigned char a_b[32], rf_b[32], rr_b[32], rb_b[32];
					fetobytes(a_b, &a); fetobytes(rf_b, &r); fetobytes(rr_b, &rr); BN_bn2binpad(rbn, rb_b, 32);
					char a_b64[45], fe_b64[45], ref_b64[45], bn_b64[45];
					base64_encode_32(a_b, a_b64);
					base64_encode_32(rf_b, fe_b64);
					base64_encode_32(rr_b, ref_b64);
					base64_encode_32(rb_b, bn_b64);
					// Also compare REF to BN for sanity
					BIGNUM *rrbn = BN_from_fe_limbs(&rr);
					fprintf(stderr, "FE-SQ mismatch at trial %d\nA:%s\nFE:%s\nREF:%s (BN-eq:%s)\nBN:%s\n",
						trial, a_b64, fe_b64, ref_b64, BN_cmp(rrbn, rbn)==0?"yes":"no", bn_b64);
					unsigned char dbe[32]; BN_bn2binpad(delta, dbe, 32);
					char d_b64[45]; base64_encode_32(dbe, d_b64);
					fprintf(stderr, "DELTA (rfe-rbn mod p): %s\n", d_b64);
					int rfe_ge_p = BN_cmp(rfe, p) >= 0;
					int rbn_ge_p = BN_cmp(rbn, p) >= 0;
					fprintf(stderr, "rfe>=p? %s, rbn>=p? %s, BN_cmp(rfe,rbn)=%d\n",
						rfe_ge_p?"yes":"no", rbn_ge_p?"yes":"no", BN_cmp(rfe, rbn));
					fprintf(stderr, "r limbs :"); for(int i=0;i<10;++i) fprintf(stderr, " %d", r.v[i]); fprintf(stderr, "\n");
					fprintf(stderr, "rr limbs:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", rr.v[i]); fprintf(stderr, "\n");
					BN_free(rrbn);
					BN_free(delta);
					BN_free(rfe); BN_free(rbn); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx);
					return 3;
				}
				BN_free(delta);
				BN_free(rfe); BN_free(rbn);
			}
			// invert (skip zero elements)
			{
				fe nz = a; // reuse 'a' which is uniform in [0,p)
				// If zero, tweak to 1
				int is_zero = 1; for (int i=0;i<10;++i) if (nz.v[i]!=0) { is_zero=0; break; }
				if (is_zero) nz.v[0] = 1;
				fe inv; feinvert(&inv, &nz);
				fe one; fem(&one, &nz, &inv); // one = nz * inv
				// Compare numerically via BN
				BIGNUM *one_bn = BN_from_fe_limbs(&one);
				BIGNUM *nzb = BN_from_fe_limbs(&nz);
				BIGNUM *invb = BN_mod_inverse(NULL, nzb, p, ctx);
				BIGNUM *prod = BN_new(); BN_mod_mul(prod, nzb, invb, p, ctx);
				int ok_inv = BN_is_one(one_bn) && BN_is_one(prod);
				if (!ok_inv) {
					unsigned char ofe[32], obn[32]; fetobytes(ofe, &one); BN_bn2binpad(prod, obn, 32);
					char ofe_b64[45], obn_b64[45]; base64_encode_32(ofe, ofe_b64); base64_encode_32(obn, obn_b64);
					fprintf(stderr, "FE-INV mismatch at trial %d\nFE:%s\nBN:%s\n", trial, ofe_b64, obn_b64);
					BN_free(one_bn); BN_free(prod); BN_free(invb); BN_free(nzb); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx); return 3;
				}
				BN_free(one_bn); BN_free(prod); BN_free(invb); BN_free(nzb);
			}
			// inv (ensure non-zero)
			{
				fe z, zi; fec(&z, &a); // reuse 'a' as random element
				// ensure z != 0 by forcing at least one limb non-zero
				int nz = 0; for (int i=0;i<10;++i) if (z.v[i] != 0) { nz = 1; break; }
				if (!nz) z.v[0] = 1;
				feinvert(&zi, &z);
				// Compare with BN inverse
				BIGNUM *zbn = BN_from_fe_limbs(&z);
				BIGNUM *invbn = BN_mod_inverse(NULL, zbn, p, ctx);
				if (!invbn) { BN_free(zbn); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx); fprintf(stderr, "BN_mod_inverse failed in FE test\n"); return 3; }
				BIGNUM *zife = BN_from_fe_limbs(&zi);
				if (BN_cmp(zife, invbn) != 0) {
					unsigned char z_b[32], zi_b[32], inv_b[32];
					fetobytes(z_b, &z); fetobytes(zi_b, &zi); BN_bn2binpad(invbn, inv_b, 32);
					char z_b64[45], zi_b64[45], inv_b64[45];
					base64_encode_32(z_b, z_b64); base64_encode_32(zi_b, zi_b64); base64_encode_32(inv_b, inv_b64);
					fprintf(stderr, "FE-INV mismatch at trial %d\nZ:%s\nFE:%s\nBN:%s\n", trial, z_b64, zi_b64, inv_b64);
					BN_free(zbn); BN_free(invbn); BN_free(zife); BN_free(abn); BN_free(bbn); BN_free(p); BN_CTX_free(ctx);
					return 3;
				}
				BN_free(zbn); BN_free(invbn); BN_free(zife);
			}
			BN_free(abn); BN_free(bbn); BN_free(Abn); BN_free(Bbn);
		}
		BN_free(p); BN_CTX_free(ctx);
		fprintf(stderr, "FE tests passed (%d trials).\n", N);
		return 0;
#else
		fprintf(stderr, "Built without OpenCL; FE test unavailable.\n");
		return 2;
#endif
	} else if (g_test_trace) {
#ifdef ME_KEYGEN_OPENCL
		// RFC Alice scalar; produce CPU ref10 ladder trace and GPU trace for comparison
		const char *alice_sk_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
		unsigned char sk[32];
		for (int i=0;i<32;++i){char hi=alice_sk_hex[i*2],lo=alice_sk_hex[i*2+1];int vh=(hi>='0'&&hi<='9')?(hi-'0'):(hi>='a'&&hi<='f')?(hi-'a'+10):(hi>='A'&&hi<='F')?(hi-'A'+10):-1;int vl=(lo>='0'&&lo<='9')?(lo-'0'):(lo>='a'&&lo<='f')?(lo-'a'+10):(lo>='A'&&lo<='F')?(lo-'A'+10):-1; if(vh<0||vl<0){fprintf(stderr,"Invalid hex in Alice sk\n");return 2;} sk[i]=(unsigned char)((vh<<4)|vl);} 
		// Clamp to match kernel behavior
		sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
		// Run ladder and collect first K iterations
		const unsigned K=255; int cpu[40*K];
		fe x1; fe0(&x1); x1.v[0]=9;
		fe x2,z2,x3,z3,a,aa,b,bb,e,c,d,da,cb,tmp; fe1(&x2); fe0(&z2); fec(&x3,&x1); fe1(&z3);
		int swap=0; unsigned step=0;
		for (int pos=254; pos>=0 && step<K; --pos,++step){ int bit=(sk[pos>>3]>>(pos&7))&1; swap^=bit; fex(&x2,&x3,swap); fex(&z2,&z3,swap); swap=bit; fea(&a,&x2,&z2); fesq(&aa,&a); fes(&b,&x2,&z2); fesq(&bb,&b); fes(&e,&aa,&bb); fea(&c,&x3,&z3); fes(&d,&x3,&z3); fem(&da,&d,&a); fem(&cb,&c,&b); fea(&tmp,&da,&cb); fesq(&x3,&tmp); fes(&tmp,&da,&cb); fesq(&tmp,&tmp); fem(&z3,&tmp,&x1); fem(&x2,&aa,&bb); fea24(&tmp,&e); fea(&tmp,&aa,&tmp); fem(&z2,&e,&tmp); int base=step*40; for(int i=0;i<10;++i) cpu[base+i]=x2.v[i]; for(int i=0;i<10;++i) cpu[base+10+i]=z2.v[i]; for(int i=0;i<10;++i) cpu[base+20+i]=x3.v[i]; for(int i=0;i<10;++i) cpu[base+30+i]=z3.v[i]; }
		int gpu[40*K]; int got = ocl_trace_ladder("opencl_keygen.cl", sk, K, gpu); if (got < 0) { fprintf(stderr, "ocl_trace_ladder failed (%d)\n", got); return 3; }
		// Compare and print first mismatch
		for (unsigned st=0; st<K; ++st){ int base=st*40; int mismatch=-1; for(int i=0;i<40;++i){ if(cpu[base+i]!=gpu[base+i]){ mismatch=i; break; }} if(mismatch>=0){ const char* which = (mismatch<10)?"X2":(mismatch<20)?"Z2":(mismatch<30)?"X3":"Z3"; int idx = mismatch%10; fprintf(stderr, "DIVERGE at step %u: %s limb %d: CPU=%d GPU=%d\n", st, which, idx, cpu[base+mismatch], gpu[base+mismatch]); // dump the whole step
			fprintf(stderr, "CPU X2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cpu[base+i]); fprintf(stderr, "\nCPU Z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cpu[base+10+i]); fprintf(stderr, "\nCPU X3:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cpu[base+20+i]); fprintf(stderr, "\nCPU Z3:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", cpu[base+30+i]);
			fprintf(stderr, "\nGPU X2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", gpu[base+i]); fprintf(stderr, "\nGPU Z2:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", gpu[base+10+i]); fprintf(stderr, "\nGPU X3:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", gpu[base+20+i]); fprintf(stderr, "\nGPU Z3:"); for(int i=0;i<10;++i) fprintf(stderr, " %d", gpu[base+30+i]); fprintf(stderr, "\n");
			return 5; }
		}
		fprintf(stderr, "TRACE: first %u steps match CPU vs GPU.\n", K);
		return 0;
#else
		fprintf(stderr, "Built without OpenCL; TRACE test unavailable.\n");
		return 2;
#endif
	} else if (g_test_rfc) {
#ifdef ME_KEYGEN_OPENCL
		// RFC 7748 §6.1 basepoint public keys for Alice/Bob
		// Alice private key (hex), expected pub key (hex)
		const char *alice_sk_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
		const char *alice_pk_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
		const char *bob_sk_hex   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
		const char *bob_pk_hex   = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
		unsigned char a_sk[32], b_sk[32], a_pk_exp[32], b_pk_exp[32];
		for (int i=0;i<32;++i) {
			char hi = alice_sk_hex[i*2], lo = alice_sk_hex[i*2+1];
			int vh = (hi>='0'&&hi<='9')?(hi-'0'):(hi>='a'&&hi<='f')?(hi-'a'+10):(hi>='A'&&hi<='F')?(hi-'A'+10):-1;
			int vl = (lo>='0'&&lo<='9')?(lo-'0'):(lo>='a'&&lo<='f')?(lo-'a'+10):(lo>='A'&&lo<='F')?(lo-'A'+10):-1;
			if (vh<0||vl<0){fprintf(stderr,"Invalid hex in Alice sk\n"); return 2;} a_sk[i]=(unsigned char)((vh<<4)|vl);
			hi = alice_pk_hex[i*2]; lo = alice_pk_hex[i*2+1];
			vh = (hi>='0'&&hi<='9')?(hi-'0'):(hi>='a'&&hi<='f')?(hi-'a'+10):(hi>='A'&&hi<='F')?(hi-'A'+10):-1;
			vl = (lo>='0'&&lo<='9')?(lo-'0'):(lo>='a'&&lo<='f')?(lo-'a'+10):(lo>='A'&&lo<='F')?(lo-'A'+10):-1;
			if (vh<0||vl<0){fprintf(stderr,"Invalid hex in Alice pk\n"); return 2;} a_pk_exp[i]=(unsigned char)((vh<<4)|vl);
			hi = bob_sk_hex[i*2]; lo = bob_sk_hex[i*2+1];
			vh = (hi>='0'&&hi<='9')?(hi-'0'):(hi>='a'&&hi<='f')?(hi-'a'+10):(hi>='A'&&hi<='F')?(hi-'A'+10):-1;
			vl = (lo>='0'&&lo<='9')?(lo-'0'):(lo>='a'&&lo<='f')?(lo-'a'+10):(lo>='A'&&lo<='F')?(lo-'A'+10):-1;
			if (vh<0||vl<0){fprintf(stderr,"Invalid hex in Bob sk\n"); return 2;} b_sk[i]=(unsigned char)((vh<<4)|vl);
			hi = bob_pk_hex[i*2]; lo = bob_pk_hex[i*2+1];
			vh = (hi>='0'&&hi<='9')?(hi-'0'):(hi>='a'&&hi<='f')?(hi-'a'+10):(hi>='A'&&hi<='F')?(hi-'A'+10):-1;
			vl = (lo>='0'&&lo<='9')?(lo-'0'):(lo>='a'&&lo<='f')?(lo-'a'+10):(lo>='A'&&lo<='F')?(lo-'A'+10):-1;
			if (vh<0||vl<0){fprintf(stderr,"Invalid hex in Bob pk\n"); return 2;} b_pk_exp[i]=(unsigned char)((vh<<4)|vl);
		}
		// Compute GPU pubs (kernel clamps internally). Also compute CPU(OpenSSL) and CPU-mirror pubs.
		unsigned char gpu_out[64];
		int got = ocl_pub_from_secrets("opencl_keygen.cl", a_sk, 1, gpu_out);
		if (got != 1) { fprintf(stderr, "GPU pub from Alice sk failed (%d)\n", got); return 3; }
		int ok_a = (memcmp(gpu_out, a_pk_exp, 32) == 0);
		got = ocl_pub_from_secrets("opencl_keygen.cl", b_sk, 1, gpu_out+32);
		if (got != 1) { fprintf(stderr, "GPU pub from Bob sk failed (%d)\n", got); return 3; }
		int ok_b = (memcmp(gpu_out+32, b_pk_exp, 32) == 0);

    		// Also compute with OpenSSL CPU and compare
		unsigned char cpu_mir_a[32], cpu_mir_b[32]; size_t lenA=32, lenB=32;
		EVP_PKEY *ak = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, a_sk, 32);
		EVP_PKEY *bk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, b_sk, 32);
		if (!ak || !bk) { if (ak) EVP_PKEY_free(ak); if (bk) EVP_PKEY_free(bk); fprintf(stderr, "OpenSSL key create failed\n"); return 3; }
		if (EVP_PKEY_get_raw_public_key(ak, cpu_mir_a, &lenA) <= 0 || lenA != 32) { EVP_PKEY_free(ak); EVP_PKEY_free(bk); fprintf(stderr, "OpenSSL Alice pub fail\n"); return 3; }
		if (EVP_PKEY_get_raw_public_key(bk, cpu_mir_b, &lenB) <= 0 || lenB != 32) { EVP_PKEY_free(ak); EVP_PKEY_free(bk); fprintf(stderr, "OpenSSL Bob pub fail\n"); return 3; }
		EVP_PKEY_free(ak); EVP_PKEY_free(bk);
		char a_gpu_b64[45], a_exp_b64[45], b_gpu_b64[45], b_exp_b64[45];
		base64_encode_32(gpu_out, a_gpu_b64);
		base64_encode_32(a_pk_exp, a_exp_b64);
		base64_encode_32(gpu_out+32, b_gpu_b64);
		base64_encode_32(b_pk_exp, b_exp_b64);
		// Also compute with our CPU mirror ladder (clamp like kernel) and compare
	unsigned char cpu_mirror_a2[32], cpu_mirror_b2[32];
		unsigned char a_sk_cl[32], b_sk_cl[32]; memcpy(a_sk_cl,a_sk,32); memcpy(b_sk_cl,b_sk,32);
		a_sk_cl[0] &= 248; a_sk_cl[31] &= 127; a_sk_cl[31] |= 64;
		b_sk_cl[0] &= 248; b_sk_cl[31] &= 127; b_sk_cl[31] |= 64;
		x25519_basepoint_mul_cpu(a_sk_cl, cpu_mirror_a2);
		x25519_basepoint_mul_cpu(b_sk_cl, cpu_mirror_b2);
	// Also with refmul variant
	unsigned char cpu_refmul_a2[32], cpu_refmul_b2[32];
	x25519_basepoint_mul_cpu_refmul(a_sk_cl, cpu_refmul_a2);
	x25519_basepoint_mul_cpu_refmul(b_sk_cl, cpu_refmul_b2);
	// BN reference too
	unsigned char bn_ref_a[32], bn_ref_b[32];
	x25519_basepoint_mul_bn(a_sk, bn_ref_a);
	x25519_basepoint_mul_bn(b_sk, bn_ref_b);
	char a_cpu_b64[45], b_cpu_b64[45], a_mir_b64[45], b_mir_b64[45], a_bn_b64[45], b_bn_b64[45], a_refmul_b64[45], b_refmul_b64[45];
		base64_encode_32(cpu_mir_a, a_cpu_b64);
		base64_encode_32(cpu_mir_b, b_cpu_b64);
		base64_encode_32(cpu_mirror_a2, a_mir_b64);
		base64_encode_32(cpu_mirror_b2, b_mir_b64);
	base64_encode_32(bn_ref_a, a_bn_b64);
	base64_encode_32(bn_ref_b, b_bn_b64);
	base64_encode_32(cpu_refmul_a2, a_refmul_b64);
	base64_encode_32(cpu_refmul_b2, b_refmul_b64);
	fprintf(stderr, "RFC Alice GPU pub: %s\nRFC Alice CPU pub: %s\nRFC Alice MIR pub: %s\nRFC Alice REF pub: %s\nRFC Alice BN  pub: %s\nRFC Alice EXP pub: %s\n", a_gpu_b64, a_cpu_b64, a_mir_b64, a_refmul_b64, a_bn_b64, a_exp_b64);
	fprintf(stderr, "RFC Bob   GPU pub: %s\nRFC Bob   CPU pub: %s\nRFC Bob   MIR pub: %s\nRFC Bob   REF pub: %s\nRFC Bob   BN  pub: %s\nRFC Bob   EXP pub: %s\n", b_gpu_b64, b_cpu_b64, b_mir_b64, b_refmul_b64, b_bn_b64, b_exp_b64);

		// BN cross-check: compute x = X2/Z2 mod p using OpenSSL BN from our ladder X2/Z2 and compare to OpenSSL pub
		// Alice
		fe ax2, az2; unsigned char a_sk_cl2[32]; memcpy(a_sk_cl2,a_sk,32); a_sk_cl2[0]&=248; a_sk_cl2[31]&=127; a_sk_cl2[31]|=64;
		ladder_get_x2z2(a_sk_cl2, &ax2, &az2);
		BIGNUM *ax = BN_from_fe_limbs(&ax2); BIGNUM *az = BN_from_fe_limbs(&az2);
		BN_CTX *ctx = BN_CTX_new(); BIGNUM *p = BN_new(); BN_zero(p); // p = 2^255-19
		BN_set_bit(p, 255); BN_sub_word(p, 19);
		BIGNUM *inv = BN_mod_inverse(NULL, az, p, ctx);
		BIGNUM *axz = BN_new(); BN_mod_mul(axz, ax, inv, p, ctx);
		unsigned char axz_b[32]; memset(axz_b,0,32); BN_bn2binpad(axz, axz_b, 32);
		char a_bnx_b64[45]; base64_encode_32(axz_b, a_bnx_b64);
	fprintf(stderr, "RFC Alice BN  pub: %s\n", a_bnx_b64);
		BN_free(ax); BN_free(az); BN_free(inv); BN_free(axz);
		// Bob
		fe bx2, bz2; unsigned char b_sk_cl2[32]; memcpy(b_sk_cl2,b_sk,32); b_sk_cl2[0]&=248; b_sk_cl2[31]&=127; b_sk_cl2[31]|=64;
		ladder_get_x2z2(b_sk_cl2, &bx2, &bz2);
		BIGNUM *bx = BN_from_fe_limbs(&bx2); BIGNUM *bz = BN_from_fe_limbs(&bz2);
		BIGNUM *invb = BN_mod_inverse(NULL, bz, p, ctx);
		BIGNUM *bxz = BN_new(); BN_mod_mul(bxz, bx, invb, p, ctx);
		unsigned char bxz_b[32]; memset(bxz_b,0,32); BN_bn2binpad(bxz, bxz_b, 32);
		char b_bnx_b64[45]; base64_encode_32(bxz_b, b_bnx_b64);
	fprintf(stderr, "RFC Bob   BN  pub: %s\n", b_bnx_b64);
		BN_free(bx); BN_free(bz); BN_free(invb); BN_free(bxz);
		BN_free(p); BN_CTX_free(ctx);
		int ok_ca = (memcmp(cpu_mir_a, a_pk_exp, 32) == 0);
		int ok_cb = (memcmp(cpu_mir_b, b_pk_exp, 32) == 0);
		if (!ok_ca || !ok_cb) {
			fprintf(stderr, "CPU mirror does not match RFC vectors (Alice:%s Bob:%s)\n", ok_ca?"OK":"BAD", ok_cb?"OK":"BAD");
			return 6;
		}
		if (!ok_a || !ok_b) return 5;
		fprintf(stderr, "RFC basepoint public key test passed.\n");
		return 0;
#else
		fprintf(stderr, "Built without OpenCL; RFC test unavailable.\n");
		return 2;
#endif
	} else if (bench_ms > 0 && !g_use_gpu) {
		// CPU-only benchmark mode: run N threads for bench_ms and report keys/s
		threads = (pthread_t *)malloc(sizeof(pthread_t) * (size_t)g_num_threads);
		if (!threads) { fprintf(stderr, "Failed to allocate thread handles\n"); return 1; }
		OPENSSL_init_crypto(0, NULL);
		if (!g_quiet) fprintf(stderr, "Benchmark: running %u ms on %d threads...\n", bench_ms, g_num_threads);
		for (int i = 0; i < g_num_threads; i++) { pthread_create(&threads[i], NULL, generate_keys, (void*)(intptr_t)i); }
		// Sleep for duration then stop
		struct timespec ts; ts.tv_sec = bench_ms / 1000U; ts.tv_nsec = (long)(bench_ms % 1000U) * 1000000L; nanosleep(&ts, NULL);
		atomic_store_explicit(&g_stop, 1, memory_order_relaxed);
		for (int i = 0; i < g_num_threads; i++) { pthread_join(threads[i], NULL); }
		free(threads);
		unsigned long long total = atomic_load_explicit(&g_key_count, memory_order_relaxed);
		double secs = (double)bench_ms / 1000.0;
		double rate = secs > 0.0 ? (double)total / secs : 0.0;
		char total_str[32], rate_str[32];
		human_readable_ull(total, total_str, sizeof total_str);
		human_readable_ull((unsigned long long)rate, rate_str, sizeof rate_str);
		fprintf(stderr, "Benchmark done. Elapsed: %.3fs | total keys: %s | rate: %s/s\n", secs, total_str, rate_str);
		return 0;
	} else if (!g_use_gpu) {
		// fall through to normal CPU keygen
		threads = (pthread_t *)malloc(sizeof(pthread_t) * (size_t)g_num_threads);
		if (!threads) {
			fprintf(stderr, "Failed to allocate thread handles\n");
			return 1;
		}
		// Initialize OpenSSL PRNG (modern OpenSSL auto-inits). Keep for compatibility.
		OPENSSL_init_crypto(0, NULL);
		fprintf(stderr, "Starting key generation with %d threads...\n", g_num_threads);
		if (!g_quiet) { pthread_create(&rpt, NULL, reporter, NULL); }
		for (int i = 0; i < g_num_threads; i++) { pthread_create(&threads[i], NULL, generate_keys, (void*)(intptr_t)i); }
		for (int i = 0; i < g_num_threads; i++) { pthread_join(threads[i], NULL); }
		if (!g_quiet) { pthread_join(rpt, NULL); }
		free(threads);
	} else {
#ifndef ME_KEYGEN_OPENCL
		fprintf(stderr, "This binary was built without OpenCL support. Rebuild with OPENCL=1.\n");
		return 2;
#else
		// GPU path: prepare inputs and run batches until target met
		if (!ocl_is_available()) {
			fprintf(stderr, "OpenCL runtime not available.\n");
			return 2;
		}
		// Build patterns for GPU
		struct ocl_pattern *pats = (struct ocl_pattern*)calloc(g_patterns_count, sizeof(*pats));
		if (!pats) { fprintf(stderr, "Out of memory\n"); return 1; }
		for (size_t i = 0; i < g_patterns_count; ++i) {
			pats[i].prefix = (unsigned char*)g_patterns[i].prefix;
			pats[i].prefix_len = g_patterns[i].prefix_len;
			pats[i].suffix = (unsigned char*)g_patterns[i].suffix;
			pats[i].suffix_len = g_patterns[i].suffix_len;
			pats[i].suffix_off = (unsigned int)g_patterns[i].suffix_off;
		}
		// Try to locate the kernel file relative to current directory
		const char *kernel_path = "opencl_keygen.cl";
	unsigned long long seed = (unsigned long long)time(NULL);
		// Safer defaults to avoid long-running kernels that can freeze desktop GPUs
		const char *ev_g = getenv("MEKG_OCL_GSIZE");
		const char *ev_l = getenv("MEKG_OCL_LSIZE");
		const char *ev_i = getenv("MEKG_OCL_ITERS");
	// Defaults tuned from observed stability/throughput: 16384/128/64
	size_t def_gsize = 16384;
	size_t def_lsize = 128;
	unsigned int def_iters = 64;
		// Precedence: CLI > env > defaults
		size_t user_gsize = cli_gsize ? cli_gsize : (ev_g ? (size_t)strtoull(ev_g, NULL, 10) : def_gsize);
		size_t user_lsize = cli_lsize ? cli_lsize : (ev_l ? (size_t)strtoull(ev_l, NULL, 10) : def_lsize);
		unsigned int user_iters = cli_iters ? cli_iters : (ev_i ? (unsigned int)strtoul(ev_i, NULL, 10) : def_iters);
		// Optional autotune: MEKG_OCL_AUTOTUNE=1 enables probing for safe fast params under a time budget (ms)
		const char *ev_aut = getenv("MEKG_OCL_AUTOTUNE");
		const char *ev_aut_ms = getenv("MEKG_OCL_AUTOTUNE_MS");
		int do_autotune = (cli_autotune == 1) || (ev_aut && (*ev_aut=='1' || *ev_aut=='y' || *ev_aut=='Y' || *ev_aut=='t' || *ev_aut=='T'));
		if (do_autotune) {
			unsigned int budget_ms = cli_budget_ms ? cli_budget_ms : (ev_aut_ms ? (unsigned int)strtoul(ev_aut_ms, NULL, 10) : 30U);
			size_t tg=user_gsize, tl=user_lsize; unsigned int ti=user_iters;
			int arc = ocl_autotune_params(kernel_path, &tg, &tl, &ti, seed, budget_ms);
			if (arc == 0) {
				// Accept tuned params (and keep hard cap on iters)
				user_gsize = tg; user_lsize = tl; user_iters = ti;
				if (user_iters > 512u) user_iters = 512u;
				fprintf(stderr, "OpenCL autotune: selected global=%zu local=%zu iters=%u (budget=%ums)\n", user_gsize, user_lsize, user_iters, budget_ms);
			} else {
				fprintf(stderr, "OpenCL autotune failed, using defaults or env overrides.\n");
			}
		}
		if (user_gsize == 0) user_gsize = def_gsize;
		if (user_lsize == 0) user_lsize = def_lsize;
		if (user_iters == 0) user_iters = def_iters;
		// Gentle caps
		if (user_iters > 512u) user_iters = 512u;
		// Determine per-dispatch cap (keys = global*iters)
		const char *ev_maxk = getenv("MEKG_OCL_MAX_KEYS");
		unsigned long long max_keys = cli_max_keys ? cli_max_keys : (ev_maxk ? strtoull(ev_maxk, NULL, 10) : 1048576ULL);
		if (max_keys == 0ULL) max_keys = 1048576ULL;
		fprintf(stderr, "OpenCL batch params: global=%zu local=%zu iters=%u (set MEKG_OCL_GSIZE/LSIZE/ITERS to override)\n",
			user_gsize, user_lsize, user_iters);
		fprintf(stderr, "OpenCL dispatch cap: max_keys=%llu (override with --gpu-max-keys or MEKG_OCL_MAX_KEYS)\n", (unsigned long long)max_keys);
	// Start periodic reporter like CPU path
	int gpu_reporter_started = 0;
	if (!g_quiet) { pthread_create(&rpt, NULL, reporter, NULL); gpu_reporter_started = 1; }

	unsigned long long total_found = 0;
		while (!atomic_load_explicit(&g_stop, memory_order_relaxed) && total_found < g_found_target) {
			struct ocl_inputs in = {
				.kernel_path = kernel_path,
				.patterns = pats,
				.patterns_count = g_patterns_count,
				.target_count = (unsigned int)(g_found_target - total_found),
				.global_size = user_gsize, .local_size = user_lsize, .iters_per_wi = user_iters,
				.seed = seed
			};
			// Host-level chunking: split large global into safe sub-dispatches respecting max_keys
			size_t left = user_gsize;
			// Account for OpenCL padding to local size: at minimum, kernel runs 'local_size' work-items.
			// Ensure (local_size * iters) <= max_keys to truly respect the cap.
			unsigned long long max_iters_by_cap = (user_lsize > 0) ? (max_keys / (unsigned long long)user_lsize) : max_keys;
			if (max_iters_by_cap == 0ULL) max_iters_by_cap = 1ULL; // always allow at least 1 iteration
			unsigned int effective_iters = user_iters;
			if ((unsigned long long)effective_iters > max_iters_by_cap) {
				unsigned long long new_iters = max_iters_by_cap;
				if (new_iters > 512ULL) new_iters = 512ULL;
				effective_iters = (unsigned int)(new_iters > 0ULL ? new_iters : 1ULL);
				fprintf(stderr, "Note: reducing iters to %u so (local*iters) <= max_keys\n", effective_iters);
			}
			// Double-buffered pipeline: keep up to two in-flight chunks (async compute + copy)
			struct ocl_async *inflight[2] = { NULL, NULL };
			size_t inflight_idx = 0;
			while (left > 0 && !atomic_load_explicit(&g_stop, memory_order_relaxed)) {
				unsigned long long max_wi_by_keys = max_keys / (unsigned long long)effective_iters;
				if (max_wi_by_keys == 0ULL) max_wi_by_keys = (unsigned long long)user_lsize; // due to padding, we'll run at least local size
				size_t lim_by_keys = (size_t)((max_wi_by_keys / (unsigned long long)user_lsize) * (unsigned long long)user_lsize);
				if (lim_by_keys == 0) lim_by_keys = user_lsize;
				size_t chunk = left < lim_by_keys ? left : lim_by_keys;
				if (chunk < user_lsize) chunk = user_lsize;
				chunk = (chunk / user_lsize) * user_lsize;
				if (chunk == 0) chunk = user_lsize;

				// Launch next chunk asynchronously
				struct ocl_async *h = NULL;
				int arc = ocl_run_chunk_async(&in, chunk, effective_iters, seed, &h);
				if (arc != 0) {
					fprintf(stderr, "GPU async chunk failed.\n");
					if (gpu_reporter_started) { atomic_store_explicit(&g_stop, 1, memory_order_relaxed); pthread_join(rpt, NULL); }
					free(pats);
					return 3;
				}
				// Account keys for this launched chunk
				unsigned long long keys_this_chunk = (unsigned long long)chunk * (unsigned long long)effective_iters;
				atomic_fetch_add_explicit(&g_key_count, keys_this_chunk, memory_order_relaxed);

				// If we already have a previous inflight, collect it now to overlap compute of 'h' with readback of previous
				struct ocl_async *prev = inflight[inflight_idx];
				inflight[inflight_idx] = h;
				inflight_idx ^= 1; // toggle slot

				if (prev) {
					struct ocl_outputs pout = {0};
					if (ocl_async_collect(prev, &pout) != 0) {
						fprintf(stderr, "GPU async collect failed.\n");
						ocl_async_release(prev);
						if (gpu_reporter_started) { atomic_store_explicit(&g_stop, 1, memory_order_relaxed); pthread_join(rpt, NULL); }
						free(pats);
						return 3;
					}
					for (unsigned int i = 0; i < pout.found; ++i) {
						printf("FOUND: pub=%s priv=%s\n", pout.matches[i].pub_b64, pout.matches[i].priv_b64);
						fprintf(stderr, "FOUND: pub=%s priv=%s\n", pout.matches[i].pub_b64, pout.matches[i].priv_b64);
					}
					if (pout.found > 0) {
						atomic_fetch_add_explicit(&g_found_count, pout.found, memory_order_relaxed);
						total_found += pout.found;
					}
					free(pout.matches);
					ocl_async_release(prev);
				}

				// Advance
				size_t dec = (left < chunk) ? left : chunk; left -= dec;
				seed += 0x9E3779B97F4A7C15ULL;
			}
			// Collect any remaining inflight chunks
			for (int k = 0; k < 2; ++k) {
				if (inflight[k]) {
					struct ocl_outputs pout = {0};
					if (ocl_async_collect(inflight[k], &pout) != 0) {
						fprintf(stderr, "GPU async collect failed.\n");
						ocl_async_release(inflight[k]); inflight[k] = NULL;
						if (gpu_reporter_started) { atomic_store_explicit(&g_stop, 1, memory_order_relaxed); pthread_join(rpt, NULL); }
						free(pats);
						return 3;
					}
					for (unsigned int i = 0; i < pout.found; ++i) {
						printf("FOUND: pub=%s priv=%s\n", pout.matches[i].pub_b64, pout.matches[i].priv_b64);
						fprintf(stderr, "FOUND: pub=%s priv=%s\n", pout.matches[i].pub_b64, pout.matches[i].priv_b64);
					}
					if (pout.found > 0) {
						atomic_fetch_add_explicit(&g_found_count, pout.found, memory_order_relaxed);
						total_found += pout.found;
					}
					free(pout.matches);
					ocl_async_release(inflight[k]); inflight[k] = NULL;
				}
			}
		}
	atomic_store_explicit(&g_stop, 1, memory_order_relaxed);
	if (gpu_reporter_started) { pthread_join(rpt, NULL); }
		free(pats);
#endif
	}
	// Free search strings (unreachable in normal run)
	if (g_patterns) {
		for (size_t i = 0; i < g_patterns_count; ++i) {
			free(g_patterns[i].prefix);
			free(g_patterns[i].suffix);
		}
		free(g_patterns);
	}
    
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
