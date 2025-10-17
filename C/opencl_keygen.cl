// OpenCL kernel skeleton for Meshtastic keygen (X25519 ladder TBD)
// This is a placeholder; it currently performs no real X25519.
// We'll fill in field arithmetic and ladder in subsequent iterations.

__constant char B64_TABLE[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
    uint prefix_len;
    uint suffix_len;
    uint suffix_off; // 44 - suffix_len
} pattern_meta_t;

// --- Philox4x32-10 RNG (counter-based), adapted for OpenCL ---
inline uint mulhi32(uint a, uint b) {
    ulong w = (ulong)a * (ulong)b;
    return (uint)(w >> 32);
}

inline void philox4x32_round(uint4 *ctr, uint2 *key) {
    const uint MUL0 = 0xD2511F53U;
    const uint MUL1 = 0xCD9E8D57U;
    uint hi0 = mulhi32((*ctr).x, MUL0);
    uint lo0 = (*ctr).x * MUL0;
    uint hi1 = mulhi32((*ctr).z, MUL1);
    uint lo1 = (*ctr).z * MUL1;

    uint n0 = hi1 ^ (*ctr).y ^ (*key).x;
    uint n1 = lo1;
    uint n2 = hi0 ^ (*ctr).w ^ (*key).y;
    uint n3 = lo0;
    (*ctr) = (uint4)(n0, n1, n2, n3);
    const uint W0 = 0x9E3779B9U;
    const uint W1 = 0xBB67AE85U;
    (*key).x += W0; (*key).y += W1;
}

inline uint4 philox4x32_10(uint4 ctr, uint2 key) {
    #pragma unroll
    for (int i = 0; i < 10; ++i) { philox4x32_round(&ctr, &key); }
    return ctr;
}

inline void philox_fill_32bytes(ulong seed64, uint gid, __private uchar out32[32]) {
    uint2 key = (uint2)((uint)(seed64 & 0xFFFFFFFFULL), (uint)(seed64 >> 32));
    uint4 c0 = (uint4)(gid, 0u, 0u, 0u);
    uint4 r0 = philox4x32_10(c0, key);
    uint4 c1 = (uint4)(gid, 1u, 0u, 0u);
    uint4 r1 = philox4x32_10(c1, key);
    uint words[8] = { r0.x, r0.y, r0.z, r0.w, r1.x, r1.y, r1.z, r1.w };
    int bi = 0;
    for (int i = 0; i < 8; ++i) {
        uint w = words[i];
        out32[bi++] = (uchar)(w & 0xFF);
        out32[bi++] = (uchar)((w >> 8) & 0xFF);
        out32[bi++] = (uchar)((w >> 16) & 0xFF);
        out32[bi++] = (uchar)((w >> 24) & 0xFF);
    }
}

// ---- Field arithmetic for Curve25519 (mod p = 2^255 - 19) using 10x26-bit limbs ----
// Two implementations are available:
//  - MEKG_FE_MUL_IMPL=26 (default): 10x(26/25) schoolbook multiply with 64-bit temps (ref10-style)
//  - MEKG_FE_MUL_IMPL=51: 5x51 with 128-bit emulation (slower on many GPUs)

#ifndef MEKG_FE_MUL_IMPL
#define MEKG_FE_MUL_IMPL 26
#endif

typedef struct { int v[10]; } fe;

// 128-bit signed emulation helpers for OpenCL C (file scope) - used by impl 51
#if MEKG_FE_MUL_IMPL == 51
typedef struct { ulong lo; long hi; } i128_t; // two's complement: value = (hi << 64) | lo
inline i128_t i128_zero(void) { i128_t r; r.lo=0UL; r.hi=0L; return r; }
inline void i128_add_pair(i128_t *a, ulong lo, long hi){
    ulong oldlo = a->lo;
    a->lo = oldlo + lo;
    ulong carry = (a->lo < oldlo) ? 1UL : 0UL;
    a->hi = a->hi + hi + (long)carry;
}
inline void i128_add_i128(i128_t *a, i128_t b){ i128_add_pair(a, b.lo, b.hi); }
inline void i128_add_s64(i128_t *a, long s){ i128_add_pair(a, (ulong)s, (s < 0) ? -1L : 0L); }
inline i128_t i128_mul_uu(ulong x, ulong y){ i128_t r; r.lo = x * y; r.hi = (long)mul_hi(x, y); return r; }
inline i128_t i128_mul_ll(long x, long y){
    int neg = (x < 0) ^ (y < 0);
    ulong ax = (ulong)((x < 0) ? -x : x);
    ulong ay = (ulong)((y < 0) ? -y : y);
    i128_t p = i128_mul_uu(ax, ay);
    if (neg) {
        // two's complement negate
        ulong lo = ~p.lo + 1UL; long hi = ~p.hi; if (lo == 0UL) hi += 1; p.lo = lo; p.hi = hi;
    }
    return p;
}
inline void i128_add_smul_ll(i128_t *acc, long x, long y){ i128_t p = i128_mul_ll(x, y); i128_add_i128(acc, p); }
// Return lower 64 bits of arithmetic right-shift by 51
inline ulong i128_shr51_lo64(const i128_t *a){ return (a->lo >> 51) | ((ulong)a->hi << (64 - 51)); }
inline void i128_mask51(i128_t *a){ a->lo &= ((ulong)1UL<<51) - 1UL; a->hi = 0L; }
#endif

inline void fe_reduce_canonical_cl(fe *r){
    long long h0=r->v[0], h1=r->v[1], h2=r->v[2], h3=r->v[3], h4=r->v[4];
    long long h5=r->v[5], h6=r->v[6], h7=r->v[7], h8=r->v[8], h9=r->v[9];
    long long q = (19LL * h9 + (1LL<<24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    h0 += 19LL * q;
    long long c;
    c = h0 >> 26; h1 += c; h0 -= c << 26;
    c = h1 >> 25; h2 += c; h1 -= c << 25;
    c = h2 >> 26; h3 += c; h2 -= c << 26;
    c = h3 >> 25; h4 += c; h3 -= c << 25;
    c = h4 >> 26; h5 += c; h4 -= c << 26;
    c = h5 >> 25; h6 += c; h5 -= c << 25;
    c = h6 >> 26; h7 += c; h6 -= c << 26;
    c = h7 >> 25; h8 += c; h7 -= c << 25;
    c = h8 >> 26; h9 += c; h8 -= c << 26;
    c = h9 >> 25; h9 -= c << 25; h0 += c * 19LL;
    c = h0 >> 26; h1 += c; h0 -= c << 26;
    c = h1 >> 25; h2 += c; h1 -= c << 25;
    r->v[0]=(int)h0; r->v[1]=(int)h1; r->v[2]=(int)h2; r->v[3]=(int)h3; r->v[4]=(int)h4;
    r->v[5]=(int)h5; r->v[6]=(int)h6; r->v[7]=(int)h7; r->v[8]=(int)h8; r->v[9]=(int)h9;
}

// (kept for reference; not used in fast path)
inline long long shr_floor_ll(long long x, int k) {
    if (x >= 0) return x >> k;
    long long n = -x; long long q = (n + ((1LL << k) - 1)) >> k; return -q;
}

inline void fe_0(fe *h) { for (int i = 0; i < 10; ++i) h->v[i] = 0; }
inline void fe_1(fe *h) { fe_0(h); h->v[0] = 1; }
inline void fe_copy(fe *h, const fe *f) { for (int i = 0; i < 10; ++i) h->v[i] = f->v[i]; }

inline void fe_fromint(fe *h, int x) { fe_0(h); h->v[0] = x; }

// basic ops
inline void fe_add(fe *h, const fe *f, const fe *g) { for (int i=0;i<10;++i) h->v[i]=f->v[i]+g->v[i]; }
inline void fe_sub(fe *h, const fe *f, const fe *g) { for (int i=0;i<10;++i) h->v[i]=f->v[i]-g->v[i]; }
inline void fe_cswap(fe *f, fe *g, int b) {
    int mask = -b;
    for (int i=0;i<10;++i){ int x = mask & (f->v[i]^g->v[i]); f->v[i]^=x; g->v[i]^=x; }
}

inline void fe_mul(fe *h, const fe *f, const fe *g) {
#if MEKG_FE_MUL_IMPL == 51
    // 5x51 implementation with signed packing and 128-bit emulation (slower, kept for fallback/validation)
    long f0 = (long)f->v[0], f1 = (long)f->v[1], f2 = (long)f->v[2], f3 = (long)f->v[3], f4 = (long)f->v[4];
    long f5 = (long)f->v[5], f6 = (long)f->v[6], f7 = (long)f->v[7], f8 = (long)f->v[8], f9 = (long)f->v[9];
    long g0 = (long)g->v[0], g1 = (long)g->v[1], g2 = (long)g->v[2], g3 = (long)g->v[3], g4 = (long)g->v[4];
    long g5 = (long)g->v[5], g6 = (long)g->v[6], g7 = (long)g->v[7], g8 = (long)g->v[8], g9 = (long)g->v[9];

    long F0 = f0 + (f1 << 26);
    long F1 = f2 + (f3 << 26);
    long F2 = f4 + (f5 << 26);
    long F3 = f6 + (f7 << 26);
    long F4 = f8 + (f9 << 26);

    long G0 = g0 + (g1 << 26);
    long G1 = g2 + (g3 << 26);
    long G2 = g4 + (g5 << 26);
    long G3 = g6 + (g7 << 26);
    long G4 = g8 + (g9 << 26);

    long G1_19 = G1 * 19L;
    long G2_19 = G2 * 19L;
    long G3_19 = G3 * 19L;
    long G4_19 = G4 * 19L;

    i128_t H0 = i128_zero(); i128_t H1 = i128_zero(); i128_t H2 = i128_zero(); i128_t H3 = i128_zero(); i128_t H4 = i128_zero();
    i128_add_smul_ll(&H0, F0, G0);  i128_add_smul_ll(&H0, F1, G4_19); i128_add_smul_ll(&H0, F2, G3_19); i128_add_smul_ll(&H0, F3, G2_19); i128_add_smul_ll(&H0, F4, G1_19);
    i128_add_smul_ll(&H1, F0, G1);  i128_add_smul_ll(&H1, F1, G0);    i128_add_smul_ll(&H1, F2, G4_19); i128_add_smul_ll(&H1, F3, G3_19); i128_add_smul_ll(&H1, F4, G2_19);
    i128_add_smul_ll(&H2, F0, G2);  i128_add_smul_ll(&H2, F1, G1);    i128_add_smul_ll(&H2, F2, G0);    i128_add_smul_ll(&H2, F3, G4_19); i128_add_smul_ll(&H2, F4, G3_19);
    i128_add_smul_ll(&H3, F0, G3);  i128_add_smul_ll(&H3, F1, G2);    i128_add_smul_ll(&H3, F2, G1);    i128_add_smul_ll(&H3, F3, G0);    i128_add_smul_ll(&H3, F4, G4_19);
    i128_add_smul_ll(&H4, F0, G4);  i128_add_smul_ll(&H4, F1, G3);    i128_add_smul_ll(&H4, F2, G2);    i128_add_smul_ll(&H4, F3, G1);    i128_add_smul_ll(&H4, F4, G0);

    long c0 = (long)i128_shr51_lo64(&H0); i128_mask51(&H0); i128_add_s64(&H1, c0);
    long c1 = (long)i128_shr51_lo64(&H1); i128_mask51(&H1); i128_add_s64(&H2, c1);
    long c2 = (long)i128_shr51_lo64(&H2); i128_mask51(&H2); i128_add_s64(&H3, c2);
    long c3 = (long)i128_shr51_lo64(&H3); i128_mask51(&H3); i128_add_s64(&H4, c3);
    long c4 = (long)i128_shr51_lo64(&H4); i128_mask51(&H4); i128_add_smul_ll(&H0, c4, 19L);
    c0 = (long)i128_shr51_lo64(&H0); i128_mask51(&H0); i128_add_s64(&H1, c0);

    ulong T0 = H0.lo; ulong T1 = H1.lo; ulong T2 = H2.lo; ulong T3 = H3.lo; ulong T4 = H4.lo;
    int h0_i = (int)(T0 & 0x3ffffffUL); int h1_i = (int)(T0 >> 26);
    int h2_i = (int)(T1 & 0x3ffffffUL); int h3_i = (int)(T1 >> 26);
    int h4_i = (int)(T2 & 0x3ffffffUL); int h5_i = (int)(T2 >> 26);
    int h6_i = (int)(T3 & 0x3ffffffUL); int h7_i = (int)(T3 >> 26);
    int h8_i = (int)(T4 & 0x3ffffffUL); int h9_i = (int)(T4 >> 26);
    h->v[0]=h0_i; h->v[1]=h1_i; h->v[2]=h2_i; h->v[3]=h3_i; h->v[4]=h4_i; h->v[5]=h5_i; h->v[6]=h6_i; h->v[7]=h7_i; h->v[8]=h8_i; h->v[9]=h9_i;
#else
    // 10x(26/25) ref10-style with precomputed 19-folds and doubles
    long long f0=f->v[0], f1=f->v[1], f2=f->v[2], f3=f->v[3], f4=f->v[4];
    long long f5=f->v[5], f6=f->v[6], f7=f->v[7], f8=f->v[8], f9=f->v[9];
    long long g0=g->v[0], g1=g->v[1], g2=g->v[2], g3=g->v[3], g4=g->v[4];
    long long g5=g->v[5], g6=g->v[6], g7=g->v[7], g8=g->v[8], g9=g->v[9];

    long long g1_19 = 19LL*g1, g2_19 = 19LL*g2, g3_19 = 19LL*g3, g4_19 = 19LL*g4, g5_19 = 19LL*g5, g6_19 = 19LL*g6, g7_19 = 19LL*g7, g8_19 = 19LL*g8, g9_19 = 19LL*g9;
    long long f1_2 = 2LL*f1, f3_2 = 2LL*f3, f5_2 = 2LL*f5, f7_2 = 2LL*f7, f9_2 = 2LL*f9;

    long long h0 = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19 + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
    long long h1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19 + f5*g6_19 + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;
    long long h2 = f0*g2 + f1_2*g1 + f2*g0 + f3_2*g9_19 + f4*g8_19 + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
    long long h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19 + f5*g8_19 + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;
    long long h4 = f0*g4 + f1_2*g3 + f2*g2 + f3_2*g1 + f4*g0 + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
    long long h5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0 + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;
    long long h6 = f0*g6 + f1_2*g5 + f2*g4 + f3_2*g3 + f4*g2 + f5_2*g1 + f6*g0 + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
    long long h7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2 + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19;
    long long h8 = f0*g8 + f1_2*g7 + f2*g6 + f3_2*g5 + f4*g4 + f5_2*g3 + f6*g2 + f7_2*g1 + f8*g0 + f9_2*g9_19;
    long long h9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4 + f6*g3 + f7*g2 + f8*g1 + f9*g0;

    // Use sign-safe floor shifts for carries to match ref10 semantics exactly
    long long c;
    c = shr_floor_ll(h0, 26); h1 += c; h0 -= c << 26;
    c = shr_floor_ll(h1, 25); h2 += c; h1 -= c << 25;
    c = shr_floor_ll(h2, 26); h3 += c; h2 -= c << 26;
    c = shr_floor_ll(h3, 25); h4 += c; h3 -= c << 25;
    c = shr_floor_ll(h4, 26); h5 += c; h4 -= c << 26;
    c = shr_floor_ll(h5, 25); h6 += c; h5 -= c << 25;
    c = shr_floor_ll(h6, 26); h7 += c; h6 -= c << 26;
    c = shr_floor_ll(h7, 25); h8 += c; h7 -= c << 25;
    c = shr_floor_ll(h8, 26); h9 += c; h8 -= c << 26;
    c = shr_floor_ll(h9, 25); h9 -= c << 25; h0 += c * 19LL;
    c = shr_floor_ll(h0, 26); h1 += c; h0 -= c << 26;
    c = shr_floor_ll(h1, 25); h2 += c; h1 -= c << 25;

    h->v[0]=(int)h0; h->v[1]=(int)h1; h->v[2]=(int)h2; h->v[3]=(int)h3; h->v[4]=(int)h4; h->v[5]=(int)h5; h->v[6]=(int)h6; h->v[7]=(int)h7; h->v[8]=(int)h8; h->v[9]=(int)h9;
#endif
}

inline void fe_sq(fe *h, const fe *f) { fe t; fe_mul(&t, f, f); fe_copy(h, &t); }

// Multiply by a24 in RFC X25519 ladder: a24 = (A-2)/4 = 121665; used in z2 = E*(AA + a24*E)
inline void fe_mul_a24(fe *h, const fe *f) {
    fe a24; for (int i=0;i<10;++i) a24.v[i]=0; a24.v[0] = 121665;
    fe_mul(h, f, &a24);
}


// Canonical ref10 addition chain to compute z^(p-2)
static inline void fe_invert(fe *out, const fe *z) {
    fe t0,t1,t2,t3; int i;
    fe_sq(&t0, z);                  // t0 = z^2
    fe_sq(&t1, &t0);                // t1 = z^4
    fe_sq(&t1, &t1);                // t1 = z^8
    fe_mul(&t1, &t1, z);            // t1 = z^9
    fe_mul(&t0, &t0, &t1);          // t0 = z^11
    fe_sq(&t2, &t0);                // t2 = z^22
    fe_mul(&t1, &t1, &t2);          // t1 = z^31 = 2^5 - 1

    fe_sq(&t2, &t1);                // t2 = 2^6 - 2
    for (i = 0; i < 4; ++i) fe_sq(&t2, &t2); // t2 = 2^10 - 2^5
    fe_mul(&t1, &t2, &t1);          // t1 = 2^10 - 1

    fe_sq(&t2, &t1);                // t2 = 2^11 - 2
    for (i = 0; i < 9; ++i) fe_sq(&t2, &t2); // t2 = 2^20 - 2^10
    fe_mul(&t2, &t2, &t1);          // t2 = 2^20 - 1

    fe_sq(&t3, &t2);                // t3 = 2^21 - 2
    for (i = 0; i < 19; ++i) fe_sq(&t3, &t3); // t3 = 2^40 - 2^20
    fe_mul(&t2, &t3, &t2);          // t2 = 2^40 - 1

    fe_sq(&t2, &t2);                // t2 = 2^41 - 2
    for (i = 0; i < 9; ++i) fe_sq(&t2, &t2); // t2 = 2^50 - 2^10
    fe_mul(&t1, &t2, &t1);          // t1 = 2^50 - 1

    fe_sq(&t2, &t1);                // t2 = 2^51 - 2
    for (i = 0; i < 49; ++i) fe_sq(&t2, &t2); // t2 = 2^100 - 2^50
    fe_mul(&t2, &t2, &t1);          // t2 = 2^100 - 1

    fe_sq(&t3, &t2);                // t3 = 2^101 - 2
    for (i = 0; i < 99; ++i) fe_sq(&t3, &t3); // t3 = 2^200 - 2^100
    fe_mul(&t2, &t3, &t2);          // t2 = 2^200 - 1

    for (i = 0; i < 50; ++i) fe_sq(&t2, &t2); // t2 = 2^250 - 2^50
    fe_mul(&t2, &t2, &t1);          // t2 = 2^250 - 1
    for (i = 0; i < 5; ++i) fe_sq(&t2, &t2);  // t2 = 2^255 - 32
    fe_mul(out, &t2, &t0);          // out = 2^255 - 21
}

inline void fe_tobytes(__global uchar *s, const fe *h) {
    long long t[10]; for (int i=0;i<10;++i) t[i] = h->v[i];
    long long c0,c1,c2,c3,c4,c5,c6,c7,c8,c9;
    c0=(t[0]+(1LL<<25))>>26; t[0]-=c0<<26; t[1]+=c0;
    c1=(t[1]+(1LL<<24))>>25; t[1]-=c1<<25; t[2]+=c1;
    c2=(t[2]+(1LL<<25))>>26; t[2]-=c2<<26; t[3]+=c2;
    c3=(t[3]+(1LL<<24))>>25; t[3]-=c3<<25; t[4]+=c3;
    c4=(t[4]+(1LL<<25))>>26; t[4]-=c4<<26; t[5]+=c4;
    c5=(t[5]+(1LL<<24))>>25; t[5]-=c5<<25; t[6]+=c5;
    c6=(t[6]+(1LL<<25))>>26; t[6]-=c6<<26; t[7]+=c6;
    c7=(t[7]+(1LL<<24))>>25; t[7]-=c7<<25; t[8]+=c7;
    c8=(t[8]+(1LL<<25))>>26; t[8]-=c8<<26; t[9]+=c8;
    c9=(t[9]+(1LL<<24))>>25; t[9]-=c9<<25; t[0]+=c9*19;
    c0=(t[0]+(1LL<<25))>>26; t[0]-=c0<<26; t[1]+=c0;
    c1=(t[1]+(1LL<<24))>>25; t[1]-=c1<<25; t[2]+=c1;

    ulong u0 = (ulong)(t[0]      ) | ((ulong)t[1] << 26);
    ulong u1 = (ulong)(t[1] >> 6 ) | ((ulong)t[2] << 19);
    ulong u2 = (ulong)(t[2] >> 13) | ((ulong)t[3] << 13);
    ulong u3 = (ulong)(t[3] >> 19) | ((ulong)t[4] << 6 );
    ulong u4 = (ulong)(t[4] >> 20) | ((ulong)t[5] << 25);
    ulong u5 = (ulong)(t[5] >> 7 ) | ((ulong)t[6] << 19);
    ulong u6 = (ulong)(t[6] >> 13) | ((ulong)t[7] << 12);
    ulong u7 = (ulong)(t[7] >> 20) | ((ulong)t[8] << 6 );
    ulong u8 = (ulong)(t[8] >> 19) | ((ulong)t[9] << 12);

    // Write 32 bytes little-endian
    uint w0 = (uint)(u0 & 0xffffffffUL);
    uint w1 = (uint)((u0 >> 32) & 0xffffffffUL);
    uint w2 = (uint)(u1 & 0xffffffffUL);
    uint w3 = (uint)((u1 >> 32) & 0xffffffffUL);
    uint w4 = (uint)(u2 & 0xffffffffUL);
    uint w5 = (uint)((u2 >> 32) & 0xffffffffUL);
    uint w6 = (uint)(u3 & 0xffffffffUL);
    uint w7 = (uint)((u3 >> 32) & 0xffffffffUL);
    uint w8 = (uint)(u4 & 0xffffffffUL);
    uint w9 = (uint)((u4 >> 32) & 0xffffffffUL);
    uint wA = (uint)(u5 & 0xffffffffUL);
    uint wB = (uint)((u5 >> 32) & 0xffffffffUL);
    uint wC = (uint)(u6 & 0xffffffffUL);
    uint wD = (uint)((u6 >> 32) & 0xffffffffUL);
    uint wE = (uint)(u7 & 0xffffffffUL);
    uint wF = (uint)((u7 >> 32) & 0xffffffffUL);
    // pack into 32 bytes
    uint words[16] = {w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,wA,wB,wC,wD,wE,wF};
    for (int i=0;i<16;++i) {
        uint w = words[i];
        int off = i*2;
        s[off*2+0] = (uchar)( w        & 0xFF);
        s[off*2+1] = (uchar)((w >> 8 ) & 0xFF);
        s[off*2+2] = (uchar)((w >> 16) & 0xFF);
        s[off*2+3] = (uchar)((w >> 24) & 0xFF);
    }
}

// Serialize field element to 32 bytes (private address space), ref10 mapping
inline void fe_tobytes_priv(__private uchar *s, const fe *h) {
    long long t[10]; for (int i=0;i<10;++i) t[i] = h->v[i];
    long long c0,c1,c2,c3,c4,c5,c6,c7,c8,c9;
    c0=(t[0]+(1LL<<25))>>26; t[0]-=c0<<26; t[1]+=c0;
    c1=(t[1]+(1LL<<24))>>25; t[1]-=c1<<25; t[2]+=c1;
    c2=(t[2]+(1LL<<25))>>26; t[2]-=c2<<26; t[3]+=c2;
    c3=(t[3]+(1LL<<24))>>25; t[3]-=c3<<25; t[4]+=c3;
    c4=(t[4]+(1LL<<25))>>26; t[4]-=c4<<26; t[5]+=c4;
    c5=(t[5]+(1LL<<24))>>25; t[5]-=c5<<25; t[6]+=c5;
    c6=(t[6]+(1LL<<25))>>26; t[6]-=c6<<26; t[7]+=c6;
    c7=(t[7]+(1LL<<24))>>25; t[7]-=c7<<25; t[8]+=c7;
    c8=(t[8]+(1LL<<25))>>26; t[8]-=c8<<26; t[9]+=c8;
    c9=(t[9]+(1LL<<24))>>25; t[9]-=c9<<25; t[0]+=c9*19;
    c0=(t[0]+(1LL<<25))>>26; t[0]-=c0<<26; t[1]+=c0;
    c1=(t[1]+(1LL<<24))>>25; t[1]-=c1<<25; t[2]+=c1;

    long long t0=t[0], t1=t[1], t2=t[2], t3=t[3], t4=t[4], t5=t[5], t6=t[6], t7=t[7], t8=t[8], t9=t[9];
    s[0]  = (uchar)( t0        & 0xff);
    s[1]  = (uchar)((t0 >> 8 ) & 0xff);
    s[2]  = (uchar)((t0 >> 16) & 0xff);
    s[3]  = (uchar)(((t0 >> 24) | (t1 << 2)) & 0xff);
    s[4]  = (uchar)((t1 >> 6 ) & 0xff);
    s[5]  = (uchar)((t1 >> 14) & 0xff);
    s[6]  = (uchar)(((t1 >> 22) | (t2 << 3)) & 0xff);
    s[7]  = (uchar)((t2 >> 5 ) & 0xff);
    s[8]  = (uchar)((t2 >> 13) & 0xff);
    s[9]  = (uchar)(((t2 >> 21) | (t3 << 5)) & 0xff);
    s[10] = (uchar)((t3 >> 3 ) & 0xff);
    s[11] = (uchar)((t3 >> 11) & 0xff);
    s[12] = (uchar)(((t3 >> 19) | (t4 << 6)) & 0xff);
    s[13] = (uchar)((t4 >> 2 ) & 0xff);
    s[14] = (uchar)((t4 >> 10) & 0xff);
    s[15] = (uchar)((t4 >> 18) & 0xff);
    s[16] = (uchar)( t5        & 0xff);
    s[17] = (uchar)((t5 >> 8 ) & 0xff);
    s[18] = (uchar)((t5 >> 16) & 0xff);
    s[19] = (uchar)(((t5 >> 24) | (t6 << 1)) & 0xff);
    s[20] = (uchar)((t6 >> 7 ) & 0xff);
    s[21] = (uchar)((t6 >> 15) & 0xff);
    s[22] = (uchar)(((t6 >> 23) | (t7 << 3)) & 0xff);
    s[23] = (uchar)((t7 >> 5 ) & 0xff);
    s[24] = (uchar)((t7 >> 13) & 0xff);
    s[25] = (uchar)(((t7 >> 21) | (t8 << 4)) & 0xff);
    s[26] = (uchar)((t8 >> 4 ) & 0xff);
    s[27] = (uchar)((t8 >> 12) & 0xff);
    s[28] = (uchar)(((t8 >> 20) | (t9 << 6)) & 0xff);
    s[29] = (uchar)((t9 >> 2 ) & 0xff);
    s[30] = (uchar)((t9 >> 10) & 0xff);
    s[31] = (uchar)((t9 >> 18) & 0xff);
}

// CPU-parity serializer: q-accumulator canonicalization + ref10 packing
inline void fe_tobytes_q(__private uchar *s, const fe *h) {
    long long h0=h->v[0], h1=h->v[1], h2=h->v[2], h3=h->v[3], h4=h->v[4];
    long long h5=h->v[5], h6=h->v[6], h7=h->v[7], h8=h->v[8], h9=h->v[9];
    long long q = (19LL * h9 + (1LL<<24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    h0 += 19LL * q;
    long long c;
    c = h0 >> 26; h1 += c; h0 -= c << 26;
    c = h1 >> 25; h2 += c; h1 -= c << 25;
    c = h2 >> 26; h3 += c; h2 -= c << 26;
    c = h3 >> 25; h4 += c; h3 -= c << 25;
    c = h4 >> 26; h5 += c; h4 -= c << 26;
    c = h5 >> 25; h6 += c; h5 -= c << 25;
    c = h6 >> 26; h7 += c; h6 -= c << 26;
    c = h7 >> 25; h8 += c; h7 -= c << 25;
    c = h8 >> 26; h9 += c; h8 -= c << 26;
    c = h9 >> 25; h9 -= c << 25; h0 += c * 19LL;
    c = h0 >> 26; h1 += c; h0 -= c << 26;
    c = h1 >> 25; h2 += c; h1 -= c << 25;

    long long t0=h0,t1=h1,t2=h2,t3=h3,t4=h4,t5=h5,t6=h6,t7=h7,t8=h8,t9=h9;
    s[0]  = (uchar)( t0        & 0xff);
    s[1]  = (uchar)((t0 >> 8 ) & 0xff);
    s[2]  = (uchar)((t0 >> 16) & 0xff);
    s[3]  = (uchar)(((t0 >> 24) | (t1 << 2)) & 0xff);
    s[4]  = (uchar)((t1 >> 6 ) & 0xff);
    s[5]  = (uchar)((t1 >> 14) & 0xff);
    s[6]  = (uchar)(((t1 >> 22) | (t2 << 3)) & 0xff);
    s[7]  = (uchar)((t2 >> 5 ) & 0xff);
    s[8]  = (uchar)((t2 >> 13) & 0xff);
    s[9]  = (uchar)(((t2 >> 21) | (t3 << 5)) & 0xff);
    s[10] = (uchar)((t3 >> 3 ) & 0xff);
    s[11] = (uchar)((t3 >> 11) & 0xff);
    s[12] = (uchar)(((t3 >> 19) | (t4 << 6)) & 0xff);
    s[13] = (uchar)((t4 >> 2 ) & 0xff);
    s[14] = (uchar)((t4 >> 10) & 0xff);
    s[15] = (uchar)((t4 >> 18) & 0xff);
    s[16] = (uchar)( t5        & 0xff);
    s[17] = (uchar)((t5 >> 8 ) & 0xff);
    s[18] = (uchar)((t5 >> 16) & 0xff);
    s[19] = (uchar)(((t5 >> 24) | (t6 << 1)) & 0xff);
    s[20] = (uchar)((t6 >> 7 ) & 0xff);
    s[21] = (uchar)((t6 >> 15) & 0xff);
    s[22] = (uchar)(((t6 >> 23) | (t7 << 3)) & 0xff);
    s[23] = (uchar)((t7 >> 5 ) & 0xff);
    s[24] = (uchar)((t7 >> 13) & 0xff);
    s[25] = (uchar)(((t7 >> 21) | (t8 << 4)) & 0xff);
    s[26] = (uchar)((t8 >> 4 ) & 0xff);
    s[27] = (uchar)((t8 >> 12) & 0xff);
    s[28] = (uchar)(((t8 >> 20) | (t9 << 6)) & 0xff);
    s[29] = (uchar)((t9 >> 2 ) & 0xff);
    s[30] = (uchar)((t9 >> 10) & 0xff);
    s[31] = (uchar)((t9 >> 18) & 0xff);
}

static inline void x25519_basepoint_mul(__private const uchar sk[32], __private uchar out[32]) {
    // basepoint u = 9
    fe x1; fe_fromint(&x1, 9);
    fe x2,z2,x3,z3,a,aa,fb,bb,e,fc,d,da,cb, tmp;
    fe_1(&x2); fe_0(&z2);
    fe_copy(&x3, &x1); fe_1(&z3);
    int swap = 0;
    // process bits 254..0 of scalar
    for (int pos = 254; pos >= 0; --pos) {
        int bit = (sk[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(&x2, &x3, swap);
        fe_cswap(&z2, &z3, swap);
        swap = bit;

        fe_add(&a, &x2, &z2);       // A = x2+z2
        fe_sq(&aa, &a);             // AA = A^2
        fe_sub(&fb, &x2, &z2);      // B = x2-z2
        fe_sq(&bb, &fb);            // BB = B^2
        fe_sub(&e, &aa, &bb);       // E = AA-BB

        fe_add(&fc, &x3, &z3);      // C = x3+z3
        fe_sub(&d, &x3, &z3);       // D = x3-z3
        fe_mul(&da, &d, &a);        // DA = D*A
        fe_mul(&cb, &fc, &fb);      // CB = C*B
        fe_add(&tmp, &da, &cb);
        fe_sq(&x3, &tmp);           // x3' = (DA+CB)^2
        fe_sub(&tmp, &da, &cb);
        fe_sq(&tmp, &tmp);
        fe_mul(&z3, &tmp, &x1);     // z3' = x1*(DA-CB)^2

    fe_mul(&x2, &aa, &bb);      // x2' = AA*BB
    // RFC X25519: a24 = 121665, z2' = E*(AA + a24*E)
    fe_mul_a24(&tmp, &e);     // t = a24*E
    fe_add(&tmp, &aa, &tmp);    // AA + a24*E
    fe_mul(&z2, &e, &tmp);      // z2' = E*(AA + a24*E)
    }
    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);

    fe_invert(&z2, &z2);           // z2 = 1/z2
    fe_mul(&x2, &x2, &z2);         // x2 = x2/z2
    // encode
    fe_tobytes_q(out, &x2);
}

// Trace kernel: accepts one secret (already clamped) and dumps per-iteration
// Montgomery ladder state for debugging (first N steps), writing fe limbs.
// Layout per-iteration: X2[10], Z2[10], X3[10], Z3[10] as int32 little-endian
__kernel void x25519_trace_kernel(
    __global const uchar *in_sk,
    __global int *out_limbs, // size: iters * 40 ints
    const uint iters
) {
    const uint gid = get_global_id(0);
    if (gid != 0) return; // single scalar for trace
    __private uchar sk[32];
    for (int i=0;i<32;++i) sk[i]=in_sk[i];
    // Clamp
    sk[0] &= (uchar)248; sk[31] &= (uchar)127; sk[31] |= (uchar)64;
    fe x1; fe_fromint(&x1, 9);
    fe x2,z2,x3,z3,a,aa,fb,bb,e,fc,d,da,cb,tmp;
    fe_1(&x2); fe_0(&z2);
    fe_copy(&x3,&x1); fe_1(&z3);
    int swap=0;
    for (int pos=254,step=0; pos>=0 && (uint)step<iters; --pos,++step) {
        int bit=(sk[pos>>3]>>(pos&7))&1; swap^=bit; fe_cswap(&x2,&x3,swap); fe_cswap(&z2,&z3,swap); swap=bit;
        fe_add(&a,&x2,&z2); fe_sq(&aa,&a); fe_sub(&fb,&x2,&z2); fe_sq(&bb,&fb); fe_sub(&e,&aa,&bb);
        fe_add(&fc,&x3,&z3); fe_sub(&d,&x3,&z3); fe_mul(&da,&d,&a); fe_mul(&cb,&fc,&fb);
        fe_add(&tmp,&da,&cb); fe_sq(&x3,&tmp); fe_sub(&tmp,&da,&cb); fe_sq(&tmp,&tmp); fe_mul(&z3,&tmp,&x1);
    fe_mul(&x2,&aa,&bb); // x2'
    fe_mul_a24(&tmp,&e); fe_add(&tmp,&aa,&tmp); fe_mul(&z2,&e,&tmp);
        // dump limbs
        int base = step*40;
        for (int i=0;i<10;++i) out_limbs[base+i] = x2.v[i];
        for (int i=0;i<10;++i) out_limbs[base+10+i] = z2.v[i];
        for (int i=0;i<10;++i) out_limbs[base+20+i] = x3.v[i];
        for (int i=0;i<10;++i) out_limbs[base+30+i] = z3.v[i];
    }
}

// Kernel inputs
// seeds: per-work-item seed/ctr (placeholder)
// patterns_b: concatenated bytes for prefixes and suffixes; we address by offsets passed separately
// metas: pattern metadata and offsets
// out_pub_priv: output buffer for base64 pub/priv pairs (44+1 each) per match
// found_counter: atomic counter of matches
// target_count: stop condition
// iters: iterations per work-item

__kernel void keygen_kernel(
    __global uint2 *seeds,
    __global const uchar *patterns_b,
    __global const uint *pat_offs_prefix,
    __global const uint *pat_offs_suffix,
    __global const pattern_meta_t *metas,
    const uint patterns_count,
    __global uchar *out_pub_priv,
    __global uint *found_counter,
    const uint target_count,
    const uint iters
) {
    const uint gid = get_global_id(0);
    uint2 s = seeds[gid];

    for (uint i = 0; i < iters; ++i) {
        // Counter-based RNG: use (gid, i) by offsetting the second counter lane
        uchar sk[32];
        {
            // Use (gid, i) as unique counter blocks
            uint2 key = (uint2)(s.x, s.y);
            uint4 c0 = (uint4)(gid, i*2u, 0u, 0u);
            uint4 c1 = (uint4)(gid, i*2u+1u, 0u, 0u);
            uint4 r0 = philox4x32_10(c0, key);
            uint4 r1 = philox4x32_10(c1, key);
            uint words[8] = { r0.x, r0.y, r0.z, r0.w, r1.x, r1.y, r1.z, r1.w };
            int bi2 = 0;
            for (int ii = 0; ii < 8; ++ii) {
                uint w = words[ii];
                sk[bi2++] = (uchar)(w & 0xFF);
                sk[bi2++] = (uchar)((w >> 8) & 0xFF);
                sk[bi2++] = (uchar)((w >> 16) & 0xFF);
                sk[bi2++] = (uchar)((w >> 24) & 0xFF);
            }
        }
        sk[0] &= (uchar)248; sk[31] &= (uchar)127; sk[31] |= (uchar)64;

    // Compute X25519 public key from sk (Montgomery ladder)
    uchar pk[32];
    x25519_basepoint_mul(sk, pk);

        // Base64 encode pk into 44 chars
        uchar b64[44];
        int bi = 0;
        for (int j = 0; j < 30; j += 3) {
            uint v = ((uint)pk[j] << 16) | ((uint)pk[j+1] << 8) | (uint)pk[j+2];
            b64[bi++] = B64_TABLE[(v >> 18) & 63];
            b64[bi++] = B64_TABLE[(v >> 12) & 63];
            b64[bi++] = B64_TABLE[(v >> 6) & 63];
            b64[bi++] = B64_TABLE[v & 63];
        }
        // last block for 32 bytes: 2 remainder bytes -> 4 output chars with padding '='
        {
            uint v = ((uint)pk[30] << 16) | ((uint)pk[31] << 8);
            b64[bi++] = B64_TABLE[(v >> 18) & 63];
            b64[bi++] = B64_TABLE[(v >> 12) & 63];
            b64[bi++] = B64_TABLE[(v >> 6) & 63];
            b64[bi++] = '='; // padding
        }

        // Pattern match (prefix or suffix)
        int matched = 0;
        for (uint p = 0; p < patterns_count; ++p) {
            pattern_meta_t m = metas[p];
            if (m.prefix_len > 0) {
                uint off = pat_offs_prefix[p];
                int ok = 1;
                for (uint k = 0; k < m.prefix_len; ++k) {
                    if (b64[k] != patterns_b[off + k]) { ok = 0; break; }
                }
                if (ok) { matched = 1; break; }
            }
            if (m.suffix_len > 0) {
                uint off = pat_offs_suffix[p];
                int ok = 1;
                for (uint k = 0; k < m.suffix_len; ++k) {
                    if (b64[m.suffix_off + k] != patterns_b[off + k]) { ok = 0; break; }
                }
                if (ok) { matched = 1; break; }
            }
        }

        if (matched) {
            // Atomically claim a slot and write pub/priv as base64 (priv left as placeholder too)
            uint idx = atomic_inc(found_counter);
            if (idx < target_count) {
                __global uchar *slot = out_pub_priv + idx * (44 + 1 + 44 + 1);
                // pub
                for (int k = 0; k < 44; ++k) slot[k] = b64[k];
                slot[44] = 0;
                // priv (encode sk similarly)
                // base64 of sk
                uchar b64s[44];
                bi = 0;
                for (int j = 0; j < 30; j += 3) {
                    uint v2 = ((uint)sk[j] << 16) | ((uint)sk[j+1] << 8) | (uint)sk[j+2];
                    b64s[bi++] = B64_TABLE[(v2 >> 18) & 63];
                    b64s[bi++] = B64_TABLE[(v2 >> 12) & 63];
                    b64s[bi++] = B64_TABLE[(v2 >> 6) & 63];
                    b64s[bi++] = B64_TABLE[v2 & 63];
                }
                uint v2 = ((uint)sk[30] << 16) | ((uint)sk[31] << 8);
                b64s[bi++] = B64_TABLE[(v2 >> 18) & 63];
                b64s[bi++] = B64_TABLE[(v2 >> 12) & 63];
                b64s[bi++] = B64_TABLE[(v2 >> 6) & 63];
                b64s[bi++] = '=';
                for (int k = 0; k < 44; ++k) slot[45 + k] = b64s[k];
                slot[45 + 44] = 0;
            }
        }

        if (*found_counter >= target_count) return;
    }
}

// Test kernel: dumps clamped secret (sk) base64 per work-item (first iteration only)
__kernel void rng_dump_kernel(
    __global uint2 *seeds,
    __global uchar *out_priv_b64
) {
    const uint gid = get_global_id(0);
    uint2 s = seeds[gid];
    uchar sk[32];
    // Use philox with (gid, 0)
    uint4 c0 = (uint4)(gid, 0u, 0u, 0u);
    uint4 c1 = (uint4)(gid, 1u, 0u, 0u);
    uint4 r0 = philox4x32_10(c0, s);
    uint4 r1 = philox4x32_10(c1, s);
    uint words[8] = { r0.x, r0.y, r0.z, r0.w, r1.x, r1.y, r1.z, r1.w };
    int bi = 0;
    for (int ii = 0; ii < 8; ++ii) {
        uint w = words[ii];
        sk[bi++] = (uchar)(w & 0xFF);
        sk[bi++] = (uchar)((w >> 8) & 0xFF);
        sk[bi++] = (uchar)((w >> 16) & 0xFF);
        sk[bi++] = (uchar)((w >> 24) & 0xFF);
    }
    sk[0] &= (uchar)248; sk[31] &= (uchar)127; sk[31] |= (uchar)64;
    // base64 encode to 44 chars
    uchar b64[44];
    int bj = 0;
    for (int j = 0; j < 30; j += 3) {
        uint v = ((uint)sk[j] << 16) | ((uint)sk[j+1] << 8) | (uint)sk[j+2];
        b64[bj++] = B64_TABLE[(v >> 18) & 63];
        b64[bj++] = B64_TABLE[(v >> 12) & 63];
        b64[bj++] = B64_TABLE[(v >> 6) & 63];
        b64[bj++] = B64_TABLE[v & 63];
    }
    uint v = ((uint)sk[30] << 16) | ((uint)sk[31] << 8);
    b64[bj++] = B64_TABLE[(v >> 18) & 63];
    b64[bj++] = B64_TABLE[(v >> 12) & 63];
    b64[bj++] = B64_TABLE[(v >> 6) & 63];
    b64[bj++] = '=';
    __global uchar *dst = out_priv_b64 + gid * 45;
    for (int k = 0; k < 44; ++k) dst[k] = b64[k];
    dst[44] = 0;
}

// Compute public key (raw 32 bytes) per work-item for deterministic tests
__kernel void pubkey_dump_kernel(
    __global uint2 *seeds,
    __global uchar *out_pub
) {
    const uint gid = get_global_id(0);
    uint2 s = seeds[gid];
    // 32-byte secret from Philox (two blocks)
    uchar sk[32];
    uint4 c0 = (uint4)(gid, 0u, 0u, 0u);
    uint4 c1 = (uint4)(gid, 1u, 0u, 0u);
    uint4 r0 = philox4x32_10(c0, s);
    uint4 r1 = philox4x32_10(c1, s);
    uint words[8] = { r0.x, r0.y, r0.z, r0.w, r1.x, r1.y, r1.z, r1.w };
    int bi = 0;
    for (int ii = 0; ii < 8; ++ii) {
        uint w = words[ii];
        sk[bi++] = (uchar)(w & 0xFF);
        sk[bi++] = (uchar)((w >> 8) & 0xFF);
        sk[bi++] = (uchar)((w >> 16) & 0xFF);
        sk[bi++] = (uchar)((w >> 24) & 0xFF);
    }
    sk[0] &= (uchar)248; sk[31] &= (uchar)127; sk[31] |= (uchar)64;
    uchar pk[32];
    x25519_basepoint_mul(sk, pk);
    __global uchar *dst = out_pub + gid * 32;
    for (int i=0;i<32;++i) dst[i] = pk[i];
}

// Direct-scalar kernel: compute public keys from provided clamped secrets
__kernel void x25519_from_sk_kernel(
    __global const uchar *in_sk,
    __global uchar *out_pub,
    const uint count
) {
    const uint gid = get_global_id(0);
    if (gid >= count) return;
    __private uchar sk[32];
    for (int i=0;i<32;++i) sk[i] = in_sk[gid*32 + i];
    // Clamp per X25519 decodeScalar25519
    sk[0] &= (uchar)248; sk[31] &= (uchar)127; sk[31] |= (uchar)64;
    __private uchar pk[32];
    x25519_basepoint_mul(sk, pk);
    __global uchar *dst = out_pub + gid*32;
    for (int i=0;i<32;++i) dst[i] = pk[i];
}

// Debug kernel: for a single clamped secret, dump x2, z2 (end of ladder), zinv, x=x2*zinv limbs, and serialized bytes
// out_limbs layout: x2[10], z2[10], zinv[10], x[10]
// out_bytes: 32 bytes of serialized x
// out_limbs layout: x2[10], z2[10], zinv[10], x[10]
// out_pre_limbs: pre_x2[10], pre_z2[10]
// Additionally, we write last-iter aa,bb,e,x2',z2' into out_pre_limbs extension (if sized accordingly)
__kernel void x25519_debug_final_kernel(
    __global const uchar *in_sk,
    __global int *out_limbs,
    __global uchar *out_bytes,
    __global int *out_swap_bit,
    __global int *out_pre_limbs
) {
    const uint gid = get_global_id(0);
    if (gid != 0) return; // single secret debug
    __private uchar sk[32];
    for (int i=0;i<32;++i) sk[i] = in_sk[i];
    // Clamp
    sk[0] &= (uchar)248; sk[31] &= (uchar)127; sk[31] |= (uchar)64;
    // Ladder to get x2,z2
    fe x1; fe_fromint(&x1, 9);
    fe x2,z2,x3,z3,a,aa,fb,bb,e,fc,d,da,cb,tmp;
    fe_1(&x2); fe_0(&z2);
    fe_copy(&x3,&x1); fe_1(&z3);
    int swap = 0;
    // Capture pre-final-cswap state
    fe pre_x2, pre_z2;
    for (int pos=254; pos>=0; --pos){
        int bit=(sk[pos>>3]>>(pos&7))&1; swap^=bit; fe_cswap(&x2,&x3,swap); fe_cswap(&z2,&z3,swap); swap=bit;
        fe_add(&a,&x2,&z2); fe_sq(&aa,&a); fe_sub(&fb,&x2,&z2); fe_sq(&bb,&fb); fe_sub(&e,&aa,&bb);
        fe_add(&fc,&x3,&z3); fe_sub(&d,&x3,&z3); fe_mul(&da,&d,&a); fe_mul(&cb,&fc,&fb);
        fe_add(&tmp,&da,&cb); fe_sq(&x3,&tmp); fe_sub(&tmp,&da,&cb); fe_sq(&tmp,&tmp); fe_mul(&z3,&tmp,&x1);
        fe_mul(&x2,&aa,&bb);
    fe_mul_a24(&tmp,&e); fe_add(&tmp,&aa,&tmp); fe_mul(&z2,&e,&tmp);
        if (pos==0) {
            // Dump last-iter aa, bb, e, x2', z2' into out_pre_limbs after the first 20 slots
            for (int i=0;i<10;++i) out_pre_limbs[20 + i] = aa.v[i];
            for (int i=0;i<10;++i) out_pre_limbs[30 + i] = bb.v[i];
            for (int i=0;i<10;++i) out_pre_limbs[40 + i] = e.v[i];
            for (int i=0;i<10;++i) out_pre_limbs[50 + i] = x2.v[i];
            for (int i=0;i<10;++i) out_pre_limbs[60 + i] = z2.v[i];
        }
    }
    // save pre-final cswap X2/Z2
    pre_x2 = x2; pre_z2 = z2;
    fe_cswap(&x2,&x3,swap); fe_cswap(&z2,&z3,swap);
    // Invert and multiply
    fe zinv, x; fe_invert(&zinv,&z2); fe_mul(&x,&x2,&zinv);
    // Write limbs
    for (int i=0;i<10;++i) out_limbs[i]      = x2.v[i];
    for (int i=0;i<10;++i) out_limbs[10+i]   = z2.v[i];
    for (int i=0;i<10;++i) out_limbs[20+i]   = zinv.v[i];
    for (int i=0;i<10;++i) out_limbs[30+i]   = x.v[i];
    // Serialize x
    __private uchar pk[32];
    fe_tobytes_q(pk, &x);
    for (int i=0;i<32;++i) out_bytes[i] = pk[i];
    // Write swap bit and pre-cswap limbs
    *out_swap_bit = swap;
    for (int i=0;i<10;++i) out_pre_limbs[i]    = pre_x2.v[i];
    for (int i=0;i<10;++i) out_pre_limbs[10+i] = pre_z2.v[i];
}
