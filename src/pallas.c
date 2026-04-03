#include "pallas.h"
#include "blake2b.h"
#include "memzero.h"
#include <string.h>

// Progress callback
static pallas_progress_cb s_progress_cb = NULL;
static void* s_progress_ctx = NULL;

void pallas_set_progress_cb(pallas_progress_cb cb, void* ctx) {
    s_progress_cb = cb;
    s_progress_ctx = ctx;
}

void pallas_report(uint8_t pct, const char* label) {
    if(s_progress_cb) s_progress_cb(pct, label, s_progress_ctx);
}

// Yield callback — platform sets this to prevent watchdog reset on
// constrained devices (e.g. furi_delay_tick on Flipper Zero).
// Default: no-op.
static void (*s_yield_fn)(void* ctx) = NULL;
static void* s_yield_ctx = NULL;
static uint32_t s_yield_counter = 0;

void pallas_set_yield_cb(void (*cb)(void* ctx), void* ctx) {
    s_yield_fn = cb;
    s_yield_ctx = ctx;
}

static inline void pallas_yield(void) {
    if(s_yield_fn && ++s_yield_counter >= 5) {
        s_yield_counter = 0;
        s_yield_fn(s_yield_ctx);
    }
}

// ============================================================
// Constants
// ============================================================

static const uint8_t PALLAS_P_BE[32] = {
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xed,0x00,0x00,0x00,0x01};
static const uint8_t PALLAS_Q_BE[32] = {
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x46,0x98,0xfc,0x09,0x94,0xa8,0xdd,0x8c,0x46,0xeb,0x21,0x00,0x00,0x00,0x01};
static const uint8_t P_MINUS_2_BE[32] = {
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xec,0xff,0xff,0xff,0xff};
static const uint8_t P_MINUS_1_HALF_BE[32] = {
    0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x11,0x23,0x4c,0x7e,0x04,0xa6,0x7c,0x8d,0xcc,0x96,0x98,0x76,0x80,0x00,0x00,0x00};
// Tonelli-Shanks: p-1 = 2^32 * T
#define TS_S 32
static const uint8_t TS_T_BE[32] = {
    0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xed};
static const uint8_t TS_Z_BE[32] = { // 5^T mod p
    0x2b,0xce,0x74,0xde,0xac,0x30,0xeb,0xda,0x36,0x21,0x20,0x83,0x05,0x61,0xf8,0x1a,
    0xea,0x32,0x2b,0xf2,0xb7,0xbb,0x75,0x84,0xbd,0xad,0x6f,0xab,0xd8,0x7e,0xa3,0x2f};

// iso-Pallas: y^2 = x^3 + ISO_A*x + ISO_B
static const uint8_t ISO_A_BE[32] = {
    0x18,0x35,0x4a,0x2e,0xb0,0xea,0x8c,0x9c,0x49,0xbe,0x2d,0x72,0x58,0x37,0x07,0x42,
    0xb7,0x41,0x34,0x58,0x1a,0x27,0xa5,0x9f,0x92,0xbb,0x4b,0x0b,0x65,0x7a,0x01,0x4b};
static const uint8_t ISO_B_BE[32] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0xf1};
static const uint8_t SWU_Z_BE[32] = { // -13 mod p
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xec,0xff,0xff,0xff,0xf4};

// 3-isogeny map coefficients (iso-Pallas -> Pallas)
static const uint8_t ISO_C_BE[13][32] = {
    {0x0e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x40,0x81,0x77,0x54,0x73,0xd8,0x37,0x5b,0x77,0x5f,0x60,0x34,0xaa,0xaa,0xaa,0xab},
    {0x35,0x09,0xaf,0xd5,0x18,0x72,0xd8,0x8e,0x26,0x7c,0x7f,0xfa,0x51,0xcf,0x41,0x2a,0x0f,0x93,0xb8,0x2e,0xe4,0xb9,0x94,0x95,0x8c,0xf8,0x63,0xb0,0x28,0x14,0xfb,0x76},
    {0x17,0x32,0x9b,0x9e,0xc5,0x25,0x37,0x53,0x98,0xc7,0xd7,0xac,0x3d,0x98,0xfd,0x13,0x38,0x0a,0xf0,0x66,0xcf,0xeb,0x6d,0x69,0x0e,0xb6,0x4f,0xae,0xf3,0x7e,0xa4,0xf7},
    {0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x81,0x02,0xee,0xa8,0xe7,0xb0,0x6e,0xb6,0xee,0xbe,0xc0,0x69,0x55,0x55,0x55,0x80},
    {0x1d,0x57,0x2e,0x7d,0xdc,0x09,0x9c,0xff,0x5a,0x60,0x7f,0xcc,0xe0,0x49,0x4a,0x79,0x9c,0x43,0x4a,0xc1,0xc9,0x6b,0x69,0x80,0xc4,0x7f,0x2a,0xb6,0x68,0xbc,0xd7,0x1f},
    {0x32,0x56,0x69,0xbe,0xca,0xec,0xd5,0xd1,0x1d,0x13,0xbf,0x2a,0x7f,0x22,0xb1,0x05,0xb4,0xab,0xf9,0xfb,0x9a,0x1f,0xc8,0x1c,0x2a,0xa3,0xaf,0x1e,0xae,0x5b,0x66,0x04},
    {0x1a,0x12,0xf6,0x84,0xbd,0xa1,0x2f,0x68,0x4b,0xda,0x12,0xf6,0x84,0xbd,0xa1,0x2f,0x76,0x42,0xb0,0x1a,0xd4,0x61,0xba,0xd2,0x5a,0xd9,0x85,0xb5,0xe3,0x8e,0x38,0xe4},
    {0x1a,0x84,0xd7,0xea,0x8c,0x39,0x6c,0x47,0x13,0x3e,0x3f,0xfd,0x28,0xe7,0xa0,0x95,0x07,0xc9,0xdc,0x17,0x72,0x5c,0xca,0x4a,0xc6,0x7c,0x31,0xd8,0x14,0x0a,0x7d,0xbb},
    {0x3f,0xb9,0x8f,0xf0,0xd2,0xdd,0xca,0xdd,0x30,0x32,0x16,0xcc,0xe1,0xdb,0x9f,0xf1,0x17,0x65,0xe9,0x24,0xf7,0x45,0x93,0x78,0x02,0xe2,0xbe,0x87,0xd2,0x25,0xb2,0x34},
    {0x02,0x5e,0xd0,0x97,0xb4,0x25,0xed,0x09,0x7b,0x42,0x5e,0xd0,0x97,0xb4,0x25,0xed,0x0a,0xc0,0x3e,0x8e,0x13,0x4e,0xb3,0xe4,0x93,0xe5,0x3a,0xb3,0x71,0xc7,0x1c,0x4f},
    {0x0c,0x02,0xc5,0xbc,0xca,0x0e,0x6b,0x7f,0x07,0x90,0xbf,0xb3,0x50,0x6d,0xef,0xb6,0x59,0x41,0xa3,0xa4,0xa9,0x7a,0xa1,0xb3,0x5a,0x28,0x27,0x9b,0x1d,0x1b,0x42,0xae},
    {0x17,0x03,0x3d,0x3c,0x60,0xc6,0x81,0x73,0x57,0x3b,0x3d,0x7f,0x7d,0x68,0x13,0x10,0xd9,0x76,0xbb,0xfa,0xbb,0xc5,0x66,0x1d,0x4d,0x90,0xab,0x82,0x0b,0x12,0x32,0x0a},
    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xec,0xff,0xff,0xfd,0xe5},
};

// Loaded at runtime
static bignum256 s_p, s_q, s_pm2, s_pm1h;
static bignum256 s_iso_a, s_iso_b, s_swu_z;
static bignum256 s_iso_c[13];
static bignum256 s_ts_t, s_ts_z;
static int s_initialized = 0;

void pallas_init(void) {
    if(s_initialized) return;
    bn_read_be(PALLAS_P_BE, &s_p);
    bn_read_be(PALLAS_Q_BE, &s_q);
    bn_read_be(P_MINUS_2_BE, &s_pm2);
    bn_read_be(P_MINUS_1_HALF_BE, &s_pm1h);
    bn_read_be(ISO_A_BE, &s_iso_a);
    bn_read_be(ISO_B_BE, &s_iso_b);
    bn_read_be(SWU_Z_BE, &s_swu_z);
    bn_read_be(TS_T_BE, &s_ts_t);
    bn_read_be(TS_Z_BE, &s_ts_z);
    for(int i = 0; i < 13; i++)
        bn_read_be(ISO_C_BE[i], &s_iso_c[i]);
    s_initialized = 1;
}

const bignum256* pallas_p(void) { return &s_p; }
const bignum256* pallas_q(void) { return &s_q; }

// ============================================================
// Field arithmetic mod p (bit-by-bit reduction for ~254-bit prime)
// ============================================================

// Generic: reduce bignum mod prime (single conditional subtract)
static void fp_reduce(bignum256* x) {
    static bignum256 t;
    if(!bn_is_less(x, &s_p)) {
        bn_subtract(x, &s_p, &t);
        bn_copy(&t, x);
    }
}

void fp_add(bignum256* r, const bignum256* a, const bignum256* b) {
    bn_copy(a, r);
    bn_add(r, b);
    bn_normalize(r);
    fp_reduce(r);
    fp_reduce(r);
}

void fp_sub(bignum256* r, const bignum256* a, const bignum256* b) {
    static bignum256 nb;
    bn_subtract(&s_p, b, &nb);
    fp_add(r, a, &nb);
}

void fp_neg(bignum256* r, const bignum256* a) {
    if(bn_is_zero(a)) {
        bn_zero(r);
    } else {
        bn_subtract(&s_p, a, r);
    }
}

// Fast fp_mul: use bn_multiply_long for O(n) product, then reduce 18-limb result
extern void bn_multiply_long(const bignum256* k, const bignum256* x, uint32_t res[2 * BN_LIMBS]);

void fp_mul(bignum256* r, const bignum256* a, const bignum256* b) {
    static uint32_t res[2 * BN_LIMBS]; // 18 limbs
    static bignum256 tmp;
    bn_multiply_long(a, b, res);

    // Reduce 18-limb (522-bit) result mod p using bit-by-bit Horner from MSB
    bn_zero(r);
    for(int limb = 2 * BN_LIMBS - 1; limb >= 0; limb--) {
        for(int bit = BN_BITS_PER_LIMB - 1; bit >= 0; bit--) {
            bn_lshift(r);
            if(res[limb] & (1u << bit)) {
                r->val[0] |= 1;
            }
            if(r->val[0] >= BN_BASE) bn_normalize(r);
            if(!bn_is_less(r, &s_p)) {
                bn_subtract(r, &s_p, &tmp);
                bn_copy(&tmp, r);
            }
        }
    }
    pallas_yield();
}

void fp_sqr(bignum256* r, const bignum256* a) {
    fp_mul(r, a, a);
}

// r = a^e mod p using square-and-multiply
static void fp_pow(bignum256* r, const bignum256* a, const bignum256* e) {
    static bignum256 base, tmp;
    bn_copy(a, &base);
    bn_one(r);
    for(int i = 0; i < 256; i++) {
        if(bn_testbit(e, i)) {
            fp_mul(&tmp, r, &base);
            bn_copy(&tmp, r);
        }
        fp_mul(&tmp, &base, &base);
        bn_copy(&tmp, &base);
        pallas_yield();
    }
}

// Modular inverse using binary extended GCD (Stein's algorithm)
// Much faster than Fermat's little theorem
void fp_inv(bignum256* r, const bignum256* a) {
    static bignum256 u, v, x1, x2, tmp;
    bn_copy(a, &u);
    bn_copy(&s_p, &v);
    bn_one(&x1);
    bn_zero(&x2);

    while(!bn_is_one(&u) && !bn_is_one(&v)) {
        while(bn_is_even(&u)) {
            bn_rshift(&u);
            if(bn_is_even(&x1)) {
                bn_rshift(&x1);
            } else {
                bn_add(&x1, &s_p);
                bn_normalize(&x1);
                bn_rshift(&x1);
            }
        }
        while(bn_is_even(&v)) {
            bn_rshift(&v);
            if(bn_is_even(&x2)) {
                bn_rshift(&x2);
            } else {
                bn_add(&x2, &s_p);
                bn_normalize(&x2);
                bn_rshift(&x2);
            }
        }
        if(!bn_is_less(&u, &v)) {
            bn_subtract(&u, &v, &tmp);
            bn_copy(&tmp, &u);
            // x1 = x1 - x2 mod p
            if(bn_is_less(&x1, &x2)) {
                bn_add(&x1, &s_p);
                bn_normalize(&x1);
            }
            bn_subtract(&x1, &x2, &tmp);
            bn_copy(&tmp, &x1);
        } else {
            bn_subtract(&v, &u, &tmp);
            bn_copy(&tmp, &v);
            // x2 = x2 - x1 mod p
            if(bn_is_less(&x2, &x1)) {
                bn_add(&x2, &s_p);
                bn_normalize(&x2);
            }
            bn_subtract(&x2, &x1, &tmp);
            bn_copy(&tmp, &x2);
        }
    }

    if(bn_is_one(&u)) {
        bn_copy(&x1, r);
    } else {
        bn_copy(&x2, r);
    }
    fp_reduce(r);
}

int fp_is_square(const bignum256* a) {
    if(bn_is_zero(a)) return 1;
    // Euler criterion: a^((p-1)/2) == 1
    // Still need fp_pow here but it's called less frequently
    static bignum256 r;
    fp_pow(&r, a, &s_pm1h);
    return bn_is_one(&r);
}

int fp_sqrt(bignum256* r, const bignum256* a) {
    if(bn_is_zero(a)) { bn_zero(r); return 1; }
    if(!fp_is_square(a)) return 0;

    // Tonelli-Shanks with S=32
    static bignum256 m, c, t, rr, tmp, b;
    bn_read_uint32(TS_S, &m);
    bn_copy(&s_ts_z, &c);

    // t = a^T mod p
    fp_pow(&t, a, &s_ts_t);

    // r = a^((T+1)/2) mod p
    static bignum256 exp;
    bn_copy(&s_ts_t, &exp);
    bn_addi(&exp, 1);
    bn_normalize(&exp);
    bn_rshift(&exp); // (T+1)/2
    fp_pow(&rr, a, &exp);

    while(1) {
        if(bn_is_one(&t)) {
            bn_copy(&rr, r);
            return 1;
        }
        // Find least i such that t^(2^i) = 1
        uint32_t i = 0;
        bn_copy(&t, &tmp);
        while(!bn_is_one(&tmp)) {
            fp_sqr(&b, &tmp);
            bn_copy(&b, &tmp);
            i++;
        }
        // c = c^(2^(M-i-1))
        uint32_t mm = bn_write_uint32(&m);
        bn_copy(&c, &b);
        for(uint32_t j = 0; j < mm - i - 1; j++) {
            fp_sqr(&tmp, &b);
            bn_copy(&tmp, &b);
        }
        fp_mul(&tmp, &rr, &b);
        bn_copy(&tmp, &rr);
        fp_sqr(&tmp, &b);
        bn_copy(&tmp, &c);
        fp_mul(&tmp, &t, &c);
        bn_copy(&tmp, &t);
        bn_read_uint32(i, &m);
    }
}

void fq_reduce(bignum256* r, const bignum256* a) {
    bn_copy(a, r);
    if(!bn_is_less(r, &s_q)) {
        static bignum256 t;
        bn_subtract(r, &s_q, &t);
        bn_copy(&t, r);
    }
}

// ============================================================
// Point operations on Pallas (Jacobian coordinates)
// ============================================================

void pallas_point_set_infinity(pallas_point* p) {
    bn_zero(&p->x);
    bn_zero(&p->y);
    p->infinity = 1;
}

void pallas_to_jac(pallas_jac* j, const pallas_point* p) {
    bn_copy(&p->x, &j->x);
    bn_copy(&p->y, &j->y);
    bn_one(&j->z);
    if(p->infinity) bn_zero(&j->z);
}

void pallas_from_jac(pallas_point* p, const pallas_jac* j) {
    if(bn_is_zero(&j->z)) {
        pallas_point_set_infinity(p);
        return;
    }
    p->infinity = 0;
    static bignum256 z2, z3, zinv, zinv2, zinv3, tmp;
    fp_inv(&zinv, &j->z);
    fp_sqr(&zinv2, &zinv);
    fp_mul(&zinv3, &zinv2, &zinv);
    fp_mul(&p->x, &j->x, &zinv2);
    fp_mul(&p->y, &j->y, &zinv3);
    (void)z2; (void)z3; (void)tmp;
}

// Double: 2P in Jacobian (a=0)
void pallas_jac_double(pallas_jac* r, const pallas_jac* p) {
    if(bn_is_zero(&p->z)) { bn_zero(&r->z); return; }
    static bignum256 a, b, c, d, e, f;
    fp_sqr(&a, &p->x);       // A = X^2
    fp_sqr(&b, &p->y);       // B = Y^2
    fp_sqr(&c, &b);          // C = B^2

    // D = 2*((X+B)^2 - A - C)
    fp_add(&d, &p->x, &b);
    fp_sqr(&d, &d);
    fp_sub(&d, &d, &a);
    fp_sub(&d, &d, &c);
    fp_add(&d, &d, &d);

    // E = 3*A
    fp_add(&e, &a, &a);
    fp_add(&e, &e, &a);

    fp_sqr(&f, &e);          // F = E^2
    // X3 = F - 2D
    static bignum256 x3, y3, z3;
    fp_sub(&x3, &f, &d);
    fp_sub(&x3, &x3, &d);
    // Y3 = E*(D - X3) - 8C
    fp_sub(&y3, &d, &x3);
    fp_mul(&y3, &e, &y3);
    fp_add(&c, &c, &c); fp_add(&c, &c, &c); fp_add(&c, &c, &c); // 8C
    fp_sub(&y3, &y3, &c);
    // Z3 = 2*Y*Z
    fp_mul(&z3, &p->y, &p->z);
    fp_add(&z3, &z3, &z3);

    bn_copy(&x3, &r->x);
    bn_copy(&y3, &r->y);
    bn_copy(&z3, &r->z);
}

// Mixed add: J + affine P
void pallas_jac_add_mixed(pallas_jac* r, const pallas_jac* j, const pallas_point* p) {
    if(p->infinity) { *r = *j; return; }
    if(bn_is_zero(&j->z)) { pallas_to_jac(r, p); return; }

    static bignum256 z2, u2, s2, h, hh, hhh, rr, v, x3, y3, z3;
    fp_sqr(&z2, &j->z);
    fp_mul(&u2, &p->x, &z2);          // U2 = X2*Z1^2
    static bignum256 z3t;
    fp_mul(&z3t, &z2, &j->z);
    fp_mul(&s2, &p->y, &z3t);         // S2 = Y2*Z1^3

    fp_sub(&h, &u2, &j->x);           // H = U2 - X1
    fp_sub(&rr, &s2, &j->y);          // R = S2 - Y1

    if(bn_is_zero(&h)) {
        if(bn_is_zero(&rr)) {
            // Point doubling case
            pallas_jac_double(r, j);
            return;
        }
        bn_zero(&r->z); // P + (-P) = O
        return;
    }

    fp_sqr(&hh, &h);
    fp_mul(&hhh, &hh, &h);
    fp_mul(&v, &j->x, &hh);

    // X3 = R^2 - HHH - 2*V
    fp_sqr(&x3, &rr);
    fp_sub(&x3, &x3, &hhh);
    fp_sub(&x3, &x3, &v);
    fp_sub(&x3, &x3, &v);

    // Y3 = R*(V - X3) - Y1*HHH
    fp_sub(&y3, &v, &x3);
    fp_mul(&y3, &rr, &y3);
    static bignum256 tmp;
    fp_mul(&tmp, &j->y, &hhh);
    fp_sub(&y3, &y3, &tmp);

    // Z3 = Z1*H
    fp_mul(&z3, &j->z, &h);

    bn_copy(&x3, &r->x);
    bn_copy(&y3, &r->y);
    bn_copy(&z3, &r->z);
}

// Constant-time Montgomery ladder scalar multiplication.
// Always performs both double and add per bit — no secret-dependent branching.
void pallas_point_mul(pallas_point* r, const bignum256* k, const pallas_point* p) {
    static pallas_jac R0, R1, tmp;
    static pallas_point R0_affine;

    // R0 = point at infinity, R1 = P
    bn_zero(&R0.x);
    bn_one(&R0.y);
    bn_zero(&R0.z);
    pallas_to_jac(&R1, p);

    for(int i = 255; i >= 0; i--) {
        uint32_t bit = bn_testbit(k, i);

        // Constant-time swap: if bit==1, swap R0 and R1
        for(int j = 0; j < BN_LIMBS; j++) {
            uint32_t mask = -(uint32_t)bit;
            uint32_t t;
            t = mask & (R0.x.val[j] ^ R1.x.val[j]);
            R0.x.val[j] ^= t; R1.x.val[j] ^= t;
            t = mask & (R0.y.val[j] ^ R1.y.val[j]);
            R0.y.val[j] ^= t; R1.y.val[j] ^= t;
            t = mask & (R0.z.val[j] ^ R1.z.val[j]);
            R0.z.val[j] ^= t; R1.z.val[j] ^= t;
        }

        // R1 = R0 + R1 (always)
        pallas_from_jac(&R0_affine, &R0);
        pallas_jac_add_mixed(&tmp, &R1, &R0_affine);
        bn_copy(&tmp.x, &R1.x);
        bn_copy(&tmp.y, &R1.y);
        bn_copy(&tmp.z, &R1.z);

        // R0 = 2*R0 (always)
        pallas_jac_double(&tmp, &R0);
        bn_copy(&tmp.x, &R0.x);
        bn_copy(&tmp.y, &R0.y);
        bn_copy(&tmp.z, &R0.z);

        // Swap back: if bit==1, swap R0 and R1
        for(int j = 0; j < BN_LIMBS; j++) {
            uint32_t mask = -(uint32_t)bit;
            uint32_t t;
            t = mask & (R0.x.val[j] ^ R1.x.val[j]);
            R0.x.val[j] ^= t; R1.x.val[j] ^= t;
            t = mask & (R0.y.val[j] ^ R1.y.val[j]);
            R0.y.val[j] ^= t; R1.y.val[j] ^= t;
            t = mask & (R0.z.val[j] ^ R1.z.val[j]);
            R0.z.val[j] ^= t; R1.z.val[j] ^= t;
        }

        pallas_yield();
    }
    pallas_from_jac(r, &R0);

    // Wipe ladder state (all static — lives in BSS)
    memzero(&R0, sizeof(R0));
    memzero(&R1, sizeof(R1));
    memzero(&tmp, sizeof(tmp));
    memzero(&R0_affine, sizeof(R0_affine));
}

// ============================================================
// Hash-to-curve: simplified SWU + 3-isogeny
// ============================================================

// (expand_message_xmd and hash_to_field are now inlined in pallas_hash_to_curve)

// Simplified SWU map for iso-Pallas (returns projective X, Y)
static void map_to_curve_swu(const bignum256* u, bignum256* out_x, bignum256* out_y) {
    static bignum256 u2, tv1, tv2, y, tmp;

    // tv1 = Z * u^2
    fp_sqr(&u2, u);
    fp_mul(&tv1, &s_swu_z, &u2);

    // tv2 = tv1^2 + tv1
    fp_sqr(&tv2, &tv1);
    fp_add(&tv2, &tv2, &tv1);

    // x1 = (-B/A) * (1 + 1/(tv2))  if tv2 != 0, else x1 = B/(Z*A)
    static bignum256 x1_num, x1_den;
    if(bn_is_zero(&tv2)) {
        // x1 = B/(Z*A) = -B/(A * (-Z))
        fp_mul(&x1_den, &s_iso_a, &s_swu_z); // A*Z
        bn_copy(&s_iso_b, &x1_num);
    } else {
        // x1_num = -B * (tv2 + 1)
        static bignum256 tv2p1;
        fp_add(&tv2p1, &tv2, &tmp); // reuse tmp for one
        bn_one(&tmp);
        fp_add(&tv2p1, &tv2, &tmp);
        fp_mul(&x1_num, &s_iso_b, &tv2p1);
        fp_neg(&x1_num, &x1_num);
        // x1_den = A * tv2
        fp_mul(&x1_den, &s_iso_a, &tv2);
    }

    // gx1 = x1^3 + A*x1 + B (using x1 = x1_num/x1_den)
    // gx1 = (x1_num^3 + A*x1_num*x1_den^2 + B*x1_den^3) / x1_den^3
    static bignum256 xn2, xn3, xd2, xd3, gx1_num;
    fp_sqr(&xn2, &x1_num);
    fp_mul(&xn3, &xn2, &x1_num);
    fp_sqr(&xd2, &x1_den);
    fp_mul(&xd3, &xd2, &x1_den);

    fp_mul(&tmp, &s_iso_a, &x1_num);
    fp_mul(&tmp, &tmp, &xd2);
    fp_add(&gx1_num, &xn3, &tmp);
    fp_mul(&tmp, &s_iso_b, &xd3);
    fp_add(&gx1_num, &gx1_num, &tmp);

    // Check if gx1 is square: gx1_num * x1_den^3 is square iff gx1 is square
    // (since (a/b) is square iff a*b is square when b != 0)
    fp_mul(&tmp, &gx1_num, &xd3);
    int gx1_square = fp_is_square(&tmp);

    if(gx1_square) {
        // y1 = sqrt(gx1_num / xd3) = sqrt(gx1_num * xd3) / xd3
        // (using sqrt(a/b) = sqrt(a*b) / b)
        fp_mul(&tmp, &gx1_num, &xd3);
        fp_sqrt(&y, &tmp);
        // Adjust sign to match u
        static bignum256 yden;
        bn_copy(&xd3, &yden);
        // y_affine = y / xd3, but we need to check sign against u
        // We output affine x, y directly
        fp_inv(&tmp, &xd3);
        fp_mul(out_x, &x1_num, &tmp); // hm, we need inv of x1_den not xd3 for x
        fp_inv(&tmp, &x1_den);
        fp_mul(out_x, &x1_num, &tmp);
        fp_inv(&tmp, &xd3);
        fp_mul(out_y, &y, &tmp);
    } else {
        // x2 = Z * u^2 * x1 = tv1 * x1
        // x2 = tv1 * x1_num / x1_den
        static bignum256 x2_num;
        fp_mul(&x2_num, &tv1, &x1_num);
        // gx2 = Z^3 * u^6 * gx1, but easier: just compute from x2
        // y2 = sqrt(gx2)
        static bignum256 x2n2, x2n3, gx2_num;
        fp_sqr(&x2n2, &x2_num);
        fp_mul(&x2n3, &x2n2, &x2_num);
        fp_mul(&tmp, &s_iso_a, &x2_num);
        fp_mul(&tmp, &tmp, &xd2);
        fp_add(&gx2_num, &x2n3, &tmp);
        fp_mul(&tmp, &s_iso_b, &xd3);
        fp_add(&gx2_num, &gx2_num, &tmp);

        fp_mul(&tmp, &gx2_num, &xd3);
        fp_sqrt(&y, &tmp);

        fp_inv(&tmp, &x1_den);
        fp_mul(out_x, &x2_num, &tmp);
        fp_inv(&tmp, &xd3);
        fp_mul(out_y, &y, &tmp);
    }

    // Ensure sgn0(y) == sgn0(u)
    int u_sign = u->val[0] & 1;
    int y_sign = out_y->val[0] & 1;
    if(u_sign != y_sign) {
        fp_neg(out_y, out_y);
    }
}

// 3-isogeny map from iso-Pallas to Pallas
static void iso_map(const bignum256* ix, const bignum256* iy, bignum256* ox, bignum256* oy) {
    // x_num = c[0]*x^3 + c[1]*x^2 + c[2]*x + c[3]
    // x_den = x^2 + c[4]*x + c[5]
    // y_num = c[6]*x^3 + c[7]*x^2 + c[8]*x + c[9]
    // y_den = x^3 + c[10]*x^2 + c[11]*x + c[12]
    static bignum256 x2, x3, tmp;
    fp_sqr(&x2, ix);
    fp_mul(&x3, &x2, ix);

    // x_num
    static bignum256 xn;
    fp_mul(&xn, &s_iso_c[0], &x3);
    fp_mul(&tmp, &s_iso_c[1], &x2);
    fp_add(&xn, &xn, &tmp);
    fp_mul(&tmp, &s_iso_c[2], ix);
    fp_add(&xn, &xn, &tmp);
    fp_add(&xn, &xn, &s_iso_c[3]);

    // x_den
    static bignum256 xd;
    fp_add(&xd, &x2, &tmp); // tmp is c[2]*x, recompute
    bn_copy(&x2, &xd);
    fp_mul(&tmp, &s_iso_c[4], ix);
    fp_add(&xd, &xd, &tmp);
    fp_add(&xd, &xd, &s_iso_c[5]);

    // y_num
    static bignum256 yn;
    fp_mul(&yn, &s_iso_c[6], &x3);
    fp_mul(&tmp, &s_iso_c[7], &x2);
    fp_add(&yn, &yn, &tmp);
    fp_mul(&tmp, &s_iso_c[8], ix);
    fp_add(&yn, &yn, &tmp);
    fp_add(&yn, &yn, &s_iso_c[9]);

    // y_den
    static bignum256 yd;
    bn_copy(&x3, &yd);
    fp_mul(&tmp, &s_iso_c[10], &x2);
    fp_add(&yd, &yd, &tmp);
    fp_mul(&tmp, &s_iso_c[11], ix);
    fp_add(&yd, &yd, &tmp);
    fp_add(&yd, &yd, &s_iso_c[12]);

    // ox = xn / xd
    static bignum256 inv;
    fp_inv(&inv, &xd);
    fp_mul(ox, &xn, &inv);

    // oy = iy * yn / yd
    fp_inv(&inv, &yd);
    fp_mul(oy, &yn, &inv);
    fp_mul(oy, oy, iy);
}

// Full hash-to-curve for Pallas
// Matches pasta_curves::hashtocurve::hash_to_field exactly
void pallas_hash_to_curve(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len) {
    pallas_init();

    // pasta_curves uses CHUNKLEN=64, builds DST inline in BLAKE2b input (not personalization)
    // DST = domain_prefix + "-pallas_XMD:BLAKE2b_SSWU_RO_" + len_byte
    // BLAKE2b personalization = 16 zero bytes
    const char* curve_suffix = "-pallas_XMD:BLAKE2b_SSWU_RO_";
    size_t dom_len = strlen(domain);
    size_t suf_len = strlen(curve_suffix);
    size_t dst_total = dom_len + suf_len;
    uint8_t dst_len_byte = (uint8_t)dst_total;

    const uint8_t personal[16] = {0};
    const int CHUNKLEN = 64;
    static uint8_t b0[64], b1[64], b2[64];

    // b_0 = BLAKE2b-64(personal=zeros, Z_pad(128) || msg || I2OSP(128,2) || I2OSP(0,1) || DST || len)
    {
        blake2b_state S;
        blake2b_InitPersonal(&S, CHUNKLEN, personal, 16);
        uint8_t zeros[128] = {0};
        blake2b_Update(&S, zeros, 128);
        blake2b_Update(&S, msg, msg_len);
        uint8_t len_buf[3] = {0, (uint8_t)(CHUNKLEN * 2), 0}; // I2OSP(128,2) || I2OSP(0,1)
        blake2b_Update(&S, len_buf, 3);
        blake2b_Update(&S, (const uint8_t*)domain, dom_len);
        blake2b_Update(&S, (const uint8_t*)curve_suffix, suf_len);
        blake2b_Update(&S, &dst_len_byte, 1);
        blake2b_Final(&S, b0, CHUNKLEN);
    }

    // b_1 = BLAKE2b-64(personal=zeros, b_0 || I2OSP(1,1) || DST || len)
    {
        blake2b_state S;
        blake2b_InitPersonal(&S, CHUNKLEN, personal, 16);
        blake2b_Update(&S, b0, CHUNKLEN);
        uint8_t one = 1;
        blake2b_Update(&S, &one, 1);
        blake2b_Update(&S, (const uint8_t*)domain, dom_len);
        blake2b_Update(&S, (const uint8_t*)curve_suffix, suf_len);
        blake2b_Update(&S, &dst_len_byte, 1);
        blake2b_Final(&S, b1, CHUNKLEN);
    }

    // b_2 = BLAKE2b-64(personal=zeros, (b_0 XOR b_1) || I2OSP(2,1) || DST || len)
    {
        blake2b_state S;
        blake2b_InitPersonal(&S, CHUNKLEN, personal, 16);
        uint8_t xored[64];
        for(int j = 0; j < 64; j++) xored[j] = b0[j] ^ b1[j];
        blake2b_Update(&S, xored, CHUNKLEN);
        uint8_t two = 2;
        blake2b_Update(&S, &two, 1);
        blake2b_Update(&S, (const uint8_t*)domain, dom_len);
        blake2b_Update(&S, (const uint8_t*)curve_suffix, suf_len);
        blake2b_Update(&S, &dst_len_byte, 1);
        blake2b_Final(&S, b2, CHUNKLEN);
    }

    // Hash to field: reverse each 64-byte block, then reduce mod p
    // u0 = from_uniform_bytes(reverse(b1))
    // u1 = from_uniform_bytes(reverse(b2))
    static bignum256 u0, u1;
    {
        static uint8_t rev[64];
        // u0 from b1 (reversed for LE interpretation)
        for(int i = 0; i < 64; i++) rev[i] = b1[63 - i];
        // Reduce 512-bit LE value mod p using bit-by-bit Horner
        static bignum256 tmp;
        bn_zero(&u0);
        for(int bit = 511; bit >= 0; bit--) {
            bn_lshift(&u0);
            if(rev[bit / 8] & (1 << (bit % 8))) u0.val[0] |= 1;
            if(u0.val[0] >= BN_BASE) bn_normalize(&u0);
            if(!bn_is_less(&u0, &s_p)) { bn_subtract(&u0, &s_p, &tmp); bn_copy(&tmp, &u0); }
        }

        // u1 from b2 (reversed)
        for(int i = 0; i < 64; i++) rev[i] = b2[63 - i];
        bn_zero(&u1);
        for(int bit = 511; bit >= 0; bit--) {
            bn_lshift(&u1);
            if(rev[bit / 8] & (1 << (bit % 8))) u1.val[0] |= 1;
            if(u1.val[0] >= BN_BASE) bn_normalize(&u1);
            if(!bn_is_less(&u1, &s_p)) { bn_subtract(&u1, &s_p, &tmp); bn_copy(&tmp, &u1); }
        }
    }

    // Map to iso-Pallas via SWU
    bignum256 ix0, iy0, ix1, iy1;
    map_to_curve_swu(&u0, &ix0, &iy0);
    map_to_curve_swu(&u1, &ix1, &iy1);

    // Apply isogeny to get Pallas points
    bignum256 px0, py0, px1, py1;
    iso_map(&ix0, &iy0, &px0, &py0);
    iso_map(&ix1, &iy1, &px1, &py1);

    // Add the two points
    pallas_point p0, p1;
    bn_copy(&px0, &p0.x); bn_copy(&py0, &p0.y); p0.infinity = 0;
    bn_copy(&px1, &p1.x); bn_copy(&py1, &p1.y); p1.infinity = 0;

    pallas_jac j0, jtmp;
    pallas_to_jac(&j0, &p0);
    pallas_jac_add_mixed(&jtmp, &j0, &p1);
    pallas_from_jac(r, &jtmp);
}

void pallas_group_hash(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len) {
    pallas_hash_to_curve(r, domain, msg, msg_len);
}

// ============================================================
// Sinsemilla hash
// ============================================================

// Sinsemilla S lookup: 1024 precomputed points (64 KB binary)
// S_i = hash_to_curve("z.cash:SinsemillaS")(i.to_le_bytes()), i in 0..1024
// Each entry: 64 bytes (x_le 32 || y_le 32)
//
// Platform integrators can register a lookup callback to load points from
// storage (SD card, flash, etc.) instead of computing them on-the-fly.
// See pallas_set_sinsemilla_lookup() in pallas.h.

static pallas_sinsemilla_lookup_fn s_sinsemilla_lookup = NULL;
static void* s_sinsemilla_lookup_ctx = NULL;

void pallas_set_sinsemilla_lookup(pallas_sinsemilla_lookup_fn fn, void* ctx) {
    s_sinsemilla_lookup = fn;
    s_sinsemilla_lookup_ctx = ctx;
}

void sinsemilla_hash_to_point(
    pallas_point* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits) {
    pallas_init();

    // Q = GroupHash("z.cash:SinsemillaQ", domain)
    pallas_point Q;
    pallas_group_hash(&Q, "z.cash:SinsemillaQ", (const uint8_t*)domain, strlen(domain));

    static pallas_jac acc;
    pallas_to_jac(&acc, &Q);

    bool has_table = (s_sinsemilla_lookup != NULL);

    size_t num_chunks = num_bits / 10;
    for(size_t i = 0; i < num_chunks; i++) {
        pallas_report(35 + (uint8_t)(i * 35 / num_chunks),
            has_table ? "Sinsemilla (fast)..." : "Sinsemilla (slow)...");

        uint32_t chunk = 0;
        for(int b = 0; b < 10; b++) {
            size_t bit_idx = i * 10 + b;
            if(msg_bits[bit_idx / 8] & (1 << (bit_idx % 8))) {
                chunk |= (1 << b);
            }
        }

        pallas_point S;
        bool got = false;
        if(s_sinsemilla_lookup) {
            uint8_t buf[64];
            got = s_sinsemilla_lookup(chunk, buf, s_sinsemilla_lookup_ctx);
            if(got) {
                bn_read_le(buf, &S.x);
                bn_read_le(buf + 32, &S.y);
                S.infinity = 0;
            }
        }
        if(!got) {
            // Slow fallback: compute on-the-fly
            uint8_t chunk_le[4] = {(uint8_t)(chunk & 0xff), (uint8_t)((chunk >> 8) & 0xff), 0, 0};
            pallas_group_hash(&S, "z.cash:SinsemillaS", chunk_le, 4);
        }

        static pallas_jac tmp;
        pallas_jac_add_mixed(&tmp, &acc, &S);
        pallas_point acc_affine;
        pallas_from_jac(&acc_affine, &acc);
        pallas_jac_add_mixed(&tmp, &tmp, &acc_affine);
        acc = tmp;
    }

    pallas_from_jac(r, &acc);
}

void sinsemilla_short_commit(
    bignum256* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits,
    const bignum256* rcm) {
    pallas_init();

    // S = SinsemillaHashToPoint(domain + "-M", M)
    char m_domain[128] = {0};
    strcpy(m_domain, domain);
    strcat(m_domain, "-M");
    static pallas_point S;
    sinsemilla_hash_to_point(&S, m_domain, msg_bits, num_bits);

    // R = hash_to_curve(domain + "-r")(&[])
    char r_domain[128] = {0};
    strcpy(r_domain, domain);
    strcat(r_domain, "-r");
    static pallas_point R;
    pallas_hash_to_curve(&R, r_domain, (const uint8_t*)"", 0);

    // commit = S + [rcm] * R
    static pallas_point rcm_R;
    pallas_point_mul(&rcm_R, rcm, &R);

    static pallas_jac j;
    pallas_to_jac(&j, &S);
    static pallas_jac tmp;
    pallas_jac_add_mixed(&tmp, &j, &rcm_R);

    static pallas_point commit;
    pallas_from_jac(&commit, &tmp);

    // Extract x-coordinate
    bn_copy(&commit.x, r);
}
