#pragma once

#include <stdint.h>
#include <stddef.h>
#include "bignum.h"

// Pallas curve: y^2 = x^3 + 5
// Field modulus p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
// Group order  q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

typedef struct {
    bignum256 x, y, z; // Jacobian coordinates: affine = (X/Z^2, Y/Z^3)
} pallas_jac;

typedef struct {
    bignum256 x, y;
    int infinity;
} pallas_point;

// Progress callback for long operations
typedef void (*pallas_progress_cb)(uint8_t percent, const char* label, void* ctx);
void pallas_set_progress_cb(pallas_progress_cb cb, void* ctx);

void pallas_report(uint8_t pct, const char* label);

// Yield callback — set this on constrained platforms to prevent watchdog reset.
// The callback is invoked periodically during long computations.
void pallas_set_yield_cb(void (*cb)(void* ctx), void* ctx);

// Sinsemilla S-table lookup callback (optional, for performance).
// If registered, called with index (0..1023). Must write 64 bytes
// (x_le[32] || y_le[32]) into buf_out. Return true on success.
// When not set (or returns false), points are computed on-the-fly.
typedef bool (*pallas_sinsemilla_lookup_fn)(uint32_t index, uint8_t buf_out[64], void* ctx);
void pallas_set_sinsemilla_lookup(pallas_sinsemilla_lookup_fn fn, void* ctx);

// Must call before any Pallas operations
void pallas_init(void);

// Field arithmetic mod p (Pallas base field)
void fp_add(bignum256* r, const bignum256* a, const bignum256* b);
void fp_sub(bignum256* r, const bignum256* a, const bignum256* b);
void fp_mul(bignum256* r, const bignum256* a, const bignum256* b);
void fp_sqr(bignum256* r, const bignum256* a);
void fp_neg(bignum256* r, const bignum256* a);
void fp_inv(bignum256* r, const bignum256* a);
int fp_sqrt(bignum256* r, const bignum256* a);
int fp_is_square(const bignum256* a);

// Scalar field arithmetic (mod q)
void fq_reduce(bignum256* r, const bignum256* a);

// Point operations on Pallas
void pallas_point_set_infinity(pallas_point* p);
void pallas_to_jac(pallas_jac* j, const pallas_point* p);
void pallas_from_jac(pallas_point* p, const pallas_jac* j);
void pallas_jac_double(pallas_jac* r, const pallas_jac* p);
void pallas_jac_add_mixed(pallas_jac* r, const pallas_jac* p, const pallas_point* q);
void pallas_point_mul(pallas_point* r, const bignum256* k, const pallas_point* p);

// Hash to curve
void pallas_hash_to_curve(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len);
void pallas_group_hash(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len);

// Sinsemilla
void sinsemilla_hash_to_point(
    pallas_point* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits);

void sinsemilla_short_commit(
    bignum256* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits,
    const bignum256* rcm);

// Access to the Pallas prime for external use
const bignum256* pallas_p(void);
const bignum256* pallas_q(void);

