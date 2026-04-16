/**
 * secp256k1 curve operations + ECDSA signing for Zcash transparent.
 *
 * Reuses the existing bignum256 (29-bit limbs, fork of trezor-crypto).
 * Point arithmetic: short Weierstrass y^2 = x^3 + 7, Jacobian coordinates.
 * Signing: ECDSA with RFC 6979 deterministic nonce (HMAC-SHA256).
 *
 * No precomputed tables — uses constant-time Montgomery ladder.
 * Stack: ~600 bytes peak. No heap. Suitable for ESP32.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "bignum.h"

/* ── Point types ─────────────────────────────────────────────────── */

typedef struct {
    bignum256 x, y, z;  /* Jacobian: affine = (X/Z^2, Y/Z^3) */
} secp256k1_jac;

typedef struct {
    bignum256 x, y;
    int infinity;
} secp256k1_point;

/* ── Curve constants ─────────────────────────────────────────────── */

const bignum256 *secp256k1_p(void);   /* field prime */
const bignum256 *secp256k1_n(void);   /* group order */
const bignum256 *secp256k1_Gx(void);  /* generator x */
const bignum256 *secp256k1_Gy(void);  /* generator y */

/* ── Point operations ────────────────────────────────────────────── */

void secp256k1_point_set_infinity(secp256k1_point *p);
void secp256k1_to_jac(secp256k1_jac *j, const secp256k1_point *p);
void secp256k1_from_jac(secp256k1_point *p, const secp256k1_jac *j);
void secp256k1_jac_double(secp256k1_jac *r, const secp256k1_jac *p);
void secp256k1_jac_add_mixed(secp256k1_jac *r, const secp256k1_jac *p, const secp256k1_point *q);

/**
 * Scalar multiplication: r = k * p (constant-time Montgomery ladder).
 * k is a 256-bit scalar, p is an affine point.
 */
void secp256k1_point_mul(secp256k1_point *r, const bignum256 *k, const secp256k1_point *p);

/* ── Key operations ──────────────────────────────────────────────── */

/**
 * Derive compressed public key (33 bytes: 0x02/0x03 || x) from 32-byte secret key.
 * Returns 0 on success, -1 if sk is zero or >= order.
 */
int secp256k1_get_public_key33(const uint8_t sk[32], uint8_t pubkey[33]);

/* ── ECDSA signing ───────────────────────────────────────────────── */

/**
 * Sign a 32-byte digest with ECDSA (RFC 6979 deterministic nonce).
 *
 * @param sk        32-byte secret key
 * @param digest    32-byte message digest (e.g., sighash)
 * @param sig_out   64-byte output: r[32] || s[32] (compact, NOT DER)
 * @return 0 on success, -1 on error
 *
 * The signature is normalized to low-S form (s <= n/2) per BIP-62.
 */
int secp256k1_ecdsa_sign_digest(const uint8_t sk[32], const uint8_t digest[32],
                                 uint8_t sig_out[64]);

/**
 * Encode a 64-byte compact signature (r||s) to DER format.
 *
 * @param compact   64-byte input: r[32] || s[32]
 * @param der_out   Output buffer (max 72 bytes)
 * @return DER-encoded length, or 0 on error
 */
size_t secp256k1_sig_to_der(const uint8_t compact[64], uint8_t *der_out);
