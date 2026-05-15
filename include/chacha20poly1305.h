/**
 * ChaCha20-Poly1305 AEAD (RFC 7539).
 *
 * Added to libzcash-orchard-c for on-device verification of the Orchard
 * note encryption (`enc_ciphertext` and `out_ciphertext`), which uses
 * ChaCha20-Poly1305 with IV = 0 over the unencrypted note plaintext.
 *
 * The pre-existing `aead.h` primitive in this library is AES-256-CTR +
 * HMAC-SHA256 (for PIN-sealed wallet storage). It is NOT interchangeable:
 * Orchard uses ChaCha20-Poly1305 specifically and a wrong primitive would
 * never match the on-chain ciphertext byte-for-byte.
 *
 * Implementation choices:
 *   - Pure C, no platform-specific intrinsics — every supported MCU runs
 *     the same path. Performance on a 240 MHz Cortex-class core is
 *     ample for the 564 / 80-byte Orchard plaintexts (sub-millisecond).
 *   - Constant time across secret-dependent inputs: the inner ChaCha20
 *     round function uses only `+`, `^`, and rotates on 32-bit words —
 *     no table lookups, no secret-dependent branches. Poly1305 evaluates
 *     a fixed polynomial modulo 2^130 - 5 with secret-independent
 *     control flow; the final tag comparison must be performed by the
 *     caller with `ct_memequal` (the decrypt path here does that).
 *   - No heap. All state is on the caller's stack or in the small
 *     fixed-size context structs declared below.
 *
 * Tested against the RFC 7539 §A.5 reference vector + an Orchard note
 * encryption fixture in `tests/test_chacha20poly1305.c`.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA20_KEY_SIZE      32
#define CHACHA20_NONCE_SIZE    12
#define CHACHA20_BLOCK_SIZE    64
#define POLY1305_KEY_SIZE      32
#define POLY1305_TAG_SIZE      16
#define CHACHA20POLY1305_TAG_SIZE  POLY1305_TAG_SIZE

/**
 * Encrypt `pt_len` bytes of plaintext into `ct` and write the 16-byte
 * authentication tag into `tag_out`. `aad` is covered by the tag but
 * not encrypted; pass NULL / 0 if empty (which is the Orchard case).
 *
 * Buffers may not alias except that `pt == ct` (in-place) is allowed.
 * The nonce MUST be unique per (key, message); reusing a nonce under
 * the same key catastrophically breaks confidentiality and integrity.
 * In the Orchard usage `nonce` is the all-zero 12-byte buffer because
 * the key itself is per-note (derived from a fresh `esk`).
 */
void chacha20poly1305_encrypt(
    const uint8_t key[CHACHA20_KEY_SIZE],
    const uint8_t nonce[CHACHA20_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag_out[CHACHA20POLY1305_TAG_SIZE]);

/**
 * Decrypt `ct_len` bytes of ciphertext into `pt` after verifying the
 * 16-byte authentication tag. Returns 0 on success, -1 if the tag does
 * not match (in which case `pt` is NOT written — the tag check runs
 * before decryption).
 *
 * The tag comparison is constant-time.
 */
int chacha20poly1305_decrypt(
    const uint8_t key[CHACHA20_KEY_SIZE],
    const uint8_t nonce[CHACHA20_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
    uint8_t* pt);

/**
 * Self-test: encrypt-then-decrypt the RFC 7539 §A.5 reference vector
 * (the "Ladies and Gentlemen" plaintext) and verify byte-for-byte.
 * Returns 1 on full success, 0 on any mismatch.
 *
 * Intended to be called once at firmware boot before any Orchard note
 * verification, to catch a corrupted flash image or compiler regression
 * before it can produce a wrong ciphertext recomputation.
 */
int chacha20poly1305_self_test(void);

#ifdef __cplusplus
}
#endif
