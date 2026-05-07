#pragma once

/**
 * Authenticated encryption: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC).
 *
 * Used by hardware-wallet firmware to seal the BIP-39 mnemonic / Pallas
 * spending scalars under a PIN-derived key (audit H-5).
 *
 * The 64-byte master key is split internally:
 *   - first  32 bytes -> AES-256-CTR encryption key
 *   - second 32 bytes -> HMAC-SHA256 authentication key
 *
 * Encrypt-then-MAC (with AES-CTR) is a well-understood construction with
 * minimal new code on top of what libzcash-orchard-c already ships:
 * `aes_ct_256_*` (audit H-3 constant-time AES) and `hmac_sha256` already
 * existed. No new third-party crypto is introduced.
 *
 * The HMAC-SHA256 covers, in order:
 *   nonce (16 bytes) || aad_len (8 LE) || aad || ct_len (8 LE) || ct
 * The two length prefixes are essential to prevent length-extension /
 * concatenation ambiguities that would otherwise let an attacker re-
 * partition the AAD/ciphertext boundary.
 *
 * Nonce: 16 bytes. The caller MUST never reuse a nonce with the same key.
 * For wallet-sealing where each unseal happens at boot and produces a new
 * sealed blob on save, fresh-random per save is sufficient.
 *
 * The AEAD primitive is fully MCU-agnostic; it is the foundation under
 * which firmware (ESP32, Flipper Zero, Ledger BOLOS, future targets)
 * stores PIN-protected secrets without re-implementing crypto.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AEAD_NONCE_SIZE  16
#define AEAD_TAG_SIZE    32
#define AEAD_KEY_SIZE    64  /* AES-CTR (32) || HMAC-SHA256 (32) */

/**
 * Seal a plaintext under the master key.
 *
 *   ct = AES-256-CTR(key[0..32], nonce, plaintext)
 *   tag = HMAC-SHA256(key[32..64], nonce || u64_le(aad_len) || aad
 *                                       || u64_le(ct_len)  || ct)
 *
 * Buffers may NOT alias each other. plaintext and ciphertext may be
 * the same buffer (in-place encryption is supported).
 *
 * @param key       64-byte AEAD key
 * @param nonce     16-byte nonce, must be fresh per seal under the same key
 * @param aad       associated data (covered by tag, not encrypted; may be NULL)
 * @param aad_len   length of aad in bytes
 * @param pt        plaintext input (may equal ct for in-place)
 * @param pt_len    plaintext length in bytes
 * @param ct        ciphertext output (pt_len bytes)
 * @param tag_out   32-byte authentication tag
 *
 * @return 0 on success
 */
int aead_aes256_ctr_hmac_seal(
    const uint8_t key[AEAD_KEY_SIZE],
    const uint8_t nonce[AEAD_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag_out[AEAD_TAG_SIZE]);

/**
 * Unseal a ciphertext + tag under the master key. The MAC is verified
 * BEFORE decrypting (Encrypt-then-MAC convention) so a wrong-PIN
 * attempt never produces plaintext bytes for an attacker.
 *
 * Buffers may NOT alias each other except for ct == pt (in-place
 * decryption is supported AFTER tag verification has succeeded).
 *
 * @return 0 on success (tag matched, plaintext written),
 *        -1 on tag mismatch (plaintext NOT written; the function
 *        returns before the decryption step)
 */
int aead_aes256_ctr_hmac_unseal(
    const uint8_t key[AEAD_KEY_SIZE],
    const uint8_t nonce[AEAD_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[AEAD_TAG_SIZE],
    uint8_t* pt);

/**
 * Convenience: derive a 64-byte AEAD master key from a user PIN via
 * PBKDF2-HMAC-SHA512 with the requested iteration count.
 *
 * Recommended iterations: enough to take ~1 second on the slowest target
 * MCU. On ESP32-S2 @ 240 MHz, ~150 000 iterations of PBKDF2-HMAC-SHA512
 * gives roughly 1 s. On Flipper Zero (STM32WB55 @ 64 MHz) the same wall-
 * clock target is ~50 000 iterations.
 *
 * @param pin        user PIN bytes (any encoding the firmware uses; the
 *                   library treats it as opaque bytes)
 * @param pin_len    length of pin
 * @param salt       random salt, generated once per wallet, persisted
 *                   alongside the sealed blob (it is NOT secret)
 * @param salt_len   typically 16 bytes
 * @param iterations PBKDF2 iteration count
 * @param key_out    AEAD_KEY_SIZE-byte derived key
 */
void wallet_pin_kdf(
    const uint8_t* pin, size_t pin_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t key_out[AEAD_KEY_SIZE]);

/**
 * Self-test: encrypt-then-MAC roundtrip against a hard-coded test
 * vector, then a tag-tampering check. Returns 1 on full success,
 * 0 on any mismatch. Intended to be called once at firmware boot.
 */
int aead_self_test(void);

#ifdef __cplusplus
}
#endif
