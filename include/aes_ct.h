#pragma once

/**
 * Constant-time AES-256 single-block encryption (ECB).
 *
 * The previous implementation in src/aes/ is the table-driven Brian Gladman
 * library. T-table AES leaks the round-key bytes via cache-timing on any
 * CPU with data caches: an adversary who can observe memory-bus contention
 * (other process on the same SoC, EM probe, USB-attached side-channel
 * snooper) recovers the AES key from a few hundred encryptions.
 *
 * This module replaces the cache-leaky implementation with a fully
 * constant-time variant. The S-box is implemented as a linear scan over
 * all 256 entries with a constant-time mask: every byte of the S-box
 * table is touched on every call, regardless of input. This eliminates
 * cache-timing dependency at the cost of a ~256x slowdown per S-box.
 *
 * Used by orchard.c::ff1_aes256_encrypt for diversifier derivation.
 * FF1 runs ONCE per account creation (then the address is cached in
 * NVS), so the slowdown is irrelevant in practice.
 *
 * Audit: docs/security-audit/01-crypto-c-primitives.md H-3.
 *
 * Optionally, the firmware may register a hardware-AES backend via
 * orchard_set_aes256_encrypt(); when set, it overrides the software
 * fallback. ESP32-S2 has a hardware AES accelerator that is constant-
 * time by construction; using it preserves security and avoids the
 * software overhead.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Round-key schedule for AES-256: 15 round keys of 16 bytes each. */
typedef struct {
    uint8_t rk[15][16];
} aes_ct_256_ctx;

/**
 * Compute the AES-256 key schedule.
 *
 * @param key  32-byte master key (AES-256)
 * @param ctx  output context with the 15 round keys
 */
void aes_ct_256_keysched(const uint8_t key[32], aes_ct_256_ctx* ctx);

/**
 * Encrypt a single 16-byte block under the precomputed key schedule.
 * Constant-time: same memory access pattern and instruction sequence
 * for every input.
 *
 * @param ctx  key schedule produced by aes_ct_256_keysched
 * @param in   16-byte plaintext
 * @param out  16-byte ciphertext (may alias in)
 */
void aes_ct_256_ecb_encrypt(const aes_ct_256_ctx* ctx,
                             const uint8_t in[16],
                             uint8_t out[16]);

/**
 * Convenience wrapper: schedule the key, encrypt one block, wipe the
 * schedule. Use when only a single block needs to be encrypted under a
 * given key (the typical FF1 inner loop allocates the schedule once
 * and reuses it; that path uses the explicit two-step API above).
 *
 * @param key  32-byte AES-256 key
 * @param in   16-byte plaintext
 * @param out  16-byte ciphertext (may alias in)
 */
void aes_ct_256_encrypt_single(const uint8_t key[32],
                                const uint8_t in[16],
                                uint8_t out[16]);

/**
 * Optional hardware-AES override. Platforms with a constant-time AES
 * accelerator (e.g. ESP32-S2 / S3 crypto peripheral, ARMv8 AES instructions)
 * can register their own implementation here. When set, the override is
 * used by every aes_ct_256_* function above; when NULL, the software
 * fallback is used.
 *
 * The override MUST be constant-time. The library does no detection;
 * caller is responsible for ensuring the registered backend qualifies.
 *
 * @param fn   encryption function: encrypt(ctx_user, key[32], in[16], out[16])
 * @param ctx  opaque context passed back to fn (e.g. a hardware handle)
 */
typedef void (*aes_ct_256_encrypt_fn)(void* ctx_user,
                                       const uint8_t key[32],
                                       const uint8_t in[16],
                                       uint8_t out[16]);

void aes_ct_256_set_override(aes_ct_256_encrypt_fn fn, void* ctx_user);

/**
 * Self-test: encrypts the FIPS-197 §C.3 known-answer vector and verifies
 * the result. Returns 1 on success, 0 on mismatch. Call once at firmware
 * boot before any real signing.
 *
 *   key  = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
 *   in   = 00112233445566778899aabbccddeeff
 *   out  = 8ea2b7ca516745bfeafc49904b496089
 */
int aes_ct_256_self_test(void);

#ifdef __cplusplus
}
#endif
