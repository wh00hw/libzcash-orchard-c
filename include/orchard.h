#pragma once

#include <stdint.h>
#include <stddef.h>

// ZIP-32 Orchard master key derivation from BIP39 seed
// BLAKE2b-512("ZcashIP32Orchard", seed) -> (sk, chaincode)
void orchard_master_key(
    const uint8_t seed[64],
    uint8_t sk_out[32],
    uint8_t chaincode_out[32]);

// ZIP-32 Orchard hardened child key derivation
// index must be >= 0x80000000 (hardened)
void orchard_child_key(
    const uint8_t sk_parent[32],
    const uint8_t chaincode_parent[32],
    uint32_t index,
    uint8_t sk_out[32],
    uint8_t chaincode_out[32]);

// Derive Orchard key components from account spending key
// ask = spend authorizing key (scalar mod q)
// nk  = nullifier deriving key (base field element mod p)
// rivk = commitment randomness (scalar mod q)
void orchard_derive_keys(
    const uint8_t sk[32],
    uint8_t ask_out[32],
    uint8_t nk_out[32],
    uint8_t rivk_out[32]);

// Full derivation: seed -> account spending key
// Uses path: m_Orchard / 32' / coin_type' / account'
// coin_type: 133 for mainnet, 1 for testnet
void orchard_derive_account_sk(
    const uint8_t seed[64],
    uint32_t coin_type,
    uint32_t account,
    uint8_t sk_out[32]);

// Derive default Orchard Unified Address from seed
// hrp: "u" for mainnet, "utest" for testnet
// coin_type: 133 for mainnet, 1 for testnet
// ua_out must be at least 256 bytes
// d_out (optional, 11 bytes) and pk_d_out (optional, 32 bytes) for caching
// Returns string length, or 0 on error
int orchard_derive_unified_address(
    const uint8_t seed[64],
    uint32_t coin_type,
    uint32_t account,
    const char* hrp,
    char* ua_out,
    size_t ua_out_len,
    uint8_t* d_out,
    uint8_t* pk_d_out);

/**
 * Encode a (d, pk_d) pair as an Orchard-only Unified Address (ZIP-316).
 *
 * Used by the on-device signer to render an arbitrary recipient (one
 * extracted from a PCZT, NOT necessarily belonging to the device's own
 * key) so the user can verify it on-screen before authorizing the
 * signature. This is the encoding step that closes the "blind signing"
 * gap together with on-device cmx verification.
 *
 *   raw_ua = 0x03 || 43 || d || pk_d || hrp_padded_to_16
 *   ua = bech32m(hrp, F4Jumble(raw_ua))
 *
 * @param d           recipient diversifier (11 bytes)
 * @param pk_d        recipient transmission key (32 bytes, repr_P)
 * @param hrp         "u" for mainnet, "utest" for testnet
 * @param ua_out      output buffer for the bech32m string (must be >= 200 B)
 * @param ua_out_len  size of ua_out
 * @return string length on success, 0 on error
 */
int orchard_encode_ua_raw(
    const uint8_t d[11],
    const uint8_t pk_d[32],
    const char* hrp,
    char* ua_out,
    size_t ua_out_len);

// F4Jumble encoding / decoding (ZIP-316)
void f4jumble(uint8_t* data, size_t len);
void f4jumble_inv(uint8_t* data, size_t len);

// FF1-AES-256 encrypt 11 bytes (for diversifier derivation)
void ff1_aes256_encrypt(const uint8_t key[32], const uint8_t in[11], uint8_t out[11]);

/**
 * Compute the Orchard NoteCommitment x-coordinate (cmx) for an output note.
 *
 *   cmx = Extract_P(NoteCommit_rcm^Orchard(g_d, pk_d, v, rho, psi))
 *
 * with rcm = ToScalar(PRF_expand(rseed, [0x05] || rho))
 *      psi = ToBase(PRF_expand(rseed, [0x09] || rho))
 *
 * defined in the Zcash protocol specification, §§ 4.7.3 and 5.4.8.4.
 *
 * Used by the on-device Orchard signer to verify that the cmx field of a
 * streamed action commits to the (recipient, value, rseed) the companion
 * claims it commits to. A hostile companion that tries to substitute a
 * different recipient must produce a cmx that mismatches the device's
 * recomputation, which the signer detects and rejects.
 *
 * @param d        recipient diversifier (11 bytes), as encoded in the
 *                 raw Orchard payment-address form `d || pk_d`
 * @param pk_d     recipient transmission key (32 bytes), repr_P-encoded
 *                 (Pallas point compressed: x_le with y_lsb in bit 255)
 * @param value    output note value in zatoshis
 * @param rho      action's nullifier (32 bytes); used as rho for the
 *                 output note's NoteCommit input (Orchard's split-action
 *                 design re-uses the action nullifier)
 * @param rseed    random seed for the output note (32 bytes); must be
 *                 the value the constructor used to derive psi/rcm
 * @param cmx_out  32-byte output, x-coordinate of NoteCommitment in LE form
 */
void orchard_compute_cmx(
    const uint8_t d[11],
    const uint8_t pk_d[32],
    uint64_t value,
    const uint8_t rho[32],
    const uint8_t rseed[32],
    uint8_t cmx_out[32]);
