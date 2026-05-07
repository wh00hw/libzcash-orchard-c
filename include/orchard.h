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

/**
 * Decode a Unified Address bech32m string and extract its Orchard receiver.
 *
 * Used by the on-device signer to compare a companion-supplied "intended
 * recipient" UA against the recipients actually signed for, matching the
 * defence in `orchard_signer_recipient_matches_any()`.
 *
 * Steps (ZIP-316 §3):
 *   1. bech32m decode of `ua_str` (validates checksum and HRP charset);
 *   2. 5-bit → 8-bit repacking;
 *   3. F4Jumble inverse on the entire repacked buffer;
 *   4. strip the trailing 16-byte HRP padding and verify it matches `expected_hrp`;
 *   5. walk the receivers `(typecode_compact || length_compact || data)*`
 *      and copy out the Orchard receiver (typecode == 0x03, length == 43).
 *
 * The function does NOT enforce typecode ascending order or duplicate-
 * receiver checks beyond what is necessary to find the Orchard receiver,
 * because the canonical encoding has already been signed off on by
 * librustzcash on the host side; the device only needs to verify that
 * SOME Orchard receiver in the UA matches the action it is about to sign.
 *
 * @param ua_str            UA bech32m string (NUL-terminated)
 * @param expected_hrp      HRP the UA must use ("u" or "utest"); compared
 *                          both against bech32m's HRP and the trailing pad
 * @param orchard_recipient_out
 *                          43-byte buffer for `d || pk_d` on success
 *
 * @return  0 on success
 *         -1 if bech32m decode fails (bad checksum, wrong charset)
 *         -2 if HRP mismatch (decoded HRP != expected_hrp, or pad mismatch)
 *         -3 if F4Jumble length is out of range (UA too short or too long)
 *         -4 if no Orchard receiver (typecode 0x03) is present in the UA
 *         -5 if the UA structure is malformed (truncated receiver header)
 */
int orchard_decode_ua_orchard_receiver(
    const char* ua_str,
    const char* expected_hrp,
    uint8_t orchard_recipient_out[43]);

// F4Jumble encoding / decoding (ZIP-316)
void f4jumble(uint8_t* data, size_t len);
void f4jumble_inv(uint8_t* data, size_t len);

/**
 * Sign a 32-byte message with a Pallas identity scalar, using a 16-byte
 * BLAKE2b personalization tag for cross-protocol domain separation.
 *
 * Computes:
 *     digest = BLAKE2b-256(personal=personal_16, msg)
 *     (sig, rk) = redpallas_sign(scalar, alpha=0, digest)
 *
 * Because alpha = 0:
 *   - rsk = scalar (after the y-bit-zero ak normalization that
 *     redpallas_sign applies internally),
 *   - rk  = [scalar]·G_spend in canonical encoding,
 *
 * so the returned `rk_out` equals the device's identity pubkey (the same
 * value `redpallas_derive_ak(scalar, &)` would produce). A verifier with
 * a pinned copy of that pubkey can check both rk equality (no device
 * substitution) and the RedPallas signature (no replay/forgery) against
 * the same `digest`, which is recomputed from the public `personal_16` and
 * `msg` values.
 *
 * Designed for hardware-wallet attestation flows but reusable for any
 * "prove I have this key" challenge-response. The library is MCU-agnostic
 * — every firmware (ESP32, STM32, Nordic, Ledger BOLOS, future targets)
 * loads `scalar` from its own persistent storage and calls this function.
 *
 * The HWP attestation protocol uses the personal tag "ZcashHWAttestV1!"
 * (defined as `HWP_ATTEST_PERSONAL` in `hwp.h`). Any other protocol that
 * builds on top of this primitive MUST use a distinct 16-byte tag.
 *
 * @param scalar       32-byte Pallas identity scalar (caller's secret)
 * @param personal_16  16-byte BLAKE2b personalization, distinct per protocol
 * @param msg          32-byte message to be domain-separated and signed
 * @param sig_out      64-byte RedPallas signature
 * @param rk_out       32-byte randomized key (= canonical pubkey of `scalar`)
 *
 * @return 0 on success, non-zero on signing failure (unchanged from
 *         redpallas_sign's return convention)
 */
int orchard_sign_with_personal(
    const uint8_t scalar[32],
    const uint8_t personal_16[16],
    const uint8_t msg[32],
    uint8_t sig_out[64],
    uint8_t rk_out[32]);

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
