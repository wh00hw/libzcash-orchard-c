/*
 * Base58 + Base58Check encoder, scoped to Zcash transparent address
 * rendering on constrained devices.
 *
 * Base58Check is used here for one purpose: convert a transparent
 * output's script_pubkey (P2PKH or P2SH) back to the t-address string
 * the user typed at the companion, so the device can display the
 * actual destination during the per-output review. The transparent
 * output stream is bound to the signature via the ZIP-244 transparent
 * digest, but seeing the destination on the trusted screen is the
 * non-blind-signing invariant for transparent recipients.
 *
 * Mainnet P2PKH version bytes: 0x1C 0xB8 → "t1..."
 * Mainnet P2SH  version bytes: 0x1C 0xBD → "t3..."
 * Testnet P2PKH version bytes: 0x1D 0x25 → "tm..."
 * Testnet P2SH  version bytes: 0x1C 0xBA → "t2..."
 */
#ifndef BASE58_H
#define BASE58_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode `len` raw bytes as Base58Check (input || sha256d(input)[:4]).
 * Writes a NUL-terminated string to `out` and returns the number of
 * characters (excluding NUL), or 0 if `out_cap` is too small or the
 * payload is too large for the internal scratch buffer (>96 bytes). */
size_t base58check_encode(const uint8_t* payload, size_t len,
                          char* out, size_t out_cap);

/* Convert a transparent-output script_pubkey to a Zcash t-address
 * string. Recognises:
 *   P2PKH: OP_DUP OP_HASH160 0x14 <20:pkh> OP_EQUALVERIFY OP_CHECKSIG  (25 B)
 *   P2SH:  OP_HASH160 0x14 <20:sh> OP_EQUAL                            (23 B)
 * Returns the number of chars written (typically 35) on success, or 0
 * if the script is non-standard. `out_cap` must be ≥ 40 bytes. */
size_t script_to_taddr(const uint8_t* script, size_t script_len,
                       bool testnet, char* out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* BASE58_H */
