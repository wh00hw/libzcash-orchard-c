/**
 * BIP-32 hierarchical deterministic key derivation for transparent (secp256k1).
 *
 * Derives keys along the path: m / purpose' / coin_type' / account' / change / index
 * For Zcash transparent: m / 44' / 133' / 0' / 0 / 0
 *
 * Uses HMAC-SHA512 as per BIP-32 specification.
 * No heap allocation. Stack: ~200 bytes peak.
 */
#pragma once
#include <stdint.h>

/**
 * Extended private key (BIP-32).
 * key = 32-byte secp256k1 secret key
 * chaincode = 32-byte chain code for child derivation
 */
typedef struct {
    uint8_t key[32];
    uint8_t chaincode[32];
} Bip32ExtKey;

/**
 * Derive the BIP-32 master key from a BIP-39 seed.
 *
 * @param seed      64-byte BIP-39 seed
 * @param master    Output master extended key
 */
void bip32_master_key(const uint8_t seed[64], Bip32ExtKey *master);

/**
 * Derive a BIP-32 child key (hardened or normal).
 *
 * For hardened derivation, set bit 31 of index: index | 0x80000000.
 *
 * @param parent    Parent extended key
 * @param index     Child index (bit 31 = hardened flag)
 * @param child     Output child extended key
 * @return 0 on success, -1 if derived key is invalid
 */
int bip32_derive_child(const Bip32ExtKey *parent, uint32_t index, Bip32ExtKey *child);

/**
 * Derive the transparent spending key for Zcash.
 * Path: m / 44' / coin_type' / 0' / 0 / 0
 *
 * @param seed       64-byte BIP-39 seed
 * @param coin_type  133 (mainnet) or 1 (testnet)
 * @param sk_out     32-byte secp256k1 secret key output
 * @param pubkey_out 33-byte compressed public key output (or NULL to skip)
 * @return 0 on success, -1 on error
 */
int bip32_derive_transparent_sk(const uint8_t seed[64], uint32_t coin_type,
                                 uint8_t sk_out[32], uint8_t pubkey_out[33]);
