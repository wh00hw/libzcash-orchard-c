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

// F4Jumble encoding (ZIP-316)
void f4jumble(uint8_t* data, size_t len);

// FF1-AES-256 encrypt 11 bytes (for diversifier derivation)
void ff1_aes256_encrypt(const uint8_t key[32], const uint8_t in[11], uint8_t out[11]);
