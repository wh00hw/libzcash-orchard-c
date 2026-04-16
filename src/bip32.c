/**
 * BIP-32 hierarchical deterministic key derivation.
 * HMAC-SHA512 based, for secp256k1 transparent keys.
 */
#include "bip32.h"
#include "secp256k1.h"
#include "hmac.h"
#include "memzero.h"
#include <string.h>

/* BIP-32 uses "Bitcoin seed" as the HMAC key for master derivation */
static const uint8_t BIP32_SEED_KEY[] = "Bitcoin seed";
#define BIP32_SEED_KEY_LEN 12

/* Hardened derivation flag */
#define BIP32_HARDENED 0x80000000u

void bip32_master_key(const uint8_t seed[64], Bip32ExtKey *master) {
    uint8_t I[64];
    hmac_sha512(BIP32_SEED_KEY, BIP32_SEED_KEY_LEN, seed, 64, I);
    memcpy(master->key, I, 32);
    memcpy(master->chaincode, I + 32, 32);
    memzero(I, sizeof(I));
}

int bip32_derive_child(const Bip32ExtKey *parent, uint32_t index, Bip32ExtKey *child) {
    uint8_t data[37]; /* 0x00 || key[32] || index[4] or pubkey[33] || index[4] */
    uint8_t I[64];

    if (index & BIP32_HARDENED) {
        /* Hardened: data = 0x00 || parent_key[32] || index[4 BE] */
        data[0] = 0x00;
        memcpy(data + 1, parent->key, 32);
        data[33] = (index >> 24) & 0xFF;
        data[34] = (index >> 16) & 0xFF;
        data[35] = (index >> 8) & 0xFF;
        data[36] = index & 0xFF;
        hmac_sha512(parent->chaincode, 32, data, 37, I);
    } else {
        /* Normal: data = pubkey[33] || index[4 BE] */
        if (secp256k1_get_public_key33(parent->key, data) != 0) {
            memzero(data, sizeof(data));
            return -1;
        }
        data[33] = (index >> 24) & 0xFF;
        data[34] = (index >> 16) & 0xFF;
        data[35] = (index >> 8) & 0xFF;
        data[36] = index & 0xFF;
        hmac_sha512(parent->chaincode, 32, data, 37, I);
    }

    /* child_key = (IL + parent_key) mod n */
    bignum256 il, pk, n_val;
    bn_read_be(I, &il);
    bn_read_be(parent->key, &pk);
    bn_copy(secp256k1_n(), &n_val);

    /* Check IL < n */
    if (!bn_is_less(&il, &n_val)) {
        memzero(I, sizeof(I));
        memzero(data, sizeof(data));
        return -1;
    }

    bn_addmod(&il, &pk, &n_val);
    bn_mod(&il, &n_val);

    /* Check result is not zero */
    if (bn_is_zero(&il)) {
        memzero(I, sizeof(I));
        memzero(data, sizeof(data));
        return -1;
    }

    bn_write_be(&il, child->key);
    memcpy(child->chaincode, I + 32, 32);

    memzero(I, sizeof(I));
    memzero(data, sizeof(data));
    memzero(&il, sizeof(il));
    memzero(&pk, sizeof(pk));
    return 0;
}

int bip32_derive_transparent_sk(const uint8_t seed[64], uint32_t coin_type,
                                 uint8_t sk_out[32], uint8_t pubkey_out[33]) {
    Bip32ExtKey master, child;

    bip32_master_key(seed, &master);

    /* m / 44' */
    if (bip32_derive_child(&master, 44 | BIP32_HARDENED, &child) != 0) goto fail;
    memcpy(&master, &child, sizeof(master));

    /* m / 44' / coin_type' */
    if (bip32_derive_child(&master, coin_type | BIP32_HARDENED, &child) != 0) goto fail;
    memcpy(&master, &child, sizeof(master));

    /* m / 44' / coin_type' / 0' */
    if (bip32_derive_child(&master, 0 | BIP32_HARDENED, &child) != 0) goto fail;
    memcpy(&master, &child, sizeof(master));

    /* m / 44' / coin_type' / 0' / 0 (external chain) */
    if (bip32_derive_child(&master, 0, &child) != 0) goto fail;
    memcpy(&master, &child, sizeof(master));

    /* m / 44' / coin_type' / 0' / 0 / 0 (first address) */
    if (bip32_derive_child(&master, 0, &child) != 0) goto fail;

    memcpy(sk_out, child.key, 32);

    if (pubkey_out) {
        if (secp256k1_get_public_key33(child.key, pubkey_out) != 0) goto fail;
    }

    memzero(&master, sizeof(master));
    memzero(&child, sizeof(child));
    return 0;

fail:
    memzero(&master, sizeof(master));
    memzero(&child, sizeof(child));
    memzero(sk_out, 32);
    if (pubkey_out) memzero(pubkey_out, 33);
    return -1;
}
