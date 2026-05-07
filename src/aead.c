/**
 * AEAD: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC).
 *
 * See aead.h for design rationale. This file is hardware-agnostic;
 * every consumer (ESP32, Flipper Zero, ...) links against it.
 *
 * Audit: docs/security-audit/{INDEX.md, ...} H-5.
 */

#include "aead.h"
#include "aes_ct.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "memzero.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  AES-256-CTR                                                       */
/* ------------------------------------------------------------------ */

/* AES-256-CTR: keystream block i = AES_E(key, nonce || u32_be(i)).
 *
 * Nonce layout for our purposes:
 *   nonce[0..12]   = caller-supplied 12-byte IV (random per seal)
 *   nonce[12..16]  = 32-bit big-endian block counter, starts at 0
 *
 * The caller passes 16 bytes of "nonce" to seal/unseal. We treat the
 * top 12 as IV and reset the bottom 4 to 0 internally. Even if the
 * caller passes 16 random bytes, we ignore the bottom 4 — keeping a
 * predictable counter avoids accidentally producing the same keystream
 * block twice within one seal.
 */
static void aes_ctr_xor(
    const aes_ct_256_ctx* aes,
    const uint8_t nonce[AEAD_NONCE_SIZE],
    const uint8_t* in, size_t len, uint8_t* out) {

    uint8_t counter[16];
    memcpy(counter, nonce, 12);
    counter[12] = 0;
    counter[13] = 0;
    counter[14] = 0;
    counter[15] = 0;

    uint32_t block_idx = 0;
    uint8_t keystream[16];

    while (len > 0) {
        /* counter[12..16] = block_idx in big-endian */
        counter[12] = (uint8_t)((block_idx >> 24) & 0xFF);
        counter[13] = (uint8_t)((block_idx >> 16) & 0xFF);
        counter[14] = (uint8_t)((block_idx >>  8) & 0xFF);
        counter[15] = (uint8_t)( block_idx        & 0xFF);

        aes_ct_256_ecb_encrypt(aes, counter, keystream);

        size_t chunk = (len < 16) ? len : 16;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = in[i] ^ keystream[i];
        }
        in  += chunk;
        out += chunk;
        len -= chunk;
        block_idx++;
    }

    memzero(keystream, sizeof(keystream));
    memzero(counter, sizeof(counter));
}

/* ------------------------------------------------------------------ */
/*  Tag computation                                                   */
/* ------------------------------------------------------------------ */

static void compute_tag(
    const uint8_t mac_key[32],
    const uint8_t nonce[AEAD_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct,  size_t ct_len,
    uint8_t tag_out[AEAD_TAG_SIZE]) {

    /* Length-prefix encoding to prevent canonicalisation ambiguity:
     *   nonce || u64_le(aad_len) || aad || u64_le(ct_len) || ct */
    uint8_t len_le[8];

    HMAC_SHA256_CTX h;
    hmac_sha256_Init(&h, mac_key, 32);
    hmac_sha256_Update(&h, nonce, AEAD_NONCE_SIZE);

    /* aad_len as 8-byte little-endian */
    for (int i = 0; i < 8; i++) {
        len_le[i] = (uint8_t)((aad_len >> (8 * i)) & 0xFF);
    }
    hmac_sha256_Update(&h, len_le, 8);
    if (aad_len > 0) hmac_sha256_Update(&h, aad, (uint32_t)aad_len);

    /* ct_len as 8-byte little-endian */
    for (int i = 0; i < 8; i++) {
        len_le[i] = (uint8_t)((ct_len >> (8 * i)) & 0xFF);
    }
    hmac_sha256_Update(&h, len_le, 8);
    if (ct_len > 0) hmac_sha256_Update(&h, ct, (uint32_t)ct_len);

    hmac_sha256_Final(&h, tag_out);
    memzero(&h, sizeof(h));
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

int aead_aes256_ctr_hmac_seal(
    const uint8_t key[AEAD_KEY_SIZE],
    const uint8_t nonce[AEAD_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag_out[AEAD_TAG_SIZE]) {

    aes_ct_256_ctx aes;
    aes_ct_256_keysched(key, &aes);  /* enc_key = key[0..32] */

    aes_ctr_xor(&aes, nonce, pt, pt_len, ct);

    compute_tag(key + 32, nonce, aad, aad_len, ct, pt_len, tag_out);

    memzero(&aes, sizeof(aes));
    return 0;
}

int aead_aes256_ctr_hmac_unseal(
    const uint8_t key[AEAD_KEY_SIZE],
    const uint8_t nonce[AEAD_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[AEAD_TAG_SIZE],
    uint8_t* pt) {

    /* (1) Verify tag BEFORE decrypting (Encrypt-then-MAC). */
    uint8_t expected[AEAD_TAG_SIZE];
    compute_tag(key + 32, nonce, aad, aad_len, ct, ct_len, expected);

    /* Constant-time compare. */
    uint32_t diff = 0;
    for (size_t i = 0; i < AEAD_TAG_SIZE; i++) {
        diff |= (uint32_t)(expected[i] ^ tag[i]);
    }
    memzero(expected, sizeof(expected));
    if (diff != 0) {
        /* Tag mismatch: do NOT decrypt. The plaintext buffer is
         * untouched, so a wrong-PIN attempt cannot leak any bytes. */
        return -1;
    }

    /* (2) Tag verified. Decrypt = same XOR keystream as encrypt. */
    aes_ct_256_ctx aes;
    aes_ct_256_keysched(key, &aes);
    aes_ctr_xor(&aes, nonce, ct, ct_len, pt);
    memzero(&aes, sizeof(aes));
    return 0;
}

void wallet_pin_kdf(
    const uint8_t* pin, size_t pin_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t key_out[AEAD_KEY_SIZE]) {

    /* PBKDF2-HMAC-SHA512 produces 64-byte output in one block (HMAC-SHA512
     * outputs 64 bytes per round, so a single PBKDF2 block suffices for
     * the AEAD key length). Wraps the existing library primitive. */
    pbkdf2_hmac_sha512(pin, (int)pin_len, salt, (int)salt_len,
                       iterations, key_out, AEAD_KEY_SIZE);
}

/* ------------------------------------------------------------------ */
/*  Self-test                                                         */
/* ------------------------------------------------------------------ */

int aead_self_test(void) {
    /* Hard-coded test vector: encrypt 5 known bytes with all-0x42 key /
     * all-0xAB nonce, verify roundtrip. We are not verifying against an
     * external KAT (CTR mode + HMAC-SHA256 are both NIST-validated
     * primitives by themselves; the integration is ours), but a
     * roundtrip + tag-tamper check exercises every code path. */
    static const uint8_t key[AEAD_KEY_SIZE] = {
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
    };
    static const uint8_t nonce[AEAD_NONCE_SIZE] = {
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    };
    static const uint8_t aad[] = "self-test";
    static const uint8_t pt[] = "Hello";
    uint8_t ct[5];
    uint8_t tag[AEAD_TAG_SIZE];
    uint8_t recovered[5];

    if (aead_aes256_ctr_hmac_seal(key, nonce, aad, sizeof(aad) - 1,
                                   pt, 5, ct, tag) != 0) return 0;

    /* Roundtrip: unseal must succeed and recover plaintext. */
    if (aead_aes256_ctr_hmac_unseal(key, nonce, aad, sizeof(aad) - 1,
                                     ct, 5, tag, recovered) != 0) return 0;
    int diff = 0;
    for (int i = 0; i < 5; i++) diff |= recovered[i] ^ pt[i];
    if (diff != 0) return 0;

    /* Tamper test: flipping any byte of tag must make unseal fail. */
    uint8_t tampered_tag[AEAD_TAG_SIZE];
    memcpy(tampered_tag, tag, AEAD_TAG_SIZE);
    tampered_tag[0] ^= 0x01;
    if (aead_aes256_ctr_hmac_unseal(key, nonce, aad, sizeof(aad) - 1,
                                     ct, 5, tampered_tag, recovered) == 0) {
        /* Tag-tamper unseal returned success — broken. */
        return 0;
    }

    /* Wrong AAD must also fail. */
    static const uint8_t wrong_aad[] = "self test";
    if (aead_aes256_ctr_hmac_unseal(key, nonce, wrong_aad, sizeof(wrong_aad) - 1,
                                     ct, 5, tag, recovered) == 0) {
        return 0;
    }

    memzero(recovered, sizeof(recovered));
    memzero(ct, sizeof(ct));
    memzero(tag, sizeof(tag));
    return 1;
}
