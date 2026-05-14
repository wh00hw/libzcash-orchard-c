/*
 * Base58 + Base58Check encoder. See base58.h for scope and rationale.
 */
#include "base58.h"

#include <string.h>

#include "sha2.h"

static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Internal base58 encoder. Input ≤ 96 bytes — sized for Zcash t-addr
 * payloads (2 version bytes + 32 max script payload + 4 checksum) plus
 * headroom for the BLAKE2-128 case some other Zcash strings need. */
static size_t base58_encode(const uint8_t* data, size_t data_len,
                             char* out, size_t out_cap) {
    if(data_len == 0 || out == NULL || out_cap < 2) return 0;

    /* Worst-case output size: ceil(data_len * log(256)/log(58)) ≈
     * data_len * 1.38. For 26-byte input (t-addr) that's ≤ 36 chars. */
    if(data_len > 96) return 0;
    uint8_t scratch[136];
    memset(scratch, 0, sizeof(scratch));

    size_t leading_zeros = 0;
    while(leading_zeros < data_len && data[leading_zeros] == 0) leading_zeros++;

    /* Repeated division by 58: treat `scratch` as a little-endian
     * base-58 representation built from the back. */
    size_t length = 0;
    for(size_t i = leading_zeros; i < data_len; i++) {
        int carry = data[i];
        size_t j = 0;
        for(size_t k = sizeof(scratch); k > 0; k--) {
            if(carry == 0 && j >= length) break;
            carry += 256 * scratch[k - 1];
            scratch[k - 1] = (uint8_t)(carry % 58);
            carry /= 58;
            j++;
        }
        length = j;
    }

    size_t skip = sizeof(scratch) - length;
    size_t needed = leading_zeros + length + 1; /* + NUL */
    if(out_cap < needed) return 0;

    size_t out_len = 0;
    for(size_t i = 0; i < leading_zeros; i++) out[out_len++] = '1';
    for(size_t i = skip; i < sizeof(scratch); i++) {
        out[out_len++] = BASE58_ALPHABET[scratch[i]];
    }
    out[out_len] = '\0';
    return out_len;
}

size_t base58check_encode(const uint8_t* payload, size_t len,
                          char* out, size_t out_cap) {
    if(payload == NULL || out == NULL || len > 92) return 0;

    uint8_t hash1[32], hash2[32];
    sha256_Raw(payload, len, hash1);
    sha256_Raw(hash1, 32, hash2);

    uint8_t buf[96];
    memcpy(buf, payload, len);
    memcpy(buf + len, hash2, 4); /* first 4 bytes of SHA256(SHA256(input)) */
    size_t r = base58_encode(buf, len + 4, out, out_cap);
    memset(buf, 0, sizeof(buf));
    memset(hash1, 0, sizeof(hash1));
    memset(hash2, 0, sizeof(hash2));
    return r;
}

size_t script_to_taddr(const uint8_t* script, size_t script_len,
                       bool testnet, char* out, size_t out_cap) {
    if(script == NULL || out == NULL || out_cap < 40) return 0;

    uint8_t payload[22];

    /* P2PKH: OP_DUP OP_HASH160 0x14 <pkh:20> OP_EQUALVERIFY OP_CHECKSIG */
    if(script_len == 25 &&
       script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
       script[23] == 0x88 && script[24] == 0xac) {
        payload[0] = testnet ? 0x1D : 0x1C;
        payload[1] = testnet ? 0x25 : 0xB8;
        memcpy(payload + 2, script + 3, 20);
        return base58check_encode(payload, 22, out, out_cap);
    }

    /* P2SH: OP_HASH160 0x14 <sh:20> OP_EQUAL */
    if(script_len == 23 &&
       script[0] == 0xa9 && script[1] == 0x14 &&
       script[22] == 0x87) {
        payload[0] = 0x1C;
        payload[1] = testnet ? 0xBA : 0xBD;
        memcpy(payload + 2, script + 2, 20);
        return base58check_encode(payload, 22, out, out_cap);
    }

    return 0;
}
