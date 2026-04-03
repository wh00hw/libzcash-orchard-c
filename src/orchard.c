#include "orchard.h"
#include "pallas.h"
#include "blake2b.h"
#include "bignum.h"
#include "segwit_addr.h"
#include "memzero.h"
#include <string.h>

#include "aes/aes.h"

// Pallas base field modulus (big-endian)
// p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
static const uint8_t PALLAS_P_BE[32] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b,
    0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01};

// Pallas scalar field (group order, big-endian)
// q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
static const uint8_t PALLAS_Q_BE[32] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd,
    0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01};

// Reduce a 64-byte little-endian value modulo a ~255-bit prime
// Uses bit-by-bit Horner's method: processes MSB to LSB
// Works correctly for any prime (unlike bn_fast_mod which requires prime ~ 2^256)
static void reduce_512_mod(
    const uint8_t input_le[64],
    const uint8_t modulus_be[32],
    uint8_t output_le[32]) {
    bignum256 acc, prime, temp;

    bn_read_be(modulus_be, &prime);
    bn_zero(&acc);

    // Process 512 bits from MSB to LSB
    for(int bit = 511; bit >= 0; bit--) {
        // acc = 2 * acc
        bn_lshift(&acc);

        // Add current bit
        int byte_idx = bit / 8;
        int bit_idx = bit % 8;
        if(input_le[byte_idx] & (1 << bit_idx)) {
            bn_addi(&acc, 1);
        }

        // Normalize to propagate any carries from addi/lshift
        bn_normalize(&acc);

        // Reduce: if acc >= prime, subtract prime
        if(!bn_is_less(&acc, &prime)) {
            bn_subtract(&acc, &prime, &temp);
            bn_copy(&temp, &acc);
        }
    }

    bn_write_le(&acc, output_le);

    memzero(&acc, sizeof(acc));
    memzero(&temp, sizeof(temp));
}

// ToScalar: reduce 64-byte LE value modulo Pallas group order q
static void to_scalar(const uint8_t input_le[64], uint8_t output_le[32]) {
    reduce_512_mod(input_le, PALLAS_Q_BE, output_le);
}

// ToBase: reduce 64-byte LE value modulo Pallas base field p
static void to_base(const uint8_t input_le[64], uint8_t output_le[32]) {
    reduce_512_mod(input_le, PALLAS_P_BE, output_le);
}

// PRF^expand(sk, domain, parts...):
//   BLAKE2b-512(personal="Zcash_ExpandSeed", input = sk || domain || parts)
// NOTE: sk is part of the INPUT, NOT the BLAKE2b key parameter!
static void prf_expand(
    const uint8_t sk[32],
    const uint8_t* domain_and_parts,
    size_t parts_len,
    uint8_t output[64]) {
    blake2b_state S;
    blake2b_InitPersonal(&S, 64, "Zcash_ExpandSeed", 16);
    blake2b_Update(&S, sk, 32);
    blake2b_Update(&S, domain_and_parts, parts_len);
    blake2b_Final(&S, output, 64);
    memzero(&S, sizeof(S));
}

void orchard_master_key(
    const uint8_t seed[64],
    uint8_t sk_out[32],
    uint8_t chaincode_out[32]) {
    uint8_t I[64];
    blake2b_state S;

    // I = BLAKE2b-512(personalization="ZcashIP32Orchard", input=seed)
    blake2b_InitPersonal(&S, 64, "ZcashIP32Orchard", 16);
    blake2b_Update(&S, seed, 64);
    blake2b_Final(&S, I, 64);

    memcpy(sk_out, I, 32);
    memcpy(chaincode_out, I + 32, 32);

    memzero(I, sizeof(I));
    memzero(&S, sizeof(S));
}

void orchard_child_key(
    const uint8_t sk_parent[32],
    const uint8_t chaincode_parent[32],
    uint32_t index,
    uint8_t sk_out[32],
    uint8_t chaincode_out[32]) {
    // I = PRF^expand(c_parent, [0x81] || sk_parent || I2LEOSP32(index))
    uint8_t input[1 + 32 + 4];
    input[0] = 0x81;
    memcpy(input + 1, sk_parent, 32);
    // I2LEOSP32: 32-bit little-endian encoding
    input[33] = (uint8_t)(index & 0xFF);
    input[34] = (uint8_t)((index >> 8) & 0xFF);
    input[35] = (uint8_t)((index >> 16) & 0xFF);
    input[36] = (uint8_t)((index >> 24) & 0xFF);

    uint8_t I[64];
    prf_expand(chaincode_parent, input, sizeof(input), I);

    memcpy(sk_out, I, 32);
    memcpy(chaincode_out, I + 32, 32);

    memzero(I, sizeof(I));
    memzero(input, sizeof(input));
}

void orchard_derive_keys(
    const uint8_t sk[32],
    uint8_t ask_out[32],
    uint8_t nk_out[32],
    uint8_t rivk_out[32]) {
    uint8_t prf_out[64];
    uint8_t domain[1];

    // ask = ToScalar(PRF^expand(sk, [0x06]))
    domain[0] = 0x06;
    prf_expand(sk, domain, 1, prf_out);
    to_scalar(prf_out, ask_out);

    // nk = ToBase(PRF^expand(sk, [0x07]))
    domain[0] = 0x07;
    prf_expand(sk, domain, 1, prf_out);
    to_base(prf_out, nk_out);

    // rivk = ToScalar(PRF^expand(sk, [0x08]))
    domain[0] = 0x08;
    prf_expand(sk, domain, 1, prf_out);
    to_scalar(prf_out, rivk_out);

    memzero(prf_out, sizeof(prf_out));
}

void orchard_derive_account_sk(
    const uint8_t seed[64],
    uint32_t coin_type,
    uint32_t account,
    uint8_t sk_out[32]) {
    uint8_t sk[32], chaincode[32];
    uint8_t sk_child[32], cc_child[32];

    // Master key
    orchard_master_key(seed, sk, chaincode);

    // ZIP-32 Orchard path: m_Orchard / 32' / coin_type' / account'
    // Purpose = 32 (ZIP-32)
    orchard_child_key(sk, chaincode, 0x80000000 | 32, sk_child, cc_child);
    memcpy(sk, sk_child, 32);
    memcpy(chaincode, cc_child, 32);

    // Coin type
    orchard_child_key(sk, chaincode, 0x80000000 | coin_type, sk_child, cc_child);
    memcpy(sk, sk_child, 32);
    memcpy(chaincode, cc_child, 32);

    // Account: account'
    orchard_child_key(sk, chaincode, 0x80000000 | account, sk_child, cc_child);

    memcpy(sk_out, sk_child, 32);

    memzero(sk, sizeof(sk));
    memzero(chaincode, sizeof(chaincode));
    memzero(sk_child, sizeof(sk_child));
    memzero(cc_child, sizeof(cc_child));
}

// ============================================================
// FF1-AES-256 (NIST SP 800-38G) for diversifier derivation
// Radix 2, n=88 bits, empty tweak
// Matches the fpe crate's BinaryNumeralString behavior exactly.
// ============================================================

// BinaryNumeralString: bytes are LE, bits within bytes are LE.
// Numeral i = (byte[i/8] >> (i%8)) & 1
// NUM_2(X) treats numerals in big-endian order:
//   NUM_2(X[0..m]) = X[0]*2^(m-1) + X[1]*2^(m-2) + ... + X[m-1]*2^0
// So bit 0 of byte 0 is the MSB of the 44-bit integer.

// Extract 44-bit integer from the numeral string starting at bit offset
static uint64_t ff1_extract(const uint8_t* data, int bit_offset, int count) {
    uint64_t val = 0;
    for(int i = 0; i < count; i++) {
        int src = bit_offset + i;
        int byte_idx = src / 8;
        int bit_idx = src % 8;
        if(data[byte_idx] & (1 << bit_idx)) {
            val |= (1ULL << (count - 1 - i)); // numeral 0 = MSB
        }
    }
    return val;
}

// Write 44-bit integer back to numeral string at bit offset
static void ff1_inject(uint8_t* data, int bit_offset, int count, uint64_t val) {
    for(int i = 0; i < count; i++) {
        int dst = bit_offset + i;
        int byte_idx = dst / 8;
        int bit_idx = dst % 8;
        if(val & (1ULL << (count - 1 - i))) {
            data[byte_idx] |= (1 << bit_idx);
        } else {
            data[byte_idx] &= ~(1 << bit_idx);
        }
    }
}

// Convert uint64 to b-byte big-endian
static void ff1_to_be(uint64_t val, uint8_t* out, int b) {
    for(int i = b - 1; i >= 0; i--) {
        out[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

void ff1_aes256_encrypt(const uint8_t key[32], const uint8_t in[11], uint8_t out[11]) {
    aes_encrypt_ctx ctx[1];
    aes_encrypt_key256(key, ctx);

    const int n = 88; // bits
    const int u = 44, v = 44;
    (void)v; // used in comments, m alternates u/v
    const uint64_t mask44 = (1ULL << 44) - 1;

    // Split: A = NUM_2(numerals 0..43), B = NUM_2(numerals 44..87)
    uint64_t num_a = ff1_extract(in, 0, u);
    uint64_t num_b = ff1_extract(in, u, v);

    // P = [1,2,1] || [radix=2 as 3 BE bytes] || [10] || [u%256] || [n as 4 BE] || [t=0 as 4 BE]
    uint8_t P[16] = {1, 2, 1, 0, 0, 2, 10, (uint8_t)(u & 0xFF),
                     0, 0, 0, (uint8_t)((n >> 0) & 0xFF), 0, 0, 0, 0};
    // n=88: BE 4 bytes = 0,0,0,88
    P[8] = 0; P[9] = 0; P[10] = 0; P[11] = 88;

    // PRF base: AES-CBC-MAC of P with IV=0
    // For empty tweak and b=6: padding = ((-0-6-1) mod 16 + 16) mod 16 = 9 zeros
    // So Q = [0]*9 || [i] || [NUM_2(B) as 6 BE bytes] = 16 bytes
    // R = AES(key, AES(key, P) ^ Q)
    uint8_t prf_p[16];
    aes_ecb_encrypt(P, prf_p, 16, ctx);

    for(int i = 0; i < 10; i++) {

        // Q: 9 zeros || round_byte || NUM_2(B) as 6 BE bytes
        uint8_t Q[16] = {0};
        Q[9] = (uint8_t)i;
        ff1_to_be(num_b, Q + 10, 6);

        // R = AES(key, prf_p ^ Q)
        uint8_t R[16];
        for(int j = 0; j < 16; j++) R[j] = prf_p[j] ^ Q[j];
        uint8_t S[16];
        aes_ecb_encrypt(R, S, 16, ctx);

        // y = NUM(S[0..d]) where d=12, as big-endian integer
        // We need (num_a + y) mod 2^m where m=44
        // Only the low 44 bits of y matter
        uint64_t y_low = 0;
        for(int j = 6; j < 12; j++) y_low = (y_low << 8) | S[j];
        // Also include contribution from S[5] low nibble
        y_low |= ((uint64_t)(S[5] & 0x0F) << 48);
        y_low &= mask44;

        uint64_t c = (num_a + y_low) & mask44;

        // A = B, B = c
        num_a = num_b;
        num_b = c;
    }

    // Reconstruct output
    memcpy(out, in, 11); // start with input (preserves bit layout)
    ff1_inject(out, 0, u, num_a);
    ff1_inject(out, u, v, num_b);
}

// ============================================================
// F4Jumble (ZIP-316)
// ============================================================

// F4Jumble (ZIP-316) - Reference: zcash-test-vectors/f4jumble.py
// H_i(u) -> l_L bytes (short, single BLAKE2b)
// G_i(u) -> l_R bytes (long, counter-mode BLAKE2b)
static void f4jumble_H(int i, const uint8_t* u, size_t u_len, uint8_t* out, size_t out_len) {
    uint8_t personal[16] = {'U','A','_','F','4','J','u','m','b','l','e','_','H',0,0,0};
    personal[13] = (uint8_t)i;
    blake2b_state S;
    blake2b_InitPersonal(&S, out_len, personal, 16);
    blake2b_Update(&S, u, u_len);
    blake2b_Final(&S, out, out_len);
}

static void f4jumble_G(int i, const uint8_t* u, size_t u_len, uint8_t* out, size_t out_len) {
    uint8_t personal[16] = {'U','A','_','F','4','J','u','m','b','l','e','_','G',0,0,0};
    personal[13] = (uint8_t)i;
    size_t done = 0;
    for(uint32_t j = 0; done < out_len; j++) {
        size_t chunk = out_len - done;
        if(chunk > 64) chunk = 64;
        personal[14] = (uint8_t)(j & 0xFF);
        personal[15] = (uint8_t)((j >> 8) & 0xFF);
        blake2b_state S;
        blake2b_InitPersonal(&S, 64, personal, 16);
        blake2b_Update(&S, u, u_len);
        uint8_t hash[64];
        blake2b_Final(&S, hash, 64);
        memcpy(out + done, hash, chunk);
        done += chunk;
    }
}

// F4Jumble (ZIP-316). For Unified Addresses the input is ~83 bytes.
// l_L is capped at 64, so buf needs max(l_R, l_L).
// We use a static buffer to avoid both malloc and stack pressure
// on constrained devices (Flipper Zero: 4 KB stack).
#ifndef F4JUMBLE_MAX_INPUT
#define F4JUMBLE_MAX_INPUT 256
#endif

void f4jumble(uint8_t* data, size_t len) {
    if(len < 48 || len > F4JUMBLE_MAX_INPUT) return;
    size_t l_L = len / 2;
    if(l_L > 64) l_L = 64;
    size_t l_R = len - l_L;

    // Static buffer: max(l_R, l_L) where l_L ≤ 64, l_R = len - l_L.
    // Worst case: len=256 → l_R=192. Lives in BSS, not stack.
    static uint8_t buf[F4JUMBLE_MAX_INPUT - 64];

    uint8_t* a = data;
    uint8_t* b = data + l_L;

    // x = b XOR G(0, a)
    f4jumble_G(0, a, l_L, buf, l_R);
    for(size_t i = 0; i < l_R; i++) b[i] ^= buf[i];
    // Now b = x

    // y = a XOR H(0, x)
    f4jumble_H(0, b, l_R, buf, l_L);
    for(size_t i = 0; i < l_L; i++) a[i] ^= buf[i];
    // Now a = y

    // d = x XOR G(1, y)
    f4jumble_G(1, a, l_L, buf, l_R);
    for(size_t i = 0; i < l_R; i++) b[i] ^= buf[i];
    // Now b = d

    // c = y XOR H(1, d)
    f4jumble_H(1, b, l_R, buf, l_L);
    for(size_t i = 0; i < l_L; i++) a[i] ^= buf[i];
    // Now a = c

    // Result: c || d = a || b (in-place)
}

// ============================================================
// Unified Address encoding
// ============================================================

// Convert 8-bit byte array to 5-bit array for Bech32
static size_t convert_bits_8to5(
    const uint8_t* in, size_t in_len,
    uint8_t* out, size_t out_max) {
    uint32_t val = 0;
    int bits = 0;
    size_t out_len = 0;
    for(size_t i = 0; i < in_len; i++) {
        val = (val << 8) | in[i];
        bits += 8;
        while(bits >= 5) {
            bits -= 5;
            if(out_len < out_max) out[out_len++] = (val >> bits) & 0x1F;
        }
    }
    if(bits > 0) {
        if(out_len < out_max) out[out_len++] = (val << (5 - bits)) & 0x1F;
    }
    return out_len;
}

// Address generation is done via orchard_derive_unified_address() below

int orchard_derive_unified_address(
    const uint8_t seed[64],
    uint32_t coin_type,
    uint32_t account,
    const char* hrp,
    char* ua_out,
    size_t ua_out_len,
    uint8_t* d_out,
    uint8_t* pk_d_out) {

    pallas_init();

    uint8_t d[11];
    uint8_t pk_d_bytes[32];

    // Cache is handled by caller

    // Large structures are static to avoid ~548 bytes of stack pressure
    // on constrained devices (e.g. Flipper Zero: 4 KB stack).
    // All are explicitly zeroed after use to prevent secret persistence.
    {
        // 1. Derive spending key and components
        pallas_report(2, "Deriving keys...");
        uint8_t sk[32], ask_le[32], nk_le[32], rivk_le[32];
        orchard_derive_account_sk(seed, coin_type, account, sk);
        orchard_derive_keys(sk, ask_le, nk_le, rivk_le);

        // 2. ak = [ask] * G_spend
        pallas_report(5, "Computing ak...");
        static bignum256 ask_bn;
        bn_read_le(ask_le, &ask_bn);

        static pallas_point G_spend;
        pallas_group_hash(&G_spend, "z.cash:Orchard", (const uint8_t*)"G", 1);

        pallas_report(15, "Scalar mul [ask]*G");
        static pallas_point ak;
        pallas_point_mul(&ak, &ask_bn, &G_spend);

        // 3. IVK = SinsemillaShortCommit
        pallas_report(35, "Sinsemilla IVK...");
        static bignum256 nk_bn;
        bn_read_le(nk_le, &nk_bn);

        static uint8_t commit_msg[64];
        memzero(commit_msg, 64);
        uint8_t nk_bytes_le[32], ak_x_bytes[32];
        bn_write_le(&nk_bn, nk_bytes_le);
        nk_bytes_le[31] &= 0x7F;
        bn_write_le(&ak.x, ak_x_bytes);
        ak_x_bytes[31] &= 0x7F;
        // Message = I2LEBSP_255(ak) || I2LEBSP_255(nk) — ak FIRST per spec
        memcpy(commit_msg, ak_x_bytes, 32);
        for(int i = 0; i < 255; i++) {
            int sb = i / 8, sbt = i % 8, db = (255 + i) / 8, dbt = (255 + i) % 8;
            if(nk_bytes_le[sb] & (1 << sbt)) commit_msg[db] |= (1 << dbt);
        }

        static bignum256 rivk_bn;
        bn_read_le(rivk_le, &rivk_bn);
        static bignum256 ivk_x;
        sinsemilla_short_commit(&ivk_x, "z.cash:Orchard-CommitIvk",
                                commit_msg, 510, &rivk_bn);
        fq_reduce(&ivk_x, &ivk_x);
        static bignum256 ivk;
        bn_copy(&ivk_x, &ivk);

        // 4. dk
        uint8_t ak_compressed[32];
        bn_write_le(&ak.x, ak_compressed);
        if(ak.y.val[0] & 1) ak_compressed[31] |= 0x80;
        uint8_t dk[32];
        {
            uint8_t prf_dk_out[64];
            blake2b_state S_dk;
            blake2b_InitPersonal(&S_dk, 64, "Zcash_ExpandSeed", 16);
            blake2b_Update(&S_dk, rivk_le, 32);
            uint8_t dk_d[1] = {0x82};
            blake2b_Update(&S_dk, dk_d, 1);
            blake2b_Update(&S_dk, ak_compressed, 32);
            blake2b_Update(&S_dk, nk_le, 32);
            blake2b_Final(&S_dk, prf_dk_out, 64);
            memcpy(dk, prf_dk_out, 32);
            memzero(prf_dk_out, sizeof(prf_dk_out));
            memzero(&S_dk, sizeof(S_dk));
        }

        // 5. diversifier
        pallas_report(70, "Diversifier...");
        uint8_t d_in[11] = {0};
        ff1_aes256_encrypt(dk, d_in, d);

        // 6. g_d = DiversifyHash(d)
        pallas_report(72, "DiversifyHash...");
        static pallas_point g_d;
        pallas_hash_to_curve(&g_d, "z.cash:Orchard-gd", d, 11);

        // 7. pk_d = [ivk] * g_d
        pallas_report(80, "Computing pk_d...");
        static pallas_point pk_d;
        pallas_point_mul(&pk_d, &ivk, &g_d);

        bn_write_le(&pk_d.x, pk_d_bytes);
        if(pk_d.y.val[0] & 1) pk_d_bytes[31] |= 0x80;

        pallas_report(95, "Encoding...");

        // Wipe ALL secret intermediates (static + stack)
        memzero(sk, sizeof(sk));
        memzero(ask_le, sizeof(ask_le));
        memzero(nk_le, sizeof(nk_le));
        memzero(rivk_le, sizeof(rivk_le));
        memzero(dk, sizeof(dk));
        memzero(ak_compressed, sizeof(ak_compressed));
        memzero(nk_bytes_le, sizeof(nk_bytes_le));
        memzero(ak_x_bytes, sizeof(ak_x_bytes));
        memzero(commit_msg, sizeof(commit_msg));
        memzero(&ask_bn, sizeof(ask_bn));
        memzero(&nk_bn, sizeof(nk_bn));
        memzero(&rivk_bn, sizeof(rivk_bn));
        memzero(&ivk_x, sizeof(ivk_x));
        memzero(&ivk, sizeof(ivk));
        memzero(&ak, sizeof(ak));
        memzero(&g_d, sizeof(g_d));
        memzero(&pk_d, sizeof(pk_d));
        memzero(&G_spend, sizeof(G_spend));
    }


    pallas_report(98, "Encoding UA...");

    // Export d and pk_d for caching
    if(d_out) memcpy(d_out, d, 11);
    if(pk_d_out) memcpy(pk_d_out, pk_d_bytes, 32);

    // 8. Build raw UA per ZIP-316: Orchard-only
    //    receivers (ascending typecode) || HRP padded to 16 bytes
    uint8_t raw_ua[80]; // Orchard(45) + padding(16) = 61
    size_t raw_len = 0;

    // Orchard receiver (typecode 0x03)
    raw_ua[raw_len++] = 0x03;
    raw_ua[raw_len++] = 43;
    memcpy(raw_ua + raw_len, d, 11);
    raw_len += 11;
    memcpy(raw_ua + raw_len, pk_d_bytes, 32);
    raw_len += 32;
    // raw_len = 45 (Orchard only)

    // ZIP-316 padding: HRP padded to 16 bytes with zeros
    {
        uint8_t hrp_padded[16] = {0};
        size_t hlen = strlen(hrp);
        if(hlen > 16) hlen = 16;
        memcpy(hrp_padded, hrp, hlen);
        memcpy(raw_ua + raw_len, hrp_padded, 16);
        raw_len += 16;
    }
    // raw_len = 83 (67 receivers + 16 padding)

    // 9. F4Jumble
    f4jumble(raw_ua, raw_len);

    // 11. Bech32m encode (ignoring length restrictions per ZIP-316)
    uint8_t data5[160];
    size_t data5_len = convert_bits_8to5(raw_ua, raw_len, data5, sizeof(data5));

    // Use bech32_encode directly (not segwit_addr_encode which has length limits)
    if(ua_out_len < 200) return 0;
    int ok = bech32_encode(ua_out, hrp, data5, data5_len, BECH32_ENCODING_BECH32M);
    if(!ok) return 0;

    // Sensitive data was cleared in the computation block above

    return (int)strlen(ua_out);
}
