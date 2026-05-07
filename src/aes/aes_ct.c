/**
 * Constant-time AES-256 encryption.
 *
 * Implementation strategy:
 *   - State is 16 bytes, processed bytewise (no T-tables, no bitslicing).
 *   - The S-box is implemented as a linear scan over all 256 entries with
 *     a constant-time mask: every byte of the table is touched on every
 *     call regardless of input. This eliminates the cache-timing channel
 *     that the previous Brian-Gladman T-table implementation leaked
 *     (audit H-3).
 *   - ShiftRows is a fixed byte permutation.
 *   - MixColumns uses xtime() with bitmask-based GF(2^8) reduction
 *     (no branches on secret bits).
 *   - Key schedule is the standard AES-256 expansion using the same
 *     constant-time S-box.
 *
 * Performance: ~16 × 256 = 4096 byte-comparisons per SubBytes round,
 * × 14 rounds + key schedule overhead ≈ 70 KB of byte ops per single-
 * block encrypt. On ESP32-S2 @ 240 MHz this is < 1 ms — negligible
 * for the FF1 use case (single call per account creation, then NVS-cached).
 *
 * Verified against the FIPS-197 §C.3 AES-256 known-answer test in
 * aes_ct_256_self_test() below.
 *
 * Audit: docs/security-audit/01-crypto-c-primitives.md H-3.
 */

#include "aes_ct.h"
#include "memzero.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

/* AES S-box (FIPS-197 §5.1.1, Figure 7). */
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/* AES round constants for the key schedule. RCON[i] = x^(i-1) in GF(2^8).
 * AES-256 uses RCON[1..7]; we provide more for safety. */
static const uint8_t AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* ------------------------------------------------------------------ */
/*  Constant-time primitives                                          */
/* ------------------------------------------------------------------ */

/* Constant-time byte equality: returns 0xFF if a == b, else 0x00.
 *
 * Construction: x = a XOR b is zero iff a == b. Then (x | -x) has its
 * MSB set iff x != 0; so ~((x | -x) >> 31) & 1 is 1 iff x == 0. We
 * negate that to produce a 0/0xFF mask. The arithmetic is carried in
 * uint32_t to avoid uint8_t two's-complement subtleties.
 */
static uint8_t ct_eq_u8(uint8_t a, uint8_t b) {
    uint32_t x = (uint32_t)((uint8_t)(a ^ b));
    uint32_t neq_bit = (x | (uint32_t)(0u - x)) >> 31;   /* 1 iff x != 0 */
    uint32_t eq_bit  = neq_bit ^ 1u;                     /* 1 iff x == 0 */
    return (uint8_t)(0u - eq_bit);                       /* 0xFF iff equal */
}

/* Constant-time AES S-box. Touches every entry of AES_SBOX on every
 * call, so the cache-line access pattern is independent of the input.
 *
 * The `volatile` access on `entry` prevents the compiler from optimising
 * the loop to skip iterations where the mask is zero — the loop body
 * MUST execute an unconditional memory read of AES_SBOX[i] for cache
 * uniformity. */
static uint8_t sbox_ct(uint8_t x) {
    uint8_t result = 0;
    for (int i = 0; i < 256; i++) {
        volatile uint8_t entry = AES_SBOX[i];
        uint8_t mask = ct_eq_u8(x, (uint8_t)i);
        result |= (uint8_t)(mask & entry);
    }
    return result;
}

/* GF(2^8) multiply by x (0x02) with reduction polynomial 0x11b.
 * Constant-time: mask the conditional XOR via arithmetic, no branch. */
static uint8_t xtime(uint8_t a) {
    uint8_t high_mask = (uint8_t)(0u - (uint32_t)((a >> 7) & 1u));  /* 0xFF iff MSB=1 */
    return (uint8_t)((uint8_t)(a << 1) ^ (uint8_t)(high_mask & 0x1b));
}

/* ------------------------------------------------------------------ */
/*  AES round operations                                              */
/* ------------------------------------------------------------------ */

/* SubBytes: apply the constant-time S-box to each byte of the state. */
static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox_ct(state[i]);
    }
}

/* ShiftRows: cyclic left-shift the rows of the column-major 4×4 state by
 * 0, 1, 2, 3 bytes respectively. Layout: state[r + 4c] is row r, col c. */
static void shift_rows(uint8_t s[16]) {
    uint8_t t;

    /* Row 1: rotate left by 1 — (1,5,9,13) → (5,9,13,1) */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;

    /* Row 2: rotate left by 2 — swap (2,10) and (6,14) */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;

    /* Row 3: rotate left by 3 — (3,7,11,15) → (15,3,7,11), i.e. rotate right by 1 */
    t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}

/* MixColumns: each column c of the state is treated as a polynomial over
 * GF(2^8) and multiplied by the AES MDS matrix. Standard formulation
 * using xtime; constant-time because xtime is constant-time. */
static void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[4*c + 0];
        uint8_t s1 = state[4*c + 1];
        uint8_t s2 = state[4*c + 2];
        uint8_t s3 = state[4*c + 3];
        uint8_t t  = (uint8_t)(s0 ^ s1 ^ s2 ^ s3);
        state[4*c + 0] ^= (uint8_t)(xtime((uint8_t)(s0 ^ s1)) ^ t);
        state[4*c + 1] ^= (uint8_t)(xtime((uint8_t)(s1 ^ s2)) ^ t);
        state[4*c + 2] ^= (uint8_t)(xtime((uint8_t)(s2 ^ s3)) ^ t);
        state[4*c + 3] ^= (uint8_t)(xtime((uint8_t)(s3 ^ s0)) ^ t);
    }
}

/* AddRoundKey: XOR the round key into the state. */
static void add_round_key(uint8_t state[16], const uint8_t rk[16]) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

/* ------------------------------------------------------------------ */
/*  Key schedule (AES-256, Nk=8, Nr=14, total 60 words = 15 round keys) */
/* ------------------------------------------------------------------ */

void aes_ct_256_keysched(const uint8_t key[32], aes_ct_256_ctx* ctx) {
    /* W[0..7] = key (in 32-bit-word form, big-endian byte order).
     *
     * W is a 240-byte scratch array. Declared `static` to keep the stack
     * frame within the 512-byte embedded budget that the rest of the
     * library targets. Single-threaded use only — the rest of libzcash-
     * orchard-c is the same. The buffer is zeroed before return. */
    static uint8_t W[60][4];
    for (int i = 0; i < 8; i++) {
        W[i][0] = key[4*i + 0];
        W[i][1] = key[4*i + 1];
        W[i][2] = key[4*i + 2];
        W[i][3] = key[4*i + 3];
    }

    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        t[0] = W[i-1][0];
        t[1] = W[i-1][1];
        t[2] = W[i-1][2];
        t[3] = W[i-1][3];

        if ((i & 7) == 0) {
            /* SubWord(RotWord(t)) ^ Rcon[i/8] */
            uint8_t r = t[0];
            t[0] = sbox_ct(t[1]);
            t[1] = sbox_ct(t[2]);
            t[2] = sbox_ct(t[3]);
            t[3] = sbox_ct(r);
            t[0] ^= AES_RCON[i / 8];
        } else if ((i & 7) == 4) {
            /* SubWord(t) — the AES-256-only "extra" SubWord every 4 words */
            t[0] = sbox_ct(t[0]);
            t[1] = sbox_ct(t[1]);
            t[2] = sbox_ct(t[2]);
            t[3] = sbox_ct(t[3]);
        }

        W[i][0] = (uint8_t)(W[i-8][0] ^ t[0]);
        W[i][1] = (uint8_t)(W[i-8][1] ^ t[1]);
        W[i][2] = (uint8_t)(W[i-8][2] ^ t[2]);
        W[i][3] = (uint8_t)(W[i-8][3] ^ t[3]);
    }

    /* Pack 60 words into 15 round keys of 16 bytes each. */
    for (int r = 0; r < 15; r++) {
        for (int w = 0; w < 4; w++) {
            ctx->rk[r][4*w + 0] = W[4*r + w][0];
            ctx->rk[r][4*w + 1] = W[4*r + w][1];
            ctx->rk[r][4*w + 2] = W[4*r + w][2];
            ctx->rk[r][4*w + 3] = W[4*r + w][3];
        }
    }

    memzero(W, sizeof(W));
}

/* ------------------------------------------------------------------ */
/*  Single-block encryption                                           */
/* ------------------------------------------------------------------ */

/* Optional hardware override (see header). */
static aes_ct_256_encrypt_fn s_override_fn = NULL;
static void* s_override_ctx = NULL;

void aes_ct_256_set_override(aes_ct_256_encrypt_fn fn, void* ctx_user) {
    s_override_fn = fn;
    s_override_ctx = ctx_user;
}

/* Software AES-256 encrypt against a precomputed key schedule. */
static void aes_ct_256_ecb_encrypt_sw(const aes_ct_256_ctx* ctx,
                                       const uint8_t in[16],
                                       uint8_t out[16]) {
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, ctx->rk[0]);

    for (int round = 1; round < 14; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->rk[round]);
    }

    /* Final round: SubBytes, ShiftRows, AddRoundKey (no MixColumns). */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->rk[14]);

    memcpy(out, state, 16);
    memzero(state, sizeof(state));
}

void aes_ct_256_ecb_encrypt(const aes_ct_256_ctx* ctx,
                             const uint8_t in[16],
                             uint8_t out[16]) {
    if (s_override_fn != NULL) {
        /* The hardware backend takes the raw key, not the schedule. We
         * recover it from rk[0]+rk[1] which by construction is the
         * original AES-256 master key. This avoids changing the override
         * signature for the typical FF1 use case where the same key is
         * used for many encryptions. */
        uint8_t master[32];
        memcpy(master,      ctx->rk[0], 16);
        memcpy(master + 16, ctx->rk[1], 16);
        s_override_fn(s_override_ctx, master, in, out);
        memzero(master, sizeof(master));
        return;
    }
    aes_ct_256_ecb_encrypt_sw(ctx, in, out);
}

void aes_ct_256_encrypt_single(const uint8_t key[32],
                                const uint8_t in[16],
                                uint8_t out[16]) {
    if (s_override_fn != NULL) {
        s_override_fn(s_override_ctx, key, in, out);
        return;
    }
    aes_ct_256_ctx ctx;
    aes_ct_256_keysched(key, &ctx);
    aes_ct_256_ecb_encrypt_sw(&ctx, in, out);
    memzero(&ctx, sizeof(ctx));
}

/* ------------------------------------------------------------------ */
/*  Self-test (FIPS-197 §C.3 KAT)                                     */
/* ------------------------------------------------------------------ */

int aes_ct_256_self_test(void) {
    static const uint8_t kat_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t kat_in[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    static const uint8_t kat_out[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };

    /* Run the SOFTWARE path explicitly even if a hardware override is
     * registered: the self-test verifies the constant-time fallback,
     * which is what gets used if the hardware backend ever fails. */
    aes_ct_256_ctx ctx;
    aes_ct_256_keysched(kat_key, &ctx);

    uint8_t got[16];
    aes_ct_256_ecb_encrypt_sw(&ctx, kat_in, got);

    int ok = 1;
    /* Constant-time comparison so a self-test failure does not leak via
     * timing which byte differed. */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(got[i] ^ kat_out[i]);
    if (diff != 0) ok = 0;

    memzero(&ctx, sizeof(ctx));
    memzero(got, sizeof(got));
    return ok;
}
