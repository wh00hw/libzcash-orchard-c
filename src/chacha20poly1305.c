/**
 * ChaCha20-Poly1305 AEAD (RFC 7539).
 *
 * Audit notes:
 *   - All arithmetic on secret material uses constant-time C operations
 *     (`+`, `^`, `&`, shifts). No table lookups; no secret-dependent
 *     branches. ChaCha20 itself is inherently CT.
 *   - Poly1305 reduction modulo 2^130 - 5 uses the 26-bit-limb
 *     representation from poly1305-donna, which performs all field
 *     operations with branch-free integer arithmetic.
 *   - The tag comparison in decrypt() is OR-accumulated across all 16
 *     bytes (no early-out), then collapsed to a single 0/1 result.
 */
#include "chacha20poly1305.h"
#include "memzero.h"
#include <string.h>

/* ----------------------------------------------------------------- */
/*  ChaCha20 (RFC 7539 §2.3)                                         */
/* ----------------------------------------------------------------- */

static inline uint32_t rotl32(uint32_t v, unsigned n) {
    return (v << n) | (v >> (32 - n));
}

static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define QR(a, b, c, d)                  \
    do {                                \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d,  8); \
        c += d; b ^= c; b = rotl32(b,  7); \
    } while (0)

/* Produce one 64-byte ChaCha20 block at (key, nonce, counter) into out. */
static void chacha20_block(uint8_t out[64],
                           const uint8_t key[32],
                           const uint8_t nonce[12],
                           uint32_t counter) {
    uint32_t s[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,  /* "expand 32-byte k" */
        load32_le(key +  0), load32_le(key +  4),
        load32_le(key +  8), load32_le(key + 12),
        load32_le(key + 16), load32_le(key + 20),
        load32_le(key + 24), load32_le(key + 28),
        counter,
        load32_le(nonce + 0), load32_le(nonce + 4), load32_le(nonce + 8)
    };
    uint32_t w[16];
    memcpy(w, s, sizeof(w));

    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QR(w[0], w[4], w[8],  w[12]);
        QR(w[1], w[5], w[9],  w[13]);
        QR(w[2], w[6], w[10], w[14]);
        QR(w[3], w[7], w[11], w[15]);
        /* Diagonal rounds */
        QR(w[0], w[5], w[10], w[15]);
        QR(w[1], w[6], w[11], w[12]);
        QR(w[2], w[7], w[8],  w[13]);
        QR(w[3], w[4], w[9],  w[14]);
    }

    for (int i = 0; i < 16; i++) {
        store32_le(out + 4 * i, w[i] + s[i]);
    }

    memzero(w, sizeof(w));
    memzero(s, sizeof(s));
}

/* Encrypt (or decrypt — XOR is symmetric) `len` bytes from in to out using
 * ChaCha20(key, nonce) starting at the given block counter. */
static void chacha20_xor(uint8_t* out, const uint8_t* in, size_t len,
                         const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t initial_counter) {
    uint8_t block[64];
    uint32_t counter = initial_counter;
    size_t off = 0;
    while (len > 0) {
        chacha20_block(block, key, nonce, counter);
        size_t take = (len > 64) ? 64 : len;
        for (size_t i = 0; i < take; i++) {
            out[off + i] = in[off + i] ^ block[i];
        }
        off += take;
        len -= take;
        counter++;
    }
    memzero(block, sizeof(block));
}

/* ----------------------------------------------------------------- */
/*  Poly1305 (RFC 7539 §2.5) — 26-bit-limb representation             */
/* ----------------------------------------------------------------- */
/*
 * Five 26-bit limbs h[0..4] hold the 130-bit accumulator; the prime
 * is p = 2^130 - 5. Multiplication by r is performed limb-by-limb
 * and reduced modulo p with the partial-reduction trick from the
 * poly1305-donna reference. The clamping of r is per RFC 7539:
 *   r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
 */

typedef struct {
    /* Accumulator h, in 26-bit limbs. */
    uint32_t h[5];
    /* Key r, in 26-bit limbs (5 limbs). */
    uint32_t r[5];
    /* Key pad s, in 32-bit limbs (4 limbs). */
    uint32_t pad[4];
    /* Leftover block buffer (Poly1305 processes 16-byte blocks). */
    uint8_t  leftover[16];
    size_t   leftover_len;
    /* If true, this is the final block — process it with the
     * "high bit not set" rule for non-16 sizes. */
    int final;
} poly1305_ctx;

static void poly1305_init(poly1305_ctx* ctx, const uint8_t key[32]) {
    /* Clamp r per RFC. */
    uint32_t t0 = load32_le(key + 0);
    uint32_t t1 = load32_le(key + 4);
    uint32_t t2 = load32_le(key + 8);
    uint32_t t3 = load32_le(key + 12);

    ctx->r[0] = (t0                       ) & 0x03ffffffu;
    ctx->r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x03ffff03u;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffc0ffu;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03f03fffu;
    ctx->r[4] = ((t3 >>  8)               ) & 0x000fffffu;

    ctx->pad[0] = load32_le(key + 16);
    ctx->pad[1] = load32_le(key + 20);
    ctx->pad[2] = load32_le(key + 24);
    ctx->pad[3] = load32_le(key + 28);

    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;
    ctx->leftover_len = 0;
    ctx->final = 0;
}

static void poly1305_blocks(poly1305_ctx* ctx, const uint8_t* m, size_t bytes) {
    const uint32_t hibit = ctx->final ? 0u : (1u << 24);
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2],
             r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
             h3 = ctx->h[3], h4 = ctx->h[4];

    while (bytes >= 16) {
        /* h += m[i] */
        h0 += (load32_le(m +  0)                       ) & 0x03ffffffu;
        h1 += ((load32_le(m +  3) >> 2)                 ) & 0x03ffffffu;
        h2 += ((load32_le(m +  6) >> 4)                 ) & 0x03ffffffu;
        h3 += ((load32_le(m +  9) >> 6)                 ) & 0x03ffffffu;
        h4 += ((load32_le(m + 12) >> 8) | hibit);

        /* h *= r,  mod 2^130 - 5 (partial reduction) */
        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3
                    + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4
                    + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0
                    + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1
                    + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2
                    + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        /* (partial) h %= p */
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffffu;
        d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffffu;
        d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffffu;
        d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffffu;
        d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffffu;
        h0 += c * 5;
        c = (h0 >> 26);           h0 = h0 & 0x03ffffffu;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
    ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly1305_update(poly1305_ctx* ctx, const uint8_t* m, size_t bytes) {
    /* Drain any leftover bytes from a previous call. */
    if (ctx->leftover_len) {
        size_t want = 16 - ctx->leftover_len;
        if (want > bytes) want = bytes;
        for (size_t i = 0; i < want; i++) {
            ctx->leftover[ctx->leftover_len + i] = m[i];
        }
        bytes -= want;
        m += want;
        ctx->leftover_len += want;
        if (ctx->leftover_len < 16) return;
        poly1305_blocks(ctx, ctx->leftover, 16);
        ctx->leftover_len = 0;
    }
    /* Process full blocks straight from m. */
    if (bytes >= 16) {
        size_t want = bytes & ~((size_t)15);
        poly1305_blocks(ctx, m, want);
        m += want;
        bytes -= want;
    }
    /* Buffer the rest. */
    if (bytes) {
        for (size_t i = 0; i < bytes; i++) ctx->leftover[i] = m[i];
        ctx->leftover_len = bytes;
    }
}

static void poly1305_finish(poly1305_ctx* ctx, uint8_t tag[16]) {
    /* Process the last partial block (if any) with the "high bit not
     * set" rule and 16-byte zero-padding. */
    if (ctx->leftover_len) {
        size_t i = ctx->leftover_len;
        ctx->leftover[i++] = 1;
        while (i < 16) ctx->leftover[i++] = 0;
        ctx->final = 1;
        poly1305_blocks(ctx, ctx->leftover, 16);
    }

    /* Fully reduce h mod p. */
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
             h3 = ctx->h[3], h4 = ctx->h[4];

    uint32_t c;
    c = h1 >> 26; h1 &= 0x03ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x03ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x03ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x03ffffffu; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x03ffffffu; h1 += c;

    /* Compute h - p in g, select g if h >= p (constant-time). */
    uint32_t g0 = h0 + 5;
    c = g0 >> 26; g0 &= 0x03ffffffu;
    uint32_t g1 = h1 + c;
    c = g1 >> 26; g1 &= 0x03ffffffu;
    uint32_t g2 = h2 + c;
    c = g2 >> 26; g2 &= 0x03ffffffu;
    uint32_t g3 = h3 + c;
    c = g3 >> 26; g3 &= 0x03ffffffu;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h to 32-bit limbs */
    uint32_t h0_32 =  h0       | (h1 << 26);
    uint32_t h1_32 = (h1 >>  6) | (h2 << 20);
    uint32_t h2_32 = (h2 >> 12) | (h3 << 14);
    uint32_t h3_32 = (h3 >> 18) | (h4 <<  8);

    /* tag = (h + pad) mod 2^128 */
    uint64_t f = (uint64_t)h0_32 + ctx->pad[0];
    h0_32 = (uint32_t)f;
    f = (uint64_t)h1_32 + ctx->pad[1] + (f >> 32);
    h1_32 = (uint32_t)f;
    f = (uint64_t)h2_32 + ctx->pad[2] + (f >> 32);
    h2_32 = (uint32_t)f;
    f = (uint64_t)h3_32 + ctx->pad[3] + (f >> 32);
    h3_32 = (uint32_t)f;

    store32_le(tag +  0, h0_32);
    store32_le(tag +  4, h1_32);
    store32_le(tag +  8, h2_32);
    store32_le(tag + 12, h3_32);

    memzero(ctx, sizeof(*ctx));
}

/* ----------------------------------------------------------------- */
/*  AEAD construction (RFC 7539 §2.8)                                */
/* ----------------------------------------------------------------- */

static void pad16(poly1305_ctx* p, size_t len) {
    static const uint8_t z[16] = {0};
    size_t r = len & 15;
    if (r) poly1305_update(p, z, 16 - r);
}

void chacha20poly1305_encrypt(
    const uint8_t key[CHACHA20_KEY_SIZE],
    const uint8_t nonce[CHACHA20_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag_out[CHACHA20POLY1305_TAG_SIZE])
{
    /* Derive the Poly1305 one-time key from ChaCha20 block 0. */
    uint8_t block0[64];
    chacha20_block(block0, key, nonce, 0);

    poly1305_ctx p;
    poly1305_init(&p, block0);

    /* Encrypt plaintext with counter starting at 1. */
    chacha20_xor(ct, pt, pt_len, key, nonce, 1);

    /* MAC over: aad || pad16 || ciphertext || pad16 || u64(aad_len) || u64(ct_len) */
    if (aad_len) {
        poly1305_update(&p, aad, aad_len);
        pad16(&p, aad_len);
    }
    poly1305_update(&p, ct, pt_len);
    pad16(&p, pt_len);

    uint8_t lengths[16];
    uint64_t a = (uint64_t)aad_len, c = (uint64_t)pt_len;
    for (int i = 0; i < 8; i++) { lengths[i]     = (uint8_t)(a >> (8 * i)); }
    for (int i = 0; i < 8; i++) { lengths[8 + i] = (uint8_t)(c >> (8 * i)); }
    poly1305_update(&p, lengths, 16);

    poly1305_finish(&p, tag_out);

    memzero(block0, sizeof(block0));
    memzero(lengths, sizeof(lengths));
}

static int ct_memequal_local(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    /* Collapse non-zero to 0, zero to 1. */
    uint32_t v = diff;
    v = (v | (uint32_t)(0u - v)) >> 8;  /* 0 if all-zero, else 1 in bit 0..7 */
    return (int)(1u - (v & 1u));
}

int chacha20poly1305_decrypt(
    const uint8_t key[CHACHA20_KEY_SIZE],
    const uint8_t nonce[CHACHA20_NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
    uint8_t* pt)
{
    uint8_t block0[64];
    chacha20_block(block0, key, nonce, 0);

    poly1305_ctx p;
    poly1305_init(&p, block0);

    if (aad_len) {
        poly1305_update(&p, aad, aad_len);
        pad16(&p, aad_len);
    }
    poly1305_update(&p, ct, ct_len);
    pad16(&p, ct_len);

    uint8_t lengths[16];
    uint64_t a = (uint64_t)aad_len, c = (uint64_t)ct_len;
    for (int i = 0; i < 8; i++) { lengths[i]     = (uint8_t)(a >> (8 * i)); }
    for (int i = 0; i < 8; i++) { lengths[8 + i] = (uint8_t)(c >> (8 * i)); }
    poly1305_update(&p, lengths, 16);

    uint8_t expected_tag[16];
    poly1305_finish(&p, expected_tag);

    int ok = ct_memequal_local(expected_tag, tag, 16);
    memzero(expected_tag, sizeof(expected_tag));
    memzero(block0, sizeof(block0));
    memzero(lengths, sizeof(lengths));

    if (!ok) return -1;

    /* Tag verified; safe to decrypt. */
    chacha20_xor(pt, ct, ct_len, key, nonce, 1);
    return 0;
}

/* ----------------------------------------------------------------- */
/*  Self-test against RFC 7539 §A.5                                  */
/* ----------------------------------------------------------------- */

int chacha20poly1305_self_test(void)
{
    /* RFC 7539 §2.8.2 / §A.5 reference vector. */
    static const uint8_t key[32] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f,
    };
    static const uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47,
    };
    static const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7,
    };
    static const char pt_str[] =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    /* `pt_str` includes a trailing NUL; the RFC vector covers the 114
     * payload bytes without it. */
    const uint8_t* pt = (const uint8_t*)pt_str;
    const size_t pt_len = sizeof(pt_str) - 1;
    /* RFC 7539 §A.5 (correctly transcribed expected ciphertext). */
    static const uint8_t expected_ct[114] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
        0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
        0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
        0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
        0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
        0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
        0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
        0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16,
    };
    static const uint8_t expected_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
    };

    uint8_t ct[114];
    uint8_t tag[16];
    chacha20poly1305_encrypt(
        key, nonce,
        aad, sizeof(aad),
        pt, pt_len,
        ct, tag);

    if (memcmp(ct, expected_ct, sizeof(expected_ct)) != 0) return 0;
    if (memcmp(tag, expected_tag, sizeof(expected_tag)) != 0) return 0;

    uint8_t roundtrip[114];
    int rc = chacha20poly1305_decrypt(
        key, nonce,
        aad, sizeof(aad),
        ct, sizeof(expected_ct), tag, roundtrip);
    if (rc != 0) return 0;
    if (memcmp(roundtrip, pt, pt_len) != 0) return 0;

    /* Tamper with the tag and re-decrypt: must fail. */
    tag[0] ^= 1;
    rc = chacha20poly1305_decrypt(
        key, nonce,
        aad, sizeof(aad),
        ct, sizeof(expected_ct), tag, roundtrip);
    if (rc == 0) return 0;

    return 1;
}
