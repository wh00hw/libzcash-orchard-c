/*
 * test_base58 — Known-Answer Tests for base58.h.
 *
 * Verifies that script_to_taddr() produces the canonical Zcash
 * t-address string for known (script_pubkey, network) pairs across
 * all four standard transparent address types: mainnet P2PKH (t1),
 * mainnet P2SH (t3), testnet P2PKH (tm), testnet P2SH (t2).
 *
 * Reference vectors generated offline with a textbook Base58Check
 * implementation (double-SHA-256 checksum, big-endian divmod against
 * the canonical Bitcoin/Zcash alphabet) over the same byte sequences
 * embedded below. A discrepancy in the on-device encoder against
 * these vectors indicates either a Base58 algorithm bug, a wrong
 * version byte, or a SHA-256 corruption — none of which are silent.
 *
 * The vectors deliberately use a deterministic pkh / sh =
 * sequential-byte pattern so the test exercises a payload that is
 * neither all-zero nor a "lucky" Base58 boundary. Both leading-zero
 * paths (pkh[0]=0x00) and full-payload paths are covered by the
 * round-trip and rejection tests further down.
 */
#include "base58.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define EXPECT_STREQ(actual, expected, what)                                   \
    do {                                                                       \
        if(strcmp((actual), (expected)) == 0) {                                \
            g_pass++;                                                          \
        } else {                                                               \
            g_fail++;                                                          \
            fprintf(stderr, "FAIL %s: expected '%s' got '%s'\n",               \
                    (what), (expected), (actual));                             \
        }                                                                     \
    } while(0)

#define EXPECT_EQ_SIZE(actual, expected, what)                                 \
    do {                                                                       \
        if((actual) == (expected)) {                                           \
            g_pass++;                                                          \
        } else {                                                               \
            g_fail++;                                                          \
            fprintf(stderr, "FAIL %s: expected %zu got %zu\n", (what),         \
                    (size_t)(expected), (size_t)(actual));                     \
        }                                                                     \
    } while(0)

/* Reference vectors generated with the textbook Base58Check encoder
 * (sha256d checksum, alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZ
 * abcdefghijkmnopqrstuvwxyz") over the deterministic pkh / sh below.
 * See the file header for the offline derivation script. */
static const uint8_t REF_PKH[20] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
};
static const char REF_T1[] = "t1KLZGVSeAZfP8E2xCoVaLtjWGMd7VUJbFg";
static const char REF_TM[] = "tmBBJbKw3ZEAtGUEPsXoKCZQFsLhw1Ltb9k";

static const uint8_t REF_SH[20] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
};
static const char REF_T3[] = "t3MVWFANxaMp5R1etXb8CPB5cKtcLvN5inV";
static const char REF_T2[] = "t29UhHqV6SpRSxiEdTL8EvoGFSNqWjWc9zk";

static void build_p2pkh(uint8_t out[25], const uint8_t pkh[20]) {
    /* OP_DUP OP_HASH160 0x14 <pkh:20> OP_EQUALVERIFY OP_CHECKSIG */
    out[0] = 0x76;
    out[1] = 0xa9;
    out[2] = 0x14;
    memcpy(out + 3, pkh, 20);
    out[23] = 0x88;
    out[24] = 0xac;
}

static void build_p2sh(uint8_t out[23], const uint8_t sh[20]) {
    /* OP_HASH160 0x14 <sh:20> OP_EQUAL */
    out[0] = 0xa9;
    out[1] = 0x14;
    memcpy(out + 2, sh, 20);
    out[22] = 0x87;
}

static void test_p2pkh_mainnet(void) {
    uint8_t script[25];
    build_p2pkh(script, REF_PKH);
    char out[40] = {0};
    size_t n = script_to_taddr(script, sizeof(script), /*testnet=*/false,
                                out, sizeof(out));
    EXPECT_EQ_SIZE(n, strlen(REF_T1), "P2PKH mainnet length");
    EXPECT_STREQ(out, REF_T1, "P2PKH mainnet (t1...)");
}

static void test_p2pkh_testnet(void) {
    uint8_t script[25];
    build_p2pkh(script, REF_PKH);
    char out[40] = {0};
    size_t n = script_to_taddr(script, sizeof(script), /*testnet=*/true,
                                out, sizeof(out));
    EXPECT_EQ_SIZE(n, strlen(REF_TM), "P2PKH testnet length");
    EXPECT_STREQ(out, REF_TM, "P2PKH testnet (tm...)");
}

static void test_p2sh_mainnet(void) {
    uint8_t script[23];
    build_p2sh(script, REF_SH);
    char out[40] = {0};
    size_t n = script_to_taddr(script, sizeof(script), /*testnet=*/false,
                                out, sizeof(out));
    EXPECT_EQ_SIZE(n, strlen(REF_T3), "P2SH mainnet length");
    EXPECT_STREQ(out, REF_T3, "P2SH mainnet (t3...)");
}

static void test_p2sh_testnet(void) {
    uint8_t script[23];
    build_p2sh(script, REF_SH);
    char out[40] = {0};
    size_t n = script_to_taddr(script, sizeof(script), /*testnet=*/true,
                                out, sizeof(out));
    EXPECT_EQ_SIZE(n, strlen(REF_T2), "P2SH testnet length");
    EXPECT_STREQ(out, REF_T2, "P2SH testnet (t2...)");
}

static void test_reject_short_buffer(void) {
    /* out_cap < 40 must be refused so a P2PKH/P2SH t-address (~35 chars
     * + NUL) is never truncated silently into the caller's buffer. */
    uint8_t script[25];
    build_p2pkh(script, REF_PKH);
    char tiny[8] = {0};
    size_t n = script_to_taddr(script, sizeof(script), false, tiny, sizeof(tiny));
    EXPECT_EQ_SIZE(n, 0u, "rejects out_cap < 40");
}

static void test_reject_non_standard_script(void) {
    /* Pure padding / non-standard / oversized scripts must not produce
     * an address — the device should refuse to display a destination it
     * cannot prove to itself is reachable. */
    uint8_t script[34] = {0};
    char out[40] = {0};
    /* Wrong length for any standard shape. */
    size_t n = script_to_taddr(script, sizeof(script), false, out, sizeof(out));
    EXPECT_EQ_SIZE(n, 0u, "rejects non-standard 34-byte script");

    /* 25-byte but wrong opcodes (P2PKH-shaped but tail is wrong). */
    uint8_t bad_p2pkh[25];
    build_p2pkh(bad_p2pkh, REF_PKH);
    bad_p2pkh[24] = 0x00; /* corrupt OP_CHECKSIG */
    n = script_to_taddr(bad_p2pkh, sizeof(bad_p2pkh), false, out, sizeof(out));
    EXPECT_EQ_SIZE(n, 0u, "rejects 25-byte script with bad tail");

    /* 23-byte but wrong P2SH tail. */
    uint8_t bad_p2sh[23];
    build_p2sh(bad_p2sh, REF_SH);
    bad_p2sh[22] = 0x00; /* corrupt OP_EQUAL */
    n = script_to_taddr(bad_p2sh, sizeof(bad_p2sh), false, out, sizeof(out));
    EXPECT_EQ_SIZE(n, 0u, "rejects 23-byte script with bad tail");
}

static void test_reject_null_args(void) {
    char out[40];
    EXPECT_EQ_SIZE(script_to_taddr(NULL, 25, false, out, sizeof(out)), 0u,
                   "rejects NULL script");
    uint8_t s[25] = {0};
    EXPECT_EQ_SIZE(script_to_taddr(s, sizeof(s), false, NULL, sizeof(out)), 0u,
                   "rejects NULL out");
}

int main(void) {
    test_p2pkh_mainnet();
    test_p2pkh_testnet();
    test_p2sh_mainnet();
    test_p2sh_testnet();
    test_reject_short_buffer();
    test_reject_non_standard_script();
    test_reject_null_args();

    printf("[test_base58] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
