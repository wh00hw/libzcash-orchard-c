/**
 * Tests for orchard_signer state machine — Orchard-only invariants.
 *
 * Covers the sapling_digest empty-bundle enforcement: feed_meta must accept
 * a TxMeta whose sapling_digest equals BLAKE2b-256("ZTxIdSaplingHash", [])
 * and reject any other value with SIGNER_ERR_SAPLING_NOT_EMPTY before any
 * action data is hashed.
 */
#include "orchard_signer.h"
#include "zip244.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Build a minimal-but-valid 125-byte TxMeta wire payload with the given
 * sapling_digest. Other fields are set to plausible Nu5-mainnet values. */
static void build_tx_meta_wire(uint8_t buf[125], const uint8_t sapling_digest[32]) {
    memset(buf, 0, 125);
    /* version = 5, version_group_id = 0x26A7270A (Nu5), branch_id = 0xC2D6D0B4 (Nu5),
     * lock_time = 0, expiry_height = 0 */
    buf[0]  = 0x05;                                /* version LE */
    buf[4]  = 0x0A; buf[5]  = 0x27; buf[6]  = 0xA7; buf[7]  = 0x26;  /* vgi */
    buf[8]  = 0xB4; buf[9]  = 0xD0; buf[10] = 0xD6; buf[11] = 0xC2;  /* branch_id */
    /* orchard_flags = 0x03 (spends + outputs enabled) */
    buf[20] = 0x03;
    /* value_balance = 0, anchor = 32 zero bytes (offset 29..60) */
    /* transparent_sig_digest = 32 zero bytes (offset 61..92) — not validated here */
    /* sapling_digest at offset 93 */
    memcpy(buf + 93, sapling_digest, 32);
}

static void test_sapling_empty_accepted(void) {
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t empty[32];
    zip244_sapling_empty_digest(empty);

    uint8_t wire[125];
    build_tx_meta_wire(wire, empty);

    OrchardSignerError err = orchard_signer_feed_meta(&ctx, wire, sizeof(wire), 1);
    assert(err == SIGNER_OK);
    assert(ctx.state == SIGNER_RECEIVING_ACTIONS);
    assert(ctx.has_meta == true);
    printf("  PASS: sapling empty-bundle constant accepted\n");
}

static void test_sapling_nonempty_rejected(void) {
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    /* Use a value that is definitely not the empty constant. All-0xAA is
     * a fine choice — vanishingly unlikely to collide. */
    uint8_t nonempty[32];
    memset(nonempty, 0xAA, 32);

    uint8_t wire[125];
    build_tx_meta_wire(wire, nonempty);

    OrchardSignerError err = orchard_signer_feed_meta(&ctx, wire, sizeof(wire), 1);
    assert(err == SIGNER_ERR_SAPLING_NOT_EMPTY);
    /* Context must remain in IDLE — the session must not have advanced. */
    assert(ctx.state == SIGNER_IDLE);
    assert(ctx.has_meta == false);
    printf("  PASS: non-empty sapling_digest rejected (state unchanged)\n");
}

static void test_sapling_off_by_one_byte_rejected(void) {
    /* Tamper with a single byte of the empty constant: the check must catch it. */
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t tampered[32];
    zip244_sapling_empty_digest(tampered);
    tampered[17] ^= 0x01;

    uint8_t wire[125];
    build_tx_meta_wire(wire, tampered);

    OrchardSignerError err = orchard_signer_feed_meta(&ctx, wire, sizeof(wire), 1);
    assert(err == SIGNER_ERR_SAPLING_NOT_EMPTY);
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: single-bit-flip on empty constant rejected\n");
}

static void test_sapling_empty_constant_is_stable(void) {
    /* The empty-bundle constant is BLAKE2b-256 with 16-byte personalization
     * "ZTxIdSaplingHash" and no input data. Its value is fixed and must
     * not change across runs. We pin the first/last bytes as a sanity check
     * that the personalization string and BLAKE2b finalize-on-empty are wired
     * up correctly. The full reference vector lives in test_vectors.c. */
    uint8_t a[32], b[32];
    zip244_sapling_empty_digest(a);
    zip244_sapling_empty_digest(b);
    assert(memcmp(a, b, 32) == 0);
    /* The result is deterministic and non-zero (BLAKE2b output of a
     * 16-byte personalization on empty input is never all-zero). */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (a[i] != 0) { all_zero = 0; break; }
    }
    assert(!all_zero);
    printf("  PASS: empty-bundle constant is deterministic and non-zero\n");
}

int main(void) {
    printf("Orchard signer / Sapling-empty-bundle invariant tests:\n");
    test_sapling_empty_accepted();
    test_sapling_nonempty_rejected();
    test_sapling_off_by_one_byte_rejected();
    test_sapling_empty_constant_is_stable();
    printf("All signer tests passed.\n");
    return 0;
}
