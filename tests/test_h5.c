/**
 * Tests for H-5 components:
 *   - aead_self_test (AES-256-CTR + HMAC-SHA256 roundtrip + tamper)
 *   - wallet_lockout state machine
 *   - wallet_pin_kdf reproducibility
 */

#include "aead.h"
#include "wallet_lockout.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failed = 0;
static int passed = 0;

#define ASSERT(cond) do { \
    if (cond) { passed++; printf("  PASS: %s\n", #cond); } \
    else      { failed++; printf("  FAIL: %s  (%s:%d)\n", #cond, __FILE__, __LINE__); } \
} while(0)

static void test_aead_self_test(void) {
    printf("\nAEAD self-test (FIPS-style roundtrip + tamper):\n");
    ASSERT(aead_self_test() == 1);
}

static void test_aead_inplace_roundtrip(void) {
    printf("\nAEAD: in-place encrypt/decrypt of a 64-byte secret:\n");
    uint8_t key[AEAD_KEY_SIZE];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(0x55 + i);

    uint8_t nonce[AEAD_NONCE_SIZE];
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(i * 11);

    uint8_t aad[] = "wallet.dat v1";
    uint8_t pt_orig[64];
    for (int i = 0; i < 64; i++) pt_orig[i] = (uint8_t)i;

    uint8_t buf[64];
    uint8_t tag[AEAD_TAG_SIZE];
    memcpy(buf, pt_orig, 64);

    /* In-place encrypt: ct overlaps pt */
    int rc = aead_aes256_ctr_hmac_seal(key, nonce, aad, sizeof(aad) - 1,
                                        buf, 64, buf, tag);
    ASSERT(rc == 0);

    int differs = 0;
    for (int i = 0; i < 64; i++) differs |= buf[i] ^ pt_orig[i];
    ASSERT(differs != 0);  /* ciphertext should differ from plaintext */

    /* In-place decrypt back */
    rc = aead_aes256_ctr_hmac_unseal(key, nonce, aad, sizeof(aad) - 1,
                                       buf, 64, tag, buf);
    ASSERT(rc == 0);

    int eq = 1;
    for (int i = 0; i < 64; i++) if (buf[i] != pt_orig[i]) { eq = 0; break; }
    ASSERT(eq == 1);
}

static void test_aead_wrong_key(void) {
    printf("\nAEAD: wrong key on unseal must fail:\n");
    uint8_t key[AEAD_KEY_SIZE]; memset(key, 0xAA, sizeof(key));
    uint8_t nonce[AEAD_NONCE_SIZE]; memset(nonce, 0xBB, sizeof(nonce));
    uint8_t pt[8] = {1,2,3,4,5,6,7,8};
    uint8_t ct[8], tag[AEAD_TAG_SIZE];

    aead_aes256_ctr_hmac_seal(key, nonce, NULL, 0, pt, 8, ct, tag);

    uint8_t wrong_key[AEAD_KEY_SIZE]; memset(wrong_key, 0xCC, sizeof(wrong_key));
    uint8_t recovered[8];
    int rc = aead_aes256_ctr_hmac_unseal(wrong_key, nonce, NULL, 0,
                                          ct, 8, tag, recovered);
    ASSERT(rc == -1);  /* must reject */
}

static void test_aead_kdf_deterministic(void) {
    printf("\nwallet_pin_kdf: same (pin, salt, iters) => same key:\n");
    uint8_t pin[] = "12345";
    uint8_t salt[16];
    for (int i = 0; i < 16; i++) salt[i] = (uint8_t)(i * 7);

    uint8_t k1[AEAD_KEY_SIZE], k2[AEAD_KEY_SIZE];
    wallet_pin_kdf(pin, sizeof(pin) - 1, salt, sizeof(salt), 1000, k1);
    wallet_pin_kdf(pin, sizeof(pin) - 1, salt, sizeof(salt), 1000, k2);

    int eq = (memcmp(k1, k2, AEAD_KEY_SIZE) == 0);
    ASSERT(eq == 1);

    /* Different PIN must produce a different key. */
    uint8_t pin2[] = "12346";
    uint8_t k3[AEAD_KEY_SIZE];
    wallet_pin_kdf(pin2, sizeof(pin2) - 1, salt, sizeof(salt), 1000, k3);
    int diff = (memcmp(k1, k3, AEAD_KEY_SIZE) != 0);
    ASSERT(diff == 1);
}

static void test_lockout_basic(void) {
    printf("\nLockout state machine:\n");
    wallet_lockout_state_t s;
    wallet_lockout_init(&s);

    ASSERT(s.fail_count == 0);
    ASSERT(s.total_attempts == 0);
    ASSERT(wallet_lockout_should_wipe(&s, 5) == false);

    /* Five failures → at threshold of 5. */
    for (int i = 0; i < 5; i++) wallet_lockout_record_failure(&s, 1000 + i);
    ASSERT(s.fail_count == 5);
    ASSERT(s.total_attempts == 5);
    ASSERT(wallet_lockout_should_wipe(&s, 5) == true);
    ASSERT(wallet_lockout_should_wipe(&s, 10) == false);

    /* Success resets fail_count but NOT total_attempts. */
    wallet_lockout_record_success(&s);
    ASSERT(s.fail_count == 0);
    ASSERT(s.total_attempts == 5);
    ASSERT(wallet_lockout_should_wipe(&s, 5) == false);
}

static void test_lockout_serialize(void) {
    printf("\nLockout serialize/deserialize roundtrip:\n");
    wallet_lockout_state_t a, b;
    wallet_lockout_init(&a);
    a.fail_count = 3;
    a.total_attempts = 7;
    a.last_fail_unix = 0xCAFEBABEDEADBEEFULL;

    uint8_t blob[WALLET_LOCKOUT_STATE_SIZE];
    wallet_lockout_serialize(&a, blob);

    bool ok = wallet_lockout_deserialize(&b, blob);
    ASSERT(ok == true);
    ASSERT(b.fail_count == 3);
    ASSERT(b.total_attempts == 7);
    ASSERT(b.last_fail_unix == 0xCAFEBABEDEADBEEFULL);

    /* Corruption: total_attempts < fail_count must trigger reset. */
    blob[0] = 99;  /* fail_count = 99 */
    blob[4] = 1;   /* total_attempts = 1 — corrupt */
    blob[5] = 0; blob[6] = 0; blob[7] = 0;
    ok = wallet_lockout_deserialize(&b, blob);
    ASSERT(ok == false);
    ASSERT(b.fail_count == 0);
    ASSERT(b.total_attempts == 0);
}

int main(void) {
    test_aead_self_test();
    test_aead_inplace_roundtrip();
    test_aead_wrong_key();
    test_aead_kdf_deterministic();
    test_lockout_basic();
    test_lockout_serialize();

    printf("\n=== Results: %d/%d tests passed ===\n", passed, passed + failed);
    return failed == 0 ? 0 : 1;
}
