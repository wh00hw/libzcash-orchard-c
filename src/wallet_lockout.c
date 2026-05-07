/**
 * Pure-data lockout state operations.
 *
 * No I/O, no platform dependencies — every MCU port persists the
 * 32-byte serialized blob using whatever storage primitive it has
 * (NVS on ESP32, /ext/apps_data file on Flipper, etc.).
 *
 * Audit: H-5.
 */

#include "wallet_lockout.h"
#include "memzero.h"
#include <string.h>

void wallet_lockout_init(wallet_lockout_state_t* s) {
    memzero(s, sizeof(*s));
}

bool wallet_lockout_should_wipe(
    const wallet_lockout_state_t* s,
    uint32_t max_consecutive) {
    return s->fail_count >= max_consecutive;
}

void wallet_lockout_record_success(wallet_lockout_state_t* s) {
    s->fail_count = 0;
    /* total_attempts is INTENTIONALLY not reset; it is a lifetime
     * counter that lets firmware (or an external auditor) detect
     * unusual usage patterns. */
}

void wallet_lockout_record_failure(
    wallet_lockout_state_t* s,
    uint64_t now_unix) {
    /* Saturating increment — overflow indicates the device has been
     * brute-forced 4 billion times, which is implausible but harmless
     * to clamp. */
    if (s->fail_count    < 0xFFFFFFFFu) s->fail_count++;
    if (s->total_attempts < 0xFFFFFFFFu) s->total_attempts++;
    s->last_fail_unix = now_unix;
}

/* ------------------------------------------------------------------ */
/*  Serialization (little-endian, fixed 32-byte layout)               */
/* ------------------------------------------------------------------ */

static void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)( v        & 0xFF);
    p[1] = (uint8_t)((v >>  8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void write_u64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}

static uint32_t read_u32_le(const uint8_t* p) {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64_le(const uint8_t* p) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) r |= ((uint64_t)p[i]) << (8 * i);
    return r;
}

void wallet_lockout_serialize(
    const wallet_lockout_state_t* s,
    uint8_t out[WALLET_LOCKOUT_STATE_SIZE]) {
    write_u32_le(out + 0,  s->fail_count);
    write_u32_le(out + 4,  s->total_attempts);
    write_u64_le(out + 8,  s->last_fail_unix);
    memcpy(out + 16, s->reserved, sizeof(s->reserved));
}

bool wallet_lockout_deserialize(
    wallet_lockout_state_t* s,
    const uint8_t in[WALLET_LOCKOUT_STATE_SIZE]) {
    s->fail_count     = read_u32_le(in + 0);
    s->total_attempts = read_u32_le(in + 4);
    s->last_fail_unix = read_u64_le(in + 8);
    memcpy(s->reserved, in + 16, sizeof(s->reserved));

    /* Defensive: total_attempts cannot be < fail_count (consecutive
     * failures are also lifetime failures). If the persisted blob
     * disagrees, treat it as corrupted and reset. */
    if (s->total_attempts < s->fail_count) {
        wallet_lockout_init(s);
        return false;
    }
    return true;
}
