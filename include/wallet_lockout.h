#pragma once

/**
 * Pure-data lockout state for PIN-protected hardware wallets.
 *
 * The library provides ONLY the state struct and operations on it; the
 * firmware decides where to persist the struct (NVS, file, eFuse-mirrored
 * counter, etc.) and what "wipe" means on its target.
 *
 * Hardware-agnostic: any MCU port serializes the 32-byte struct to its
 * persistent storage and calls the `record_*` / `should_wipe` helpers
 * around its PIN-verification boundary.
 *
 * Audit: docs/security-audit/{INDEX.md, ...} H-5.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WALLET_LOCKOUT_STATE_SIZE 32

/**
 * Lockout state. Always serialized as the first
 * WALLET_LOCKOUT_STATE_SIZE bytes of the struct (memcpy-safe; no
 * pointers, no padding-sensitive alignment). Firmware may store this
 * blob alongside or inside its sealed-seed file; the values are
 * non-secret (knowing them does not help an attacker).
 *
 * Layout:
 *   fail_count       (4 LE)  consecutive wrong-PIN since last success
 *   total_attempts   (4 LE)  lifetime attempt counter, monotonically increasing
 *   last_fail_unix   (8 LE)  unix timestamp of most recent failure (firmware's clock)
 *   reserved         (16)    zero, future use
 *
 * Total: 32 bytes.
 */
typedef struct {
    uint32_t fail_count;
    uint32_t total_attempts;
    uint64_t last_fail_unix;
    uint8_t  reserved[16];
} wallet_lockout_state_t;

/**
 * Initialise a fresh lockout state (all counters zeroed).
 */
void wallet_lockout_init(wallet_lockout_state_t* s);

/**
 * Returns true when the firmware MUST wipe the wallet. Caller chooses
 * `max_consecutive` (recommended: 5..10 for HW wallet UX).
 *
 * @param s                lockout state
 * @param max_consecutive  trigger threshold for fail_count
 */
bool wallet_lockout_should_wipe(
    const wallet_lockout_state_t* s,
    uint32_t max_consecutive);

/**
 * Record a successful PIN attempt. Resets `fail_count` to 0.
 * `total_attempts` is NOT reset — it is a lifetime counter.
 */
void wallet_lockout_record_success(wallet_lockout_state_t* s);

/**
 * Record a failed PIN attempt. Increments `fail_count` and
 * `total_attempts`, sets `last_fail_unix`.
 *
 * @param now_unix  current time (firmware's clock; monotonic counter
 *                  also acceptable). Used for time-based decay logic
 *                  in future revisions; the current API only stores it.
 */
void wallet_lockout_record_failure(
    wallet_lockout_state_t* s,
    uint64_t now_unix);

/**
 * Serialize state to a 32-byte blob (LE encoding). Firmware writes the
 * blob to its persistent storage. Buffers may not alias.
 */
void wallet_lockout_serialize(
    const wallet_lockout_state_t* s,
    uint8_t out[WALLET_LOCKOUT_STATE_SIZE]);

/**
 * Deserialize state from a 32-byte blob. Returns true on well-formed
 * input. Out-of-range field values trigger a defensive reset (caller
 * sees fail_count = 0; this is acceptable because corrupted state is
 * indistinguishable from "fresh wallet" and we err on usability).
 */
bool wallet_lockout_deserialize(
    wallet_lockout_state_t* s,
    const uint8_t in[WALLET_LOCKOUT_STATE_SIZE]);

#ifdef __cplusplus
}
#endif
