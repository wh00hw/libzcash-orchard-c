/**
 * Orchard Signing Context — enforces ZIP-244 verification before signing.
 *
 * This module wraps the signing state machine so that:
 *   1. The caller feeds TX metadata + action data (TX_OUTPUT messages)
 *   2. The context computes the ZIP-244 sighash incrementally
 *   3. The caller provides the expected sighash for comparison
 *   4. Only after successful verification can sign() be called
 *
 * Attempting to sign without completing ZIP-244 verification returns an error.
 * This is a library-level invariant that firmware cannot bypass.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "zip244.h"

typedef enum {
    SIGNER_IDLE,                     /* Waiting for metadata */
    SIGNER_RECEIVING_TRANSPARENT,    /* Collecting transparent inputs/outputs (v3) */
    SIGNER_RECEIVING_ACTIONS,        /* Metadata received, collecting actions */
    SIGNER_VERIFIED,                 /* ZIP-244 sighash verified, signing allowed */
} OrchardSignerState;

typedef enum {
    SIGNER_OK = 0,
    SIGNER_ERR_BAD_META,          /* Invalid metadata payload */
    SIGNER_ERR_BAD_ACTION,        /* Invalid action data */
    SIGNER_ERR_BAD_STATE,         /* Unexpected call for current state */
    SIGNER_ERR_SIGHASH_MISMATCH,  /* Device-computed sighash != companion sighash */
    SIGNER_ERR_NOT_VERIFIED,      /* sign() called without verification */
    SIGNER_ERR_WRONG_SIGHASH,     /* SIGN_REQ sighash doesn't match verified one */
    SIGNER_ERR_SIGN_FAILED,       /* redpallas_sign returned error */
    SIGNER_ERR_NETWORK_MISMATCH,         /* TxMeta coin_type != session coin_type */
    SIGNER_ERR_TRANSPARENT_BAD_INPUT,    /* Invalid transparent input data */
    SIGNER_ERR_TRANSPARENT_BAD_OUTPUT,   /* Invalid transparent output data */
    SIGNER_ERR_TRANSPARENT_MISMATCH,     /* Transparent digest mismatch (v3) */
    SIGNER_ERR_SAPLING_NOT_EMPTY,        /* sapling_digest != empty-bundle constant
                                            (Orchard-only invariant violation) */
    SIGNER_ERR_NOTE_COMMITMENT_MISMATCH, /* device-recomputed cmx != action.cmx
                                            (companion-claimed recipient does not
                                            match the recipient committed in the
                                            output note — siphoning attempt) */
} OrchardSignerError;

typedef struct {
    OrchardSignerState state;
    Zip244TxMeta tx_meta;
    Zip244ActionsState actions_state;
    Zip244TransparentState transparent_state;   /* v3: transparent digest */
    uint16_t actions_expected;
    uint16_t actions_received;
    uint16_t transparent_inputs_expected;
    uint16_t transparent_outputs_expected;
    bool has_meta;
    bool transparent_verified;                  /* v3: transparent digest matched */
    uint8_t verified_sighash[32];
    /** Session coin_type set by FvkReq. 0 = unset (backward compat). */
    uint32_t coin_type;
} OrchardSignerCtx;

/**
 * Initialize the signing context. Must be called before any operation.
 */
void orchard_signer_init(OrchardSignerCtx *ctx);

/**
 * Reset the context (abort any in-progress session).
 */
void orchard_signer_reset(OrchardSignerCtx *ctx);

/**
 * Feed transaction metadata (called with HWP_TX_META_INDEX sentinel).
 * Transitions: IDLE → RECEIVING_ACTIONS.
 *
 * @param meta_data   Raw metadata bytes (ZIP244_TX_META_SIZE)
 * @param meta_len    Length of meta_data
 * @param total_actions  Number of actions to expect
 */
OrchardSignerError orchard_signer_feed_meta(OrchardSignerCtx *ctx,
                                             const uint8_t *meta_data, size_t meta_len,
                                             uint16_t total_actions);

/**
 * Feed one action's data (820 bytes).
 * Must be called in order: index 0, 1, ..., N-1.
 *
 * @param action_data  Raw action bytes (HWP_ACTION_DATA_SIZE)
 * @param action_len   Length of action_data
 */
OrchardSignerError orchard_signer_feed_action(OrchardSignerCtx *ctx,
                                               const uint8_t *action_data, size_t action_len);

/**
 * Feed one action together with the unencrypted output-note plaintext, and
 * verify that the action's cmx field commits to the claimed recipient.
 *
 * Without this verification, a hostile companion can put a cmx that commits
 * to an attacker recipient inside an action while telling the device's UI
 * "send to <Mario>" — the device would hash the action bytes correctly,
 * produce a valid sighash, and sign a transaction whose actual on-chain
 * effect is to pay the attacker. The defence is to recompute cmx on-device
 * from the (recipient, value, rseed) the companion claims, and require it
 * to match the cmx field at offset 96 of the action data byte-for-byte.
 *
 * Per Orchard's split-action design, the rho input to the output note's
 * NoteCommit is the action's nullifier (offset 32 of action_data); this
 * function uses that automatically — the caller does not pass rho.
 *
 * On mismatch: returns SIGNER_ERR_NOTE_COMMITMENT_MISMATCH and resets the
 * context so the partial action stream is discarded.
 *
 * @param ctx          Signing context (must be in RECEIVING_ACTIONS)
 * @param action_data  Raw action bytes (820)
 * @param action_len   Length of action_data
 * @param recipient    43 bytes = d[11] || pk_d[32] (raw Orchard address)
 * @param value        Output note value in zatoshis
 * @param rseed        32-byte note rseed
 */
OrchardSignerError orchard_signer_feed_action_with_note(
    OrchardSignerCtx *ctx,
    const uint8_t *action_data, size_t action_len,
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32]);

/**
 * Begin transparent digest verification (v3).
 * Call after feed_meta() when the transaction has transparent inputs.
 * Transitions: RECEIVING_ACTIONS → RECEIVING_TRANSPARENT.
 *
 * @param num_inputs   Expected number of transparent inputs
 * @param num_outputs  Expected number of transparent outputs
 */
OrchardSignerError orchard_signer_begin_transparent(OrchardSignerCtx *ctx,
                                                     uint16_t num_inputs,
                                                     uint16_t num_outputs);

/**
 * Feed one transparent input's data (v3).
 * Must be in RECEIVING_TRANSPARENT state.
 */
OrchardSignerError orchard_signer_feed_transparent_input(OrchardSignerCtx *ctx,
                                                          const uint8_t *data, size_t data_len);

/**
 * Feed one transparent output's data (v3).
 * Must be in RECEIVING_TRANSPARENT state.
 */
OrchardSignerError orchard_signer_feed_transparent_output(OrchardSignerCtx *ctx,
                                                           const uint8_t *data, size_t data_len);

/**
 * Verify the transparent digest against TxMeta's transparent_sig_digest (v3).
 * Transitions: RECEIVING_TRANSPARENT → RECEIVING_ACTIONS (on match).
 *
 * @param expected_digest  32-byte expected transparent digest from companion
 */
OrchardSignerError orchard_signer_verify_transparent(OrchardSignerCtx *ctx,
                                                      const uint8_t expected_digest[32]);

/**
 * Feed the expected sighash (sentinel message) and verify.
 * Transitions: RECEIVING_ACTIONS → VERIFIED (on match) or resets (on mismatch).
 *
 * @param expected_sighash  32-byte sighash from companion
 */
OrchardSignerError orchard_signer_verify(OrchardSignerCtx *ctx,
                                          const uint8_t expected_sighash[32]);

/**
 * Check if the context is in VERIFIED state and the sighash matches.
 * Call this before signing to enforce the invariant.
 *
 * @param sighash  32-byte sighash from SIGN_REQ
 */
OrchardSignerError orchard_signer_check(const OrchardSignerCtx *ctx,
                                         const uint8_t sighash[32]);

/**
 * Sign a transaction action. Enforces that ZIP-244 verification passed
 * and that the SIGN_REQ sighash matches the verified one.
 *
 * @param ctx       Signing context (must be VERIFIED)
 * @param sighash   32-byte sighash (must match verified sighash)
 * @param ask       32-byte spend authorization key
 * @param alpha     32-byte randomizer
 * @param sig_out   64-byte signature output
 * @param rk_out    32-byte randomized key output
 */
OrchardSignerError orchard_signer_sign(const OrchardSignerCtx *ctx,
                                        const uint8_t sighash[32],
                                        const uint8_t ask[32],
                                        const uint8_t alpha[32],
                                        uint8_t sig_out[64],
                                        uint8_t rk_out[32]);
