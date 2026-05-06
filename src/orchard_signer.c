/**
 * Orchard Signing Context — enforces ZIP-244 verification before signing.
 */
#include "orchard_signer.h"
#include "redpallas.h"
#include "orchard.h"
#include "memzero.h"
#include <string.h>

void orchard_signer_init(OrchardSignerCtx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = SIGNER_IDLE;
}

void orchard_signer_reset(OrchardSignerCtx *ctx)
{
    memzero(ctx->verified_sighash, sizeof(ctx->verified_sighash));
    orchard_signer_init(ctx);
}

OrchardSignerError orchard_signer_feed_meta(OrchardSignerCtx *ctx,
                                             const uint8_t *meta_data, size_t meta_len,
                                             uint16_t total_actions)
{
    if (ctx->state != SIGNER_IDLE) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!zip244_parse_tx_meta(meta_data, meta_len, &ctx->tx_meta)) {
        return SIGNER_ERR_BAD_META;
    }

    /* Validate coin_type consistency: if both session and TxMeta specify
     * a coin_type (non-zero), they must match. */
    if (ctx->coin_type != 0 && ctx->tx_meta.coin_type != 0 &&
        ctx->coin_type != ctx->tx_meta.coin_type) {
        return SIGNER_ERR_NETWORK_MISMATCH;
    }

    /* Orchard-only invariant: the wallet derives no Sapling keys, holds no
     * Sapling notes, and does not send to Sapling-only recipients. The
     * companion-supplied sapling_digest must therefore equal the ZIP-244
     * empty-bundle constant. Enforcing this on-device closes the last
     * sighash component that was previously trusted from the companion
     * and prevents a hostile companion from siphoning value via a hidden
     * Sapling output. Aborts the session before any action is hashed. */
    uint8_t sapling_empty[32];
    zip244_sapling_empty_digest(sapling_empty);
    if (!ct_memequal(ctx->tx_meta.sapling_digest, sapling_empty, 32)) {
        memzero(sapling_empty, sizeof(sapling_empty));
        memzero(&ctx->tx_meta, sizeof(ctx->tx_meta));
        return SIGNER_ERR_SAPLING_NOT_EMPTY;
    }
    memzero(sapling_empty, sizeof(sapling_empty));

    /* Per-action display storage is bounded; reject early if the tx claims
     * more outputs than we can display, rather than failing partway through
     * the action stream. */
    if (total_actions > ORCHARD_SIGNER_MAX_ACTIONS) {
        memzero(&ctx->tx_meta, sizeof(ctx->tx_meta));
        return SIGNER_ERR_TOO_MANY_ACTIONS;
    }

    zip244_actions_init(&ctx->actions_state);
    ctx->has_meta = true;
    ctx->actions_expected = total_actions;
    ctx->actions_received = 0;
    ctx->state = SIGNER_RECEIVING_ACTIONS;

    return SIGNER_OK;
}

/* ------------------------------------------------------------------ */
/*  Transparent digest verification (v3)                              */
/* ------------------------------------------------------------------ */

OrchardSignerError orchard_signer_begin_transparent(OrchardSignerCtx *ctx,
                                                     uint16_t num_inputs,
                                                     uint16_t num_outputs)
{
    /* Can begin transparent verification after metadata is received
     * but before (or instead of) starting actions. Accept from
     * RECEIVING_ACTIONS state (after feed_meta). */
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }

    zip244_transparent_init(&ctx->transparent_state);
    ctx->transparent_inputs_expected = num_inputs;
    ctx->transparent_outputs_expected = num_outputs;
    ctx->transparent_verified = false;
    ctx->state = SIGNER_RECEIVING_TRANSPARENT;

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_feed_transparent_input(OrchardSignerCtx *ctx,
                                                          const uint8_t *data, size_t data_len)
{
    if (ctx->state != SIGNER_RECEIVING_TRANSPARENT) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.inputs_received >= ctx->transparent_inputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!zip244_hash_transparent_input(&ctx->transparent_state, data, data_len)) {
        return SIGNER_ERR_TRANSPARENT_BAD_INPUT;
    }

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_feed_transparent_output(OrchardSignerCtx *ctx,
                                                           const uint8_t *data, size_t data_len)
{
    if (ctx->state != SIGNER_RECEIVING_TRANSPARENT) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.outputs_received >= ctx->transparent_outputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!zip244_hash_transparent_output(&ctx->transparent_state, data, data_len)) {
        return SIGNER_ERR_TRANSPARENT_BAD_OUTPUT;
    }

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_verify_transparent(OrchardSignerCtx *ctx,
                                                      const uint8_t expected_digest[32])
{
    if (ctx->state != SIGNER_RECEIVING_TRANSPARENT) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.inputs_received != ctx->transparent_inputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.outputs_received != ctx->transparent_outputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    /* Compute transparent digest from received inputs/outputs */
    uint8_t computed[32];
    zip244_transparent_digest(&ctx->transparent_state, computed);

    /* Verify against TxMeta's transparent_sig_digest */
    if (!ct_memequal(computed, ctx->tx_meta.transparent_sig_digest, 32)) {
        memzero(computed, sizeof(computed));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TRANSPARENT_MISMATCH;
    }

    /* Also verify against the expected_digest from the companion */
    if (!ct_memequal(computed, expected_digest, 32)) {
        memzero(computed, sizeof(computed));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TRANSPARENT_MISMATCH;
    }

    memzero(computed, sizeof(computed));
    ctx->transparent_verified = true;
    ctx->state = SIGNER_RECEIVING_ACTIONS;

    return SIGNER_OK;
}

/* ------------------------------------------------------------------ */
/*  Orchard action feed                                               */
/* ------------------------------------------------------------------ */

OrchardSignerError orchard_signer_feed_action(OrchardSignerCtx *ctx,
                                               const uint8_t *action_data, size_t action_len)
{
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->actions_received >= ctx->actions_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!zip244_hash_action(&ctx->actions_state, action_data, action_len)) {
        return SIGNER_ERR_BAD_ACTION;
    }

    ctx->actions_received++;
    return SIGNER_OK;
}

/* Action data layout (matches zip244.c OFF_* constants):
 *   cv_net[32] || nullifier[32] || rk[32] || cmx[32] || ephemeral_key[32] ||
 *   enc_ciphertext[580] || out_ciphertext[80]   (total 820 bytes)
 * The nullifier is at offset 32 (used as rho for the output note's NoteCommit
 * per Orchard's split-action construction); cmx is at offset 96.
 */
#define ORCHARD_ACTION_OFFSET_NULLIFIER 32
#define ORCHARD_ACTION_OFFSET_CMX       96
#define ORCHARD_ACTION_TOTAL_SIZE       820

OrchardSignerError orchard_signer_feed_action_with_note(
    OrchardSignerCtx *ctx,
    const uint8_t *action_data, size_t action_len,
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32])
{
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }
    if (ctx->actions_received >= ctx->actions_expected) {
        return SIGNER_ERR_BAD_STATE;
    }
    if (ctx->actions_received >= ORCHARD_SIGNER_MAX_ACTIONS) {
        /* Per-action display storage is bounded; a tx with more outputs
         * than ORCHARD_SIGNER_MAX_ACTIONS cannot be safely displayed. */
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TOO_MANY_ACTIONS;
    }
    if (action_len != ORCHARD_ACTION_TOTAL_SIZE) {
        return SIGNER_ERR_BAD_ACTION;
    }

    /* Recompute cmx from the claimed (d, pk_d, value, rseed) using the
     * action's nullifier as rho, and compare it constant-time against the
     * cmx field embedded in the action bytes. A hostile companion that
     * substituted the recipient must produce a colliding cmx, which is
     * computationally infeasible against Sinsemilla. */
    const uint8_t *d         = recipient;          /* 11 bytes */
    const uint8_t *pk_d      = recipient + 11;     /* 32 bytes */
    const uint8_t *rho       = action_data + ORCHARD_ACTION_OFFSET_NULLIFIER;
    const uint8_t *action_cmx = action_data + ORCHARD_ACTION_OFFSET_CMX;

    uint8_t computed_cmx[32];
    orchard_compute_cmx(d, pk_d, value, rho, rseed, computed_cmx);

    if (!ct_memequal(computed_cmx, action_cmx, 32)) {
        memzero(computed_cmx, sizeof(computed_cmx));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_NOTE_COMMITMENT_MISMATCH;
    }
    memzero(computed_cmx, sizeof(computed_cmx));

    /* cmx verified: feed the action through the normal hash path. */
    if (!zip244_hash_action(&ctx->actions_state, action_data, action_len)) {
        return SIGNER_ERR_BAD_ACTION;
    }

    /* Capture the display info so the firmware UI can render this output
     * to the user, and so verify() can later refuse to advance to VERIFIED
     * unless every captured action has been explicitly confirmed. */
    OrchardActionDisplay *disp = &ctx->actions_display[ctx->actions_received];
    memcpy(disp->recipient, recipient, 43);
    disp->value = value;
    disp->confirmed = false;

    ctx->actions_received++;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_get_action_display(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    uint8_t recipient_out[43],
    uint64_t *value_out)
{
    if (idx >= ctx->actions_received) {
        return SIGNER_ERR_INVALID_ACTION_INDEX;
    }
    const OrchardActionDisplay *disp = &ctx->actions_display[idx];
    if (recipient_out) memcpy(recipient_out, disp->recipient, 43);
    if (value_out)     *value_out = disp->value;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_confirm_action(
    OrchardSignerCtx *ctx,
    uint16_t idx)
{
    if (idx >= ctx->actions_received) {
        return SIGNER_ERR_INVALID_ACTION_INDEX;
    }
    ctx->actions_display[idx].confirmed = true;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_verify(OrchardSignerCtx *ctx,
                                          const uint8_t expected_sighash[32])
{
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!ctx->has_meta) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->actions_received != ctx->actions_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    /* No-blind-signing invariant: every action's (recipient, value) must
     * have been displayed to the user via orchard_signer_get_action_display()
     * AND explicitly confirmed via orchard_signer_confirm_action(). The
     * library refuses to advance to SIGNER_VERIFIED until that is true.
     * orchard_signer_sign() in turn refuses to produce a signature unless
     * the context is in SIGNER_VERIFIED — so a hostile firmware that skips
     * the UI step cannot extract a signature. */
    for (uint16_t i = 0; i < ctx->actions_received; i++) {
        if (!ctx->actions_display[i].confirmed) {
            return SIGNER_ERR_ACTION_NOT_CONFIRMED;
        }
    }

    /* Compute the full ZIP-244 sighash from metadata + actions */
    uint8_t computed[32];
    zip244_shielded_sighash(&ctx->tx_meta, &ctx->actions_state, computed);

    if (!ct_memequal(computed, expected_sighash, 32)) {
        memzero(computed, sizeof(computed));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_SIGHASH_MISMATCH;
    }

    /* Store verified sighash and transition to VERIFIED */
    memcpy(ctx->verified_sighash, computed, 32);
    memzero(computed, sizeof(computed));
    ctx->state = SIGNER_VERIFIED;

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_check(const OrchardSignerCtx *ctx,
                                         const uint8_t sighash[32])
{
    if (ctx->state != SIGNER_VERIFIED) {
        return SIGNER_ERR_NOT_VERIFIED;
    }

    if (!ct_memequal(sighash, ctx->verified_sighash, 32)) {
        return SIGNER_ERR_WRONG_SIGHASH;
    }

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_sign(const OrchardSignerCtx *ctx,
                                        const uint8_t sighash[32],
                                        const uint8_t ask[32],
                                        const uint8_t alpha[32],
                                        uint8_t sig_out[64],
                                        uint8_t rk_out[32])
{
    /* Enforce verification invariant */
    if (ctx->state != SIGNER_VERIFIED) {
        return SIGNER_ERR_NOT_VERIFIED;
    }

    if (!ct_memequal(sighash, ctx->verified_sighash, 32)) {
        return SIGNER_ERR_WRONG_SIGHASH;
    }

    /* Delegate to RedPallas */
    int ret = redpallas_sign(ask, alpha, sighash, sig_out, rk_out);
    return (ret == 0) ? SIGNER_OK : SIGNER_ERR_SIGN_FAILED;
}
