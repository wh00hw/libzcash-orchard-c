/**
 * Orchard Signing Context — enforces ZIP-244 verification before signing.
 */
#include "orchard_signer.h"
#include "redpallas.h"
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
