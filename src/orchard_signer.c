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

    zip244_actions_init(&ctx->actions_state);
    ctx->has_meta = true;
    ctx->actions_expected = total_actions;
    ctx->actions_received = 0;
    ctx->state = SIGNER_RECEIVING_ACTIONS;

    return SIGNER_OK;
}

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
