/**
 * ZIP-244 Transaction Sighash Computation.
 *
 * Implements the v5 shielded sighash for Zcash Orchard transactions
 * as specified in https://zips.z.cash/zip-0244
 */
#include "zip244.h"
#include "blake2b.h"
#include <string.h>

/* --- ZIP-244 BLAKE2b personalizations (all exactly 16 bytes) --- */

static const char PERSONAL_HEADERS[]    = "ZTxIdHeadersHash";
/* transparent and sapling digests are pre-computed by the companion */
static const char PERSONAL_ORCHARD[]    = "ZTxIdOrchardHash";
static const char PERSONAL_COMPACT[]    = "ZTxIdOrcActCHash";
static const char PERSONAL_MEMOS[]      = "ZTxIdOrcActMHash";
static const char PERSONAL_NONCOMPACT[] = "ZTxIdOrcActNHash";
/* Root sighash: first 12 bytes are "ZcashTxHash_", last 4 = branch_id LE */

/* --- Action data field offsets --- */
/* Layout: cv_net[32] || nullifier[32] || rk[32] || cmx[32] ||
 *         ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80]
 * Total: 820 bytes
 */
#define OFF_CV_NET       0
#define OFF_NULLIFIER    32
#define OFF_RK           64
#define OFF_CMX          96
#define OFF_EPK          128
#define OFF_ENC          160
#define OFF_OUT          740
#define ACTION_DATA_SIZE 820
#define ENC_CIPHER_SIZE  580
#define OUT_CIPHER_SIZE  80

/* ------------------------------------------------------------------ */
/*  Metadata serialization                                            */
/* ------------------------------------------------------------------ */

static void write_u32_le(uint8_t* buf, uint32_t v) {
    buf[0] = v & 0xFF;
    buf[1] = (v >> 8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF;
    buf[3] = (v >> 24) & 0xFF;
}

static uint32_t read_u32_le(const uint8_t* buf) {
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

static void write_i64_le(uint8_t* buf, int64_t v) {
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++) {
        buf[i] = u & 0xFF;
        u >>= 8;
    }
}

static int64_t read_i64_le(const uint8_t* buf) {
    uint64_t u = 0;
    for (int i = 7; i >= 0; i--) {
        u = (u << 8) | buf[i];
    }
    return (int64_t)u;
}

bool zip244_parse_tx_meta(const uint8_t* data, size_t len, Zip244TxMeta* out) {
    if (len < ZIP244_TX_META_SIZE) return false;

    out->version              = read_u32_le(data + 0);
    out->version_group_id     = read_u32_le(data + 4);
    out->consensus_branch_id  = read_u32_le(data + 8);
    out->lock_time            = read_u32_le(data + 12);
    out->expiry_height        = read_u32_le(data + 16);
    out->orchard_flags        = data[20];
    out->value_balance        = read_i64_le(data + 21);
    memcpy(out->anchor, data + 29, 32);
    memcpy(out->transparent_sig_digest, data + 61, 32);
    memcpy(out->sapling_digest, data + 93, 32);

    /* Extended format: coin_type appended after the core 125 bytes */
    if (len >= ZIP244_TX_META_EXT_SIZE) {
        out->coin_type = read_u32_le(data + 125);
    } else {
        out->coin_type = 0; /* unspecified (backward compat with old SDK) */
    }
    return true;
}

size_t zip244_encode_tx_meta(uint8_t* buf, const Zip244TxMeta* meta) {
    write_u32_le(buf + 0,  meta->version);
    write_u32_le(buf + 4,  meta->version_group_id);
    write_u32_le(buf + 8,  meta->consensus_branch_id);
    write_u32_le(buf + 12, meta->lock_time);
    write_u32_le(buf + 16, meta->expiry_height);
    buf[20] = meta->orchard_flags;
    write_i64_le(buf + 21, meta->value_balance);
    memcpy(buf + 29, meta->anchor, 32);
    memcpy(buf + 61, meta->transparent_sig_digest, 32);
    memcpy(buf + 93, meta->sapling_digest, 32);
    /* Extended: coin_type (not part of ZIP-244 sighash, used for network validation) */
    write_u32_le(buf + 125, meta->coin_type);
    return ZIP244_TX_META_EXT_SIZE;
}

/* ------------------------------------------------------------------ */
/*  Incremental actions digest                                        */
/* ------------------------------------------------------------------ */

void zip244_actions_init(Zip244ActionsState* state) {
    memset(state, 0, sizeof(*state));

    blake2b_InitPersonal(&state->compact_ctx,    32, PERSONAL_COMPACT,    16);
    blake2b_InitPersonal(&state->memos_ctx,      32, PERSONAL_MEMOS,      16);
    blake2b_InitPersonal(&state->noncompact_ctx, 32, PERSONAL_NONCOMPACT, 16);

    state->actions_hashed = 0;
    state->initialized = true;
}

bool zip244_hash_action(Zip244ActionsState* state,
                        const uint8_t* action_data, size_t action_data_len) {
    if (!state->initialized || action_data_len != ACTION_DATA_SIZE)
        return false;

    blake2b_state* compact = &state->compact_ctx;
    blake2b_state* memos   = &state->memos_ctx;
    blake2b_state* noncomp = &state->noncompact_ctx;

    const uint8_t* cv_net = action_data + OFF_CV_NET;
    const uint8_t* nullifier = action_data + OFF_NULLIFIER;
    const uint8_t* rk = action_data + OFF_RK;
    const uint8_t* cmx = action_data + OFF_CMX;
    const uint8_t* epk = action_data + OFF_EPK;
    const uint8_t* enc = action_data + OFF_ENC;
    const uint8_t* out = action_data + OFF_OUT;

    /* Compact digest: nullifier(32) || cmx(32) || epk(32) || enc[0..52] */
    blake2b_Update(compact, nullifier, 32);
    blake2b_Update(compact, cmx, 32);
    blake2b_Update(compact, epk, 32);
    blake2b_Update(compact, enc, 52);

    /* Memos digest: enc[52..564] (512 bytes) */
    blake2b_Update(memos, enc + 52, 512);

    /* Non-compact digest: cv_net(32) || rk(32) || enc[564..580](16) || out(80) */
    blake2b_Update(noncomp, cv_net, 32);
    blake2b_Update(noncomp, rk, 32);
    blake2b_Update(noncomp, enc + 564, 16);
    blake2b_Update(noncomp, out, OUT_CIPHER_SIZE);

    state->actions_hashed++;
    return true;
}

void zip244_orchard_digest(Zip244ActionsState* state,
                           const Zip244TxMeta* meta,
                           uint8_t digest_out[32]) {
    /* Finalize the three sub-digests */
    uint8_t compact_digest[32], memos_digest[32], noncompact_digest[32];

    blake2b_Final(&state->compact_ctx,    compact_digest,    32);
    blake2b_Final(&state->memos_ctx,      memos_digest,      32);
    blake2b_Final(&state->noncompact_ctx, noncompact_digest, 32);

    /* Combine into orchard digest:
     * BLAKE2b-256("ZTxIdOrchardHash",
     *     compact || memos || noncompact || flags[1] || value_balance[8] || anchor[32])
     */
    blake2b_state orchard;
    blake2b_InitPersonal(&orchard, 32, PERSONAL_ORCHARD, 16);
    blake2b_Update(&orchard, compact_digest, 32);
    blake2b_Update(&orchard, memos_digest, 32);
    blake2b_Update(&orchard, noncompact_digest, 32);

    /* Flags: 1 byte */
    blake2b_Update(&orchard, &meta->orchard_flags, 1);

    /* Value balance: 8 bytes LE signed */
    uint8_t vb[8];
    write_i64_le(vb, meta->value_balance);
    blake2b_Update(&orchard, vb, 8);

    /* Anchor: 32 bytes */
    blake2b_Update(&orchard, meta->anchor, 32);

    blake2b_Final(&orchard, digest_out, 32);
}

/* ------------------------------------------------------------------ */
/*  Header and empty-bundle digests                                   */
/* ------------------------------------------------------------------ */

void zip244_empty_digest(const char* personal, uint8_t digest_out[32]) {
    blake2b_state s;
    blake2b_InitPersonal(&s, 32, personal, 16);
    blake2b_Final(&s, digest_out, 32);
}

void zip244_header_digest(const Zip244TxMeta* meta, uint8_t digest_out[32]) {
    blake2b_state s;
    blake2b_InitPersonal(&s, 32, PERSONAL_HEADERS, 16);

    uint8_t buf[4];
    write_u32_le(buf, meta->version);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->version_group_id);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->consensus_branch_id);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->lock_time);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->expiry_height);
    blake2b_Update(&s, buf, 4);

    blake2b_Final(&s, digest_out, 32);
}

/* ------------------------------------------------------------------ */
/*  Full shielded sighash                                             */
/* ------------------------------------------------------------------ */

void zip244_shielded_sighash(const Zip244TxMeta* meta,
                             Zip244ActionsState* actions_state,
                             uint8_t sighash_out[32]) {
    /* 1. Header digest */
    uint8_t hdr_digest[32];
    zip244_header_digest(meta, hdr_digest);

    /* 2. Transparent sig digest (pre-computed by companion) */
    const uint8_t *transparent_digest = meta->transparent_sig_digest;

    /* 3. Sapling digest (pre-computed by companion) */
    const uint8_t *sapling_digest = meta->sapling_digest;

    /* 4. Orchard digest */
    uint8_t orchard_digest_val[32];
    zip244_orchard_digest(actions_state, meta, orchard_digest_val);

    /* 5. Root sighash:
     * BLAKE2b-256("ZcashTxHash_" || consensus_branch_id[4 LE],
     *     header || transparent || sapling || orchard)
     */
    uint8_t root_personal[16];
    memcpy(root_personal, "ZcashTxHash_", 12);
    write_u32_le(root_personal + 12, meta->consensus_branch_id);

    blake2b_state root;
    blake2b_InitPersonal(&root, 32, (const char*)root_personal, 16);
    blake2b_Update(&root, hdr_digest, 32);
    blake2b_Update(&root, transparent_digest, 32);
    blake2b_Update(&root, sapling_digest, 32);
    blake2b_Update(&root, orchard_digest_val, 32);
    blake2b_Final(&root, sighash_out, 32);
}
