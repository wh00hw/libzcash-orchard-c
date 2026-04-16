/**
 * ZIP-244 Transaction Sighash Computation for Zcash v5 Transactions.
 *
 * Implements the shielded sighash algorithm as specified in ZIP-244:
 * https://zips.z.cash/zip-0244
 *
 * Digest tree:
 *   sighash = BLAKE2b-256("ZcashTxHash_" || branch_id_le,
 *       header_digest || transparent_digest || sapling_digest || orchard_digest)
 *
 * Where orchard_digest = BLAKE2b-256("ZTxIdOrchardHash",
 *       compact_digest || memos_digest || noncompact_digest ||
 *       flags[1] || value_balance[8 LE] || anchor[32])
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "blake2b.h"

/**
 * Transaction header metadata needed for sighash computation.
 * Sent from companion to device before action data.
 *
 * Wire format (125 bytes):
 *   version[4 LE] || version_group_id[4 LE] || consensus_branch_id[4 LE] ||
 *   lock_time[4 LE] || expiry_height[4 LE] ||
 *   orchard_flags[1] || value_balance[8 LE signed] || anchor[32] ||
 *   transparent_sig_digest[32] || sapling_digest[32]
 *
 * The transparent_sig_digest and sapling_digest are pre-computed by the
 * companion from the full transaction data, since the device only has
 * access to the Orchard bundle.
 */
/** Wire size of the core TxMeta fields (used for ZIP-244 sighash computation). */
#define ZIP244_TX_META_SIZE     125
/** Wire size with the coin_type extension (network discrimination). */
#define ZIP244_TX_META_EXT_SIZE 129

typedef struct {
    uint32_t version;
    uint32_t version_group_id;
    uint32_t consensus_branch_id;
    uint32_t lock_time;
    uint32_t expiry_height;
    uint8_t  orchard_flags;
    int64_t  value_balance;
    uint8_t  anchor[32];
    uint8_t  transparent_sig_digest[32];
    uint8_t  sapling_digest[32];
    /** ZIP-32 coin type: 133 = mainnet, 1 = testnet, 0 = unspecified. */
    uint32_t coin_type;
} Zip244TxMeta;

/**
 * Incremental state for computing the ZIP-244 orchard actions digest.
 *
 * Three parallel BLAKE2b contexts hash different portions of each action:
 * - compact:    nullifier || cmx || epk || enc_ciphertext[0..52]
 * - memos:      enc_ciphertext[52..564]
 * - noncompact: cv_net || rk || enc_ciphertext[564..580] || out_ciphertext
 */
typedef struct {
    /* Three parallel BLAKE2b-256 hashers with ZIP-244 personalizations */
    blake2b_state compact_ctx;
    blake2b_state memos_ctx;
    blake2b_state noncompact_ctx;
    uint16_t actions_hashed;
    bool initialized;
} Zip244ActionsState;

/* ------------------------------------------------------------------ */
/*  Transparent digest (incremental, for on-device verification)      */
/* ------------------------------------------------------------------ */

/**
 * Incremental state for computing the ZIP-244 transparent txid digest.
 *
 * Three parallel BLAKE2b contexts hash different portions of each input/output:
 * - prevouts:  prevout_hash[32] || prevout_index[4 LE] per input
 * - sequences: sequence[4 LE] per input
 * - outputs:   value[8 LE] || CompactSize(script_len) || script_pubkey per output
 *
 * The combined digest is:
 *   BLAKE2b-256("ZTxIdTranspaHash",
 *       prevouts_digest || sequence_digest || outputs_digest)
 */
typedef struct {
    blake2b_state prevouts_ctx;    /* "ZTxIdPrevoutHash" */
    blake2b_state sequence_ctx;    /* "ZTxIdSequencHash" */
    blake2b_state outputs_ctx;     /* "ZTxIdOutputsHash" */
    blake2b_state amounts_ctx;     /* "ZTxTrAmountsHash" (per-input sighash) */
    blake2b_state scripts_ctx;     /* "ZTxTrScriptsHash" (per-input sighash) */
    uint16_t inputs_received;
    uint16_t outputs_received;
    bool initialized;
} Zip244TransparentState;

/**
 * Initialize the incremental transparent digest state.
 * Must be called before any zip244_hash_transparent_input/output() calls.
 */
void zip244_transparent_init(Zip244TransparentState *state);

/**
 * Hash one transparent input incrementally.
 *
 * Wire format (from companion SDK):
 *   prevout_hash[32] || prevout_index[4 LE] || sequence[4 LE] ||
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 *
 * Extracts prevout + sequence and feeds them into the respective hashers.
 * Returns true on success, false if data_len < 48 (minimum: 32+4+4+8).
 */
bool zip244_hash_transparent_input(Zip244TransparentState *state,
                                   const uint8_t *data, size_t data_len);

/**
 * Hash one transparent output incrementally.
 *
 * Wire format (from companion SDK):
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 *
 * Re-encodes with CompactSize for the script length before hashing,
 * matching the serialization used by zcash_primitives::TxOut::write().
 * Returns true on success, false if data_len < 10.
 */
bool zip244_hash_transparent_output(Zip244TransparentState *state,
                                    const uint8_t *data, size_t data_len);

/**
 * Finalize and compute the transparent txid digest.
 *
 * transparent_digest = BLAKE2b-256("ZTxIdTranspaHash",
 *     prevouts_digest || sequence_digest || outputs_digest)
 *
 * digest_out must be 32 bytes.
 */
void zip244_transparent_digest(Zip244TransparentState *state,
                               uint8_t digest_out[32]);

/**
 * Compute the per-input transparent signature digest (ZIP-244 S.2).
 *
 * For SIGHASH_ALL (the standard case):
 *   BLAKE2b-256("ZTxIdTranspaHash",
 *       hash_type[1] || prevouts_digest || amounts_digest || scripts_digest ||
 *       sequence_digest || outputs_digest || txin_sig_digest)
 *
 * Where txin_sig_digest = BLAKE2b-256("Zcash___TxInHash",
 *       prevout_hash[32] || prevout_index[4 LE] || value[8 LE signed] ||
 *       CompactSize(script_len) || script_pubkey || sequence[4 LE])
 *
 * @param state         Transparent state (must have all inputs/outputs hashed)
 * @param input_index   Index of the input being signed
 * @param inputs        Array of all transparent inputs (for txin_sig_digest)
 * @param num_inputs    Number of inputs
 * @param hash_type     Sighash type (usually 0x01 = SIGHASH_ALL)
 * @param sighash_out   32-byte output
 */
void zip244_transparent_per_input_sighash(
    Zip244TransparentState *state,
    uint16_t input_index,
    const uint8_t *input_data,  /* raw wire data of the specific input being signed */
    size_t input_data_len,
    uint8_t hash_type,
    uint8_t sighash_out[32]);

/* ------------------------------------------------------------------ */

/**
 * Parse transaction metadata from wire format.
 * Returns true on success.
 */
bool zip244_parse_tx_meta(const uint8_t* data, size_t len, Zip244TxMeta* out);

/**
 * Serialize transaction metadata to wire format.
 * buf must be at least ZIP244_TX_META_SIZE bytes.
 * Returns ZIP244_TX_META_SIZE.
 */
size_t zip244_encode_tx_meta(uint8_t* buf, const Zip244TxMeta* meta);

/**
 * Initialize the incremental actions digest state.
 * Must be called before any zip244_hash_action() calls.
 */
void zip244_actions_init(Zip244ActionsState* state);

/**
 * Hash one action's data incrementally into the three parallel digesters.
 *
 * action_data layout (820 bytes):
 *   cv_net[32] || nullifier[32] || rk[32] || cmx[32] ||
 *   ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80]
 *
 * Returns true on success, false if action_data_len != 820.
 */
bool zip244_hash_action(Zip244ActionsState* state,
                        const uint8_t* action_data, size_t action_data_len);

/**
 * Finalize the three action digesters and compute the full orchard digest.
 *
 * orchard_digest = BLAKE2b-256("ZTxIdOrchardHash",
 *     compact_digest || memos_digest || noncompact_digest ||
 *     flags[1] || value_balance[8 LE] || anchor[32])
 *
 * digest_out must be 32 bytes.
 */
void zip244_orchard_digest(Zip244ActionsState* state,
                           const Zip244TxMeta* meta,
                           uint8_t digest_out[32]);

/**
 * Compute the empty-bundle digest for a protocol component.
 * Used when transparent or sapling bundles are absent.
 *
 * Returns BLAKE2b-256(personal, "") — hash with personalization but no data.
 * personal must be exactly 16 bytes. digest_out must be 32 bytes.
 */
void zip244_empty_digest(const char* personal, uint8_t digest_out[32]);

/**
 * Compute the header digest.
 *
 * header_digest = BLAKE2b-256("ZTxIdHeadersHash",
 *     version[4 LE] || version_group_id[4 LE] ||
 *     consensus_branch_id[4 LE] || lock_time[4 LE] || expiry_height[4 LE])
 */
void zip244_header_digest(const Zip244TxMeta* meta, uint8_t digest_out[32]);

/**
 * Compute the full v5 shielded sighash.
 *
 * sighash = BLAKE2b-256("ZcashTxHash_" || consensus_branch_id[4 LE],
 *     header_digest || transparent_digest || sapling_digest || orchard_digest)
 *
 * For Orchard-only transactions (no transparent, no sapling),
 * transparent_digest and sapling_digest are computed as empty-bundle hashes.
 *
 * sighash_out must be 32 bytes.
 */
void zip244_shielded_sighash(const Zip244TxMeta* meta,
                             Zip244ActionsState* actions_state,
                             uint8_t sighash_out[32]);
