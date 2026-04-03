/**
 * Hardware Wallet Protocol (HWP) v2 — Binary framed serial protocol.
 *
 * Frame: [MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]
 *
 * Compatible with zcash-hw-signer-sdk (Rust).
 * Supports staged transaction verification: outputs are sent individually
 * and hashed incrementally on-device to verify sighash integrity before signing.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define HWP_MAGIC         0xFB
#define HWP_VERSION       0x02

#define HWP_HEADER_SIZE   6
#define HWP_CRC_SIZE      2
#define HWP_MAX_PAYLOAD   512
#define HWP_MAX_FRAME     (HWP_HEADER_SIZE + HWP_MAX_PAYLOAD + HWP_CRC_SIZE) // 520

// --- Message types (matches zcash-hw-signer-sdk MsgType) ---
typedef enum {
    HWP_MSG_PING         = 0x01, // Keepalive / flow control
    HWP_MSG_PONG         = 0x02, // Keepalive response
    HWP_MSG_FVK_REQ      = 0x03, // Request full viewing key
    HWP_MSG_FVK_RSP      = 0x04, // FVK response: ak[32]||nk[32]||rivk[32] = 96 bytes
    HWP_MSG_SIGN_REQ     = 0x05, // Sign request (see payload format below)
    HWP_MSG_SIGN_RSP     = 0x06, // Signature response: sig[64]||rk[32] = 96 bytes
    HWP_MSG_ERROR        = 0x07, // Error: error_code[1]||message[N]
    HWP_MSG_TX_OUTPUT     = 0x08, // Individual tx output for incremental hashing (v2)
    HWP_MSG_TX_OUTPUT_ACK = 0x09, // Output hash acknowledged (v2)
    HWP_MSG_ABORT        = 0x0A, // Cancel signing session
} HwpMsgType;

// --- Error codes (matches zcash-hw-signer-sdk ErrorCode) ---
typedef enum {
    HWP_ERR_UNKNOWN           = 0x00,
    HWP_ERR_BAD_FRAME         = 0x01, // CRC or format error
    HWP_ERR_BAD_SIGHASH       = 0x02, // Invalid sighash
    HWP_ERR_BAD_ALPHA         = 0x03, // Invalid alpha randomizer
    HWP_ERR_BAD_AMOUNT        = 0x04, // Invalid amount encoding
    HWP_ERR_NETWORK_MISMATCH  = 0x05, // Device on different network
    HWP_ERR_USER_CANCELLED    = 0x06, // User rejected on device
    HWP_ERR_SIGN_FAILED       = 0x07, // Signing operation failed
    HWP_ERR_UNSUPPORTED_VER   = 0x08, // Protocol version not supported
    HWP_ERR_SIGHASH_MISMATCH  = 0x09, // Device sighash != companion sighash (v2)
    HWP_ERR_INVALID_STATE     = 0x0A, // Unexpected message in current state (v2)
} HwpErrorCode;

// SIGN_REQ payload:
//   sighash[32] || alpha[32] || amount[8 LE] || fee[8 LE] || recipient_len[1] || recipient[N]
// Total: 81 + recipient_len
#define HWP_SIGN_REQ_FIXED 81 // 32+32+8+8+1

// TX_OUTPUT payload:
//   output_index[2 LE] || total_outputs[2 LE] || output_data[N]
#define HWP_TX_OUTPUT_HEADER 4 // 2+2

// --- Parsed structures ---

typedef struct {
    uint8_t sighash[32];
    uint8_t alpha[32];
    uint64_t amount;
    uint64_t fee;
    uint8_t recipient_len;
    char recipient[128];
} HwpSignReq;

typedef struct {
    uint16_t output_index;
    uint16_t total_outputs;
    const uint8_t* output_data;
    uint16_t output_data_len;
} HwpTxOutput;

typedef struct {
    uint8_t version;
    uint8_t seq;
    uint8_t type;
    uint16_t payload_len;
    uint8_t payload[HWP_MAX_PAYLOAD];
} HwpFrame;

// --- Frame parser (state machine, processes one byte at a time) ---
typedef enum {
    HWP_PARSE_WAIT_MAGIC,
    HWP_PARSE_VERSION,
    HWP_PARSE_SEQ,
    HWP_PARSE_TYPE,
    HWP_PARSE_LEN_LO,
    HWP_PARSE_LEN_HI,
    HWP_PARSE_PAYLOAD,
    HWP_PARSE_CRC_LO,
    HWP_PARSE_CRC_HI,
} HwpParserState;

typedef enum {
    HWP_FEED_INCOMPLETE,   // Need more bytes
    HWP_FEED_FRAME_READY,  // Complete valid frame in parser->frame
    HWP_FEED_CRC_ERROR,    // Frame received but CRC mismatch
    HWP_FEED_OVERFLOW,     // Payload too large
} HwpFeedResult;

typedef struct {
    HwpParserState state;
    HwpFrame frame;
    uint16_t payload_idx;
    uint8_t crc_lo;
} HwpParser;

// --- API ---

// CRC-16/CCITT (poly 0x1021, init 0xFFFF)
uint16_t hwp_crc16(const uint8_t* buf, size_t len);

// Initialize parser
void hwp_parser_init(HwpParser* p);

// Feed one byte to parser. Returns status.
HwpFeedResult hwp_parser_feed(HwpParser* p, uint8_t byte);

// Encode a frame into buf. Returns total frame size.
// Version is set to HWP_VERSION (0x02).
size_t hwp_encode(uint8_t* buf, uint8_t seq, uint8_t msg_type,
                  const uint8_t* payload, uint16_t payload_len);

// Convenience: encode an ERROR frame
size_t hwp_encode_error(uint8_t* buf, uint8_t seq, HwpErrorCode code, const char* msg);

// Parse a SIGN_REQ payload into struct. Returns true on success.
bool hwp_parse_sign_req(const uint8_t* payload, uint16_t len, HwpSignReq* out);

// Encode a SIGN_REQ payload. Returns payload size.
uint16_t hwp_encode_sign_req(uint8_t* payload, const HwpSignReq* req);

// Parse a TX_OUTPUT payload. Returns true on success.
// Note: output_data points into the payload buffer (not copied).
bool hwp_parse_tx_output(const uint8_t* payload, uint16_t len, HwpTxOutput* out);

// Encode a TX_OUTPUT payload. Returns payload size.
uint16_t hwp_encode_tx_output(uint8_t* payload, uint16_t output_index, uint16_t total_outputs,
                              const uint8_t* output_data, uint16_t output_data_len);
