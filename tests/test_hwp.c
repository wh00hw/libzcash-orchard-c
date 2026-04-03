#include "hwp.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void test_encode_decode_ping(void) {
    uint8_t buf[HWP_MAX_FRAME];
    size_t len = hwp_encode(buf, 0x42, HWP_MSG_PING, NULL, 0);
    assert(len == HWP_HEADER_SIZE + HWP_CRC_SIZE);
    assert(buf[0] == HWP_MAGIC);
    assert(buf[1] == HWP_VERSION);
    assert(buf[2] == 0x42);
    assert(buf[3] == HWP_MSG_PING);

    HwpParser parser;
    hwp_parser_init(&parser);
    HwpFeedResult result = HWP_FEED_INCOMPLETE;
    for(size_t i = 0; i < len; i++) {
        result = hwp_parser_feed(&parser, buf[i]);
    }
    assert(result == HWP_FEED_FRAME_READY);
    assert(parser.frame.seq == 0x42);
    assert(parser.frame.type == HWP_MSG_PING);
    assert(parser.frame.payload_len == 0);
    printf("  PASS: encode/decode PING\n");
}

static void test_encode_decode_sign_req(void) {
    HwpSignReq req = {0};
    memset(req.sighash, 0xAA, 32);
    memset(req.alpha, 0xBB, 32);
    req.amount = 1000000;
    req.fee = 10000;
    req.recipient_len = 5;
    memcpy(req.recipient, "utest", 5);

    uint8_t payload[256];
    uint16_t plen = hwp_encode_sign_req(payload, &req);
    assert(plen == HWP_SIGN_REQ_FIXED + 5);

    HwpSignReq parsed = {0};
    assert(hwp_parse_sign_req(payload, plen, &parsed));
    assert(parsed.amount == 1000000);
    assert(parsed.fee == 10000);
    assert(parsed.recipient_len == 5);
    assert(memcmp(parsed.recipient, "utest", 5) == 0);
    assert(memcmp(parsed.sighash, req.sighash, 32) == 0);
    assert(memcmp(parsed.alpha, req.alpha, 32) == 0);
    printf("  PASS: encode/decode SIGN_REQ\n");
}

static void test_crc_mismatch(void) {
    uint8_t buf[HWP_MAX_FRAME];
    size_t len = hwp_encode(buf, 0, HWP_MSG_PONG, NULL, 0);

    // Corrupt one CRC byte
    buf[len - 1] ^= 0xFF;

    HwpParser parser;
    hwp_parser_init(&parser);
    HwpFeedResult result = HWP_FEED_INCOMPLETE;
    for(size_t i = 0; i < len; i++) {
        result = hwp_parser_feed(&parser, buf[i]);
    }
    assert(result == HWP_FEED_CRC_ERROR);
    printf("  PASS: CRC mismatch detected\n");
}

static void test_encode_decode_error(void) {
    uint8_t buf[HWP_MAX_FRAME];
    size_t len = hwp_encode_error(buf, 1, HWP_ERR_USER_CANCELLED, "denied");

    HwpParser parser;
    hwp_parser_init(&parser);
    HwpFeedResult result = HWP_FEED_INCOMPLETE;
    for(size_t i = 0; i < len; i++) {
        result = hwp_parser_feed(&parser, buf[i]);
    }
    assert(result == HWP_FEED_FRAME_READY);
    assert(parser.frame.type == HWP_MSG_ERROR);
    assert(parser.frame.payload[0] == HWP_ERR_USER_CANCELLED);
    assert(memcmp(parser.frame.payload + 1, "denied", 6) == 0);
    printf("  PASS: encode/decode ERROR\n");
}

static void test_encode_decode_tx_output(void) {
    uint8_t payload[256];
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    uint16_t plen = hwp_encode_tx_output(payload, 2, 5, data, 4);
    assert(plen == HWP_TX_OUTPUT_HEADER + 4);

    HwpTxOutput out = {0};
    assert(hwp_parse_tx_output(payload, plen, &out));
    assert(out.output_index == 2);
    assert(out.total_outputs == 5);
    assert(out.output_data_len == 4);
    assert(memcmp(out.output_data, data, 4) == 0);
    printf("  PASS: encode/decode TX_OUTPUT\n");
}

static void test_v1_backward_compat(void) {
    // Encode a v1-style frame (manually set version to 0x01)
    uint8_t buf[HWP_MAX_FRAME];
    size_t len = hwp_encode(buf, 0, HWP_MSG_PING, NULL, 0);
    buf[1] = 0x01; // Override version to v1
    // Recompute CRC
    uint16_t crc = hwp_crc16(buf, HWP_HEADER_SIZE);
    buf[HWP_HEADER_SIZE] = crc & 0xFF;
    buf[HWP_HEADER_SIZE + 1] = (crc >> 8) & 0xFF;

    HwpParser parser;
    hwp_parser_init(&parser);
    HwpFeedResult result = HWP_FEED_INCOMPLETE;
    for(size_t i = 0; i < len; i++) {
        result = hwp_parser_feed(&parser, buf[i]);
    }
    assert(result == HWP_FEED_FRAME_READY);
    assert(parser.frame.version == 0x01);
    printf("  PASS: v1 backward compatibility\n");
}

int main(void) {
    printf("HWP v2 protocol tests:\n");
    test_encode_decode_ping();
    test_encode_decode_sign_req();
    test_crc_mismatch();
    test_encode_decode_error();
    test_encode_decode_tx_output();
    test_v1_backward_compat();
    printf("All HWP tests passed.\n");
    return 0;
}
