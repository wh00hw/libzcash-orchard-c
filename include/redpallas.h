#ifndef __REDPALLAS_H__
#define __REDPALLAS_H__

#include <stdint.h>

// RedPallas spend authorization signature (Orchard, ZIP 244)
//
// Inputs:
//   ask      - 32 bytes LE, spending key scalar
//   alpha    - 32 bytes LE, randomizer from companion
//   sighash  - 32 bytes, transaction sighash
//
// Outputs:
//   sig_out  - 64 bytes, (R || S) compressed signature
//   rk_out   - 32 bytes, randomized verification key (companion needs this)
//
// Returns 0 on success, nonzero on error.
int redpallas_sign(
    const uint8_t ask[32],
    const uint8_t alpha[32],
    const uint8_t sighash[32],
    uint8_t sig_out[64],
    uint8_t rk_out[32]);

// Derive ak (spend validating key) from ask
// ak = [ask] * G_SpendAuth
void redpallas_derive_ak(const uint8_t ask[32], uint8_t ak_out[32]);

#endif
