# libzcash-orchard-c

> **WARNING — Proof of Concept.** This library has **not** been audited. It is published for review and experimentation only. **Do not use it to protect real funds** until an independent security audit has been completed. Use at your own risk.

Pure C11 library for Zcash Orchard shielded transactions on embedded hardware wallets.

Implements key derivation, address generation, RedPallas signing, and a binary serial protocol (HWP) for host-device communication. Zero external dependencies — all cryptographic primitives are self-contained. No dynamic memory allocation, no OS calls, no hardware-specific code in the core.

## Features

- **ZIP-32 key derivation** — master key from BIP39 seed, hardened child derivation (`m_Orchard / 32' / coin_type' / account'`)
- **Orchard Unified Addresses** — full derivation with F4Jumble (ZIP-316) and Bech32m encoding
- **Pallas / RedPallas** — curve arithmetic, Sinsemilla hash, spend authorization signing
- **Hardware Wallet Protocol v2** — framed binary serial protocol with CRC-16, incremental sighash verification, compatible with [zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk) (Rust)
- **BIP39 mnemonic** — generation and seed derivation (PBKDF2-HMAC-SHA512)
- **Crypto primitives** — BLAKE2b, SHA-256/512, HMAC, PBKDF2, AES-256 (FF1), all in pure C
- **Platform-agnostic** — pluggable RNG, optional Sinsemilla table acceleration, portable compiler abstractions

## Target platforms

| Platform | Status | Notes |
|----------|--------|-------|
| ESP32 / ESP-IDF | Portable | Provide `random32()` via `esp_random()` |
| ARM Cortex-M (STM32, nRF52, ...) | Portable | Provide `random32()` via HW RNG peripheral |
| Flipper Zero | Portable | Provide `random32()` via `furi_hal_random_get()`, optional Sinsemilla table via storage API |
| RISC-V (GD32V, ESP32-C3) | Portable | Provide `random32()`, compile with GCC |
| Linux / macOS (testing) | Works | Uses LCG fallback (test only, **not secure**) |

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### Build options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `ON` | Build test suite |
| `USE_PLATFORM_RNG` | `0` | Expect platform-provided `random32()`/`random_buffer()` at link time |

Override at compile time:

```bash
cmake .. -DCMAKE_C_FLAGS="-DUSE_PLATFORM_RNG=1"
```

## Porting to your hardware

### 1. Implement `random32()` (required)

The library ships with a **non-cryptographic LCG fallback** for testing. You **must** replace it with your platform's hardware RNG for production use.

Define `USE_PLATFORM_RNG=1` and provide your own implementations at link time:

```c
uint32_t random32(void);
void random_buffer(uint8_t *buf, size_t len);
```

**ESP32:**
```c
#include <esp_random.h>
uint32_t random32(void) { return esp_random(); }
void random_buffer(uint8_t *buf, size_t len) { esp_fill_random(buf, len); }
```

**STM32 (HAL):**
```c
#include "stm32f4xx_hal.h"
extern RNG_HandleTypeDef hrng;
uint32_t random32(void) {
    uint32_t val;
    HAL_RNG_GenerateRandomNumber(&hrng, &val);
    return val;
}
void random_buffer(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = random32();
        size_t n = (len - i < 4) ? len - i : 4;
        memcpy(buf + i, &r, n);
    }
}
```

**Flipper Zero:**
```c
#include <furi_hal_random.h>
uint32_t random32(void) { return furi_hal_random_get(); }
void random_buffer(uint8_t *buf, size_t len) { furi_hal_random_fill_buf(buf, len); }
```

### 2. Sinsemilla lookup table (optional, performance)

Sinsemilla hashing uses a table of 1024 elliptic-curve points (the S-table). There are **three strategies** for providing it, depending on your platform's memory and storage constraints:

#### Strategy A — Compute on-the-fly (no table, default)

Do nothing. If no lookup callback is registered, each point is computed via `pallas_group_hash()` at every Sinsemilla call. This requires **no extra RAM or storage** but is slow (~seconds on Cortex-M4 @ 64 MHz per address derivation).

#### Strategy B — Embed in RAM via header (`sinsemilla_s.h`)

Include the precomputed compressed table directly in your firmware image. The header `src/sinsemilla_s.h` contains all 1024 points in compressed form (32 KB `static const` array). The points are stored as x-coordinate + parity bit and must be decompressed (y = sqrt(x³ + 5), fix parity) at lookup time.

```c
#include "sinsemilla_s.h"
#include "pallas.h"

bool sinsemilla_lookup_from_header(uint32_t index, uint8_t buf_out[64], void* ctx) {
    (void)ctx;
    // Decompress SINSEMILLA_S_COMPRESSED[index] into buf_out (x_le[32] || y_le[32])
    // ... (decompress x, compute y, write both into buf_out)
    return true;
}

pallas_set_sinsemilla_lookup(sinsemilla_lookup_from_header, NULL);
```

This uses ~32 KB of flash/ROM for the compressed table (or 64 KB if you store fully decompressed points in a `static const` array). Good for MCUs with enough flash but limited external storage.

#### Strategy C — Load binary from ROM / SD card (`sinsemilla_s.bin`)

Store the precomputed 64 KB binary (`src/sinsemilla_s.bin`) on external storage (SD card, SPI flash, etc.) and read entries on demand. Each entry is 64 bytes (x_le[32] || y_le[32], already decompressed), so entry `i` is at offset `i * 64`.

```c
#include "pallas.h"

bool sinsemilla_lookup_from_sd(uint32_t index, uint8_t buf_out[64], void* ctx) {
    // Read 64 bytes at offset (index * 64) from sinsemilla_s.bin on SD/flash
    return read_from_storage(index * 64, buf_out, 64);
}

pallas_set_sinsemilla_lookup(sinsemilla_lookup_from_sd, NULL);
```

This keeps the firmware image small and uses almost no RAM — only 64 bytes per lookup are read at a time. Ideal for platforms like Flipper Zero where an SD card is available.

#### Summary

| Strategy | RAM cost | Flash/storage cost | Speed | Best for |
|----------|----------|--------------------|-------|----------|
| A — Compute on-the-fly | 0 | 0 | Slow | Extremely constrained MCUs |
| B — Header in flash | 0 (const) | 32–64 KB flash | Fast | MCUs with enough flash |
| C — Binary from SD/ROM | 64 B | 64 KB external | Fast | Devices with external storage |

### 3. Platform callbacks (optional)

```c
// Progress reporting (e.g., update display during key derivation)
pallas_set_progress_cb(my_progress_handler, NULL);

// Yield callback (e.g., feed watchdog during long computations)
pallas_set_yield_cb(my_yield_handler, NULL);
```

## API overview

### Key derivation & addresses

```c
#include "orchard.h"

uint8_t sk[32], chain[32];
orchard_master_key(bip39_seed, sk, chain);
orchard_derive_account_sk(bip39_seed, 133, 0, sk); // mainnet, account 0

char ua[256];
int len = orchard_derive_unified_address(
    bip39_seed, 133, 0, "u", ua, sizeof(ua), NULL, NULL);
```

### RedPallas signing

```c
#include "redpallas.h"

uint8_t sig[64], rk[32];
redpallas_sign_spend(ask, alpha, sighash, sig, rk);
```

### Hardware Wallet Protocol

```c
#include "hwp.h"

// Encode a frame
uint8_t buf[HWP_MAX_FRAME];
size_t n = hwp_encode(buf, seq, HWP_MSG_SIGN_REQ, payload, payload_len);

// Parse incoming bytes (1 byte at a time, suitable for UART IRQ)
HwpParser parser;
hwp_parser_init(&parser);
HwpFeedResult r = hwp_parser_feed(&parser, byte);
if (r == HWP_FEED_FRAME_READY) {
    // parser.frame contains the decoded frame
}
```

## Architecture

```
include/
  platform.h       — Compiler/platform abstraction (CLZ, packing, alignment)
  options.h        — Build-time feature flags
  orchard.h        — Key derivation, address generation, F4Jumble
  redpallas.h      — RedPallas spend authorization signing
  pallas.h         — Pallas curve arithmetic, Sinsemilla hash
  hwp.h            — Hardware Wallet Protocol v2 (serial framing)
  bip39.h          — BIP39 mnemonic generation
  bignum.h         — 256-bit big number arithmetic
  blake2b.h        — BLAKE2b hash
  sha2.h           — SHA-256 / SHA-512
  hmac.h           — HMAC-SHA-256 / HMAC-SHA-512
  pbkdf2.h         — PBKDF2-HMAC-SHA-512
  rand.h           — RNG abstraction (pluggable backend)
  segwit_addr.h    — Bech32 / Bech32m encoding

src/
  aes/             — AES-256 (pure C, no hardware intrinsics)
  sinsemilla_s.bin — Precomputed Sinsemilla S-table (64 KB)
```

### Extension points

| Hook | How to use | Purpose |
|------|-----------|---------|
| `random32()` / `random_buffer()` | Link-time symbol | Hardware entropy source |
| `pallas_set_sinsemilla_lookup()` | Runtime callback | Fast Sinsemilla from storage |
| `pallas_set_progress_cb()` | Runtime callback | UI progress during key derivation |
| `pallas_set_yield_cb()` | Runtime callback | Watchdog / RTOS yield |

## Known limitations

- **Single-threaded** — global callback state in Pallas operations is not thread-safe (typical for embedded single-core MCUs; use a mutex wrapper if needed on multi-core platforms)
- **No transaction builder** — by design: this library handles key management and signing; transaction construction belongs on the companion host application
- **Sinsemilla performance** — without precomputed table, address generation takes several seconds on Cortex-M4 @ 64 MHz (register `pallas_set_sinsemilla_lookup()` to accelerate)
- **F4Jumble input limit** — capped at 256 bytes (sufficient for Unified Addresses; override `F4JUMBLE_MAX_INPUT` if needed)

## Security hardening

- **Constant-time scalar multiplication** — Montgomery ladder in `pallas_point_mul()` with XOR-masked conditional swap; no branching on secret scalar bits
- **Constant-time modular reduction** — `fq_full_reduce()` uses fixed-iteration conditional subtraction via `bn_cmov()`; no variable-length while loops
- **Constant-time field multiplication** — `fq_mul()` uses `bn_cmov()` for conditional add; no branching on secret bits
- **Constant-time nonce handling** — nonce == 0 check uses `bn_cmov()` instead of `if` branch
- **Full secret cleanup** — all intermediate scalars, points, and key material are explicitly zeroed via `memzero()` after use (including hash states, intermediate bignums, and point structures)
- **Embedded-safe memory layout** — large cryptographic intermediates use `static` storage (BSS) to stay within 4 KB stack constraints (e.g. Flipper Zero); all are explicitly wiped after each operation
- **`ct_memequal()`** — constant-time memory comparison utility available for application use
- **`memzero()`** — uses `SecureZeroMemory` / `memset_s` / `explicit_bzero` / volatile fallback depending on platform; resists compiler dead-store elimination
- The default RNG is **not cryptographically secure**. Always provide a hardware entropy source in production (`USE_PLATFORM_RNG=1`).

## License

MIT — see [LICENSE](LICENSE).

Includes code derived from [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto) (MIT, Copyright 2013 Tomas Dzetkulic, Pavol Rusnak).
