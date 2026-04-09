# Security Properties

This document maps every secret-dependent operation to the constant-time technique used, for audit reviewers.

## Threat model

The library runs on single-core embedded MCUs (Cortex-M4, ESP32, Flipper Zero) with 4 KB stack budgets. The attacker model is:

- **Timing side-channels**: observable via USB/UART latency or EM emanation.
- **Stack overflow**: an oversized frame can corrupt control flow or leak secrets.
- **Compiler optimization**: dead-store elimination can skip secret cleanup.

The library does **not** defend against power analysis (DPA/SPA), fault injection, or cache-timing attacks. Those require hardware countermeasures beyond the scope of a pure-C library.

## Constant-time operation map

| Operation | Technique | File | Notes |
|-----------|-----------|------|-------|
| Scalar multiplication `[k]*P` | Montgomery ladder with XOR-masked conditional swap | `src/pallas.c` pallas_point_mul() | Fixed iteration count; no branch on scalar bits |
| Modular reduction `x mod q` | Fixed-iteration conditional subtraction via `bn_cmov()` | `src/redpallas.c` fq_full_reduce() | No variable-length while loops |
| Field multiplication `a * b mod p` | Shift-and-add with `bn_cmov()` conditional add | `src/redpallas.c` fq_mul() | No branching on secret bits |
| Nonce-is-zero check | `bn_cmov()` replaces zero with 1 | `src/redpallas.c` generate_nonce() | No `if` branch on nonce value |
| Wide-to-scalar reduction (64B -> 32B) | Horner's method with nibble processing | `src/redpallas.c` fq_from_wide() | Deterministic iteration count |
| Sighash comparison | `ct_memequal()` (volatile XOR accumulator) | `src/orchard_signer.c` | Defense-in-depth; sighash is public data |
| Memory comparison | `ct_memequal()` | `src/memzero.c` | Volatile accumulator prevents short-circuit |
| Secret cleanup | `memzero()` via platform-specific secure zeroing | `src/memzero.c` | Resists dead-store elimination |

## Non-constant-time operations (justified)

| Operation | Technique | File | Why it's safe |
|-----------|-----------|------|---------------|
| `fp_sqrt()` Tonelli-Shanks | Early return on non-square | `src/pallas.c` | Input is a public curve coordinate, not a secret |
| `fp_neg()` zero check | Branch on `bn_is_zero()` | `src/pallas.c` | Input is a public field element |
| `fp_is_square()` Euler criterion | Variable-time exponentiation | `src/pallas.c` | Applied to public hash outputs during hash-to-curve |

## Stack budget

All cryptographic functions stay within a **512-byte per-function** stack limit, verified by GCC `-fstack-usage`. Large intermediates (BLAKE2b state, bignum temporaries, curve points) use `static` storage in BSS and are explicitly zeroed after use.

Build and verify:
```bash
cmake .. -DSTACK_ANALYSIS=ON && make
../scripts/check_stack.sh .
```

## Secret material lifecycle

1. **Derivation**: spending key derived from BIP39 seed via ZIP-32 (BLAKE2b-512).
2. **Use**: signing via RedPallas (deterministic nonce from BLAKE2b-512).
3. **Cleanup**: all intermediate scalars, points, hash states, and key bytes are zeroed via `memzero()` before function return. Static storage is wiped after each operation to prevent cross-call leakage.

## Test vector corpus

Known-answer tests in `tests/test_vectors.c` cross-check the C implementation against the Rust reference (librustzcash). Coverage (49 tests):

- **BLAKE2b** with 5 personalization tags (ZcashIP32Orchard, Zcash_ExpandSeed, Zcash_RedPallasN, Zcash_RedPallasH, ZTxIdOrchardHash)
- **Pallas hash-to-curve** (3 domain/message pairs including SinsemillaQ)
- **Sinsemilla S-table** (5 sample points: indices 0, 1, 2, 512, 1023)
- **ZIP-32** full derivation chain (master key, spending key, ak, nk, rivk, diversifier, pk_d)
- **ZIP-32 child key intermediates** (per-hop sk + chaincode for each of the 3 derivation steps)
- **FF1-AES-256** diversifier encryption (3 synthetic + 1 real dk from ZIP-32 derivation)
- **RedPallas signing** with deterministic nonce (4 test cases: standard, alpha=0, sighash=0, large scalars; compiled with `TEST_DETERMINISTIC_NONCE`)
- **Sinsemilla end-to-end** (HashToPoint with 1 and 2 chunks, ShortCommit with synthetic 510-bit message, ShortCommit with real ak||nk and rivk from ZIP-32)
- **F4Jumble** forward (3 test cases: 48, 83, and 128 bytes) + inverse round-trip

Regenerate vectors: `cd tools/gen_test_vectors && cargo run 2>/dev/null > ../../tests/test_vectors.h`
