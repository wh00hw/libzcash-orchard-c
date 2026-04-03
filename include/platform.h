/**
 * Platform abstraction layer for portable embedded deployment.
 *
 * This header provides compile-time macros and pluggable hooks so that the
 * library can run on any C11-capable target (ESP32, ARM Cortex-M, RISC-V,
 * x86 host, …) without hard-coding vendor-specific APIs.
 *
 * Platform integrators override behavior either by:
 *   1. Defining macros before including this header, or
 *   2. Passing -D flags via CMake / compiler command line.
 */

#ifndef ZORCHARD_PLATFORM_H
#define ZORCHARD_PLATFORM_H

/* ------------------------------------------------------------------ */
/* Compiler intrinsics portability                                     */
/* ------------------------------------------------------------------ */

/**
 * ZORCHARD_CLZ32(x) — count leading zeros of a non-zero uint32_t.
 * Returns undefined value when x == 0 (same as __builtin_clz).
 */
#ifndef ZORCHARD_CLZ32
#  if defined(__GNUC__) || defined(__clang__)
#    define ZORCHARD_CLZ32(x) __builtin_clz(x)
#  elif defined(_MSC_VER)
#    include <intrin.h>
     static inline int zorchard_clz32_msvc(uint32_t x) {
         unsigned long idx;
         _BitScanReverse(&idx, x);
         return 31 - (int)idx;
     }
#    define ZORCHARD_CLZ32(x) zorchard_clz32_msvc(x)
#  else
     /* Generic portable fallback */
     static inline int zorchard_clz32_generic(uint32_t x) {
         int n = 0;
         if (x <= 0x0000FFFF) { n += 16; x <<= 16; }
         if (x <= 0x00FFFFFF) { n +=  8; x <<=  8; }
         if (x <= 0x0FFFFFFF) { n +=  4; x <<=  4; }
         if (x <= 0x3FFFFFFF) { n +=  2; x <<=  2; }
         if (x <= 0x7FFFFFFF) { n +=  1; }
         return n;
     }
#    define ZORCHARD_CLZ32(x) zorchard_clz32_generic(x)
#  endif
#endif

/* ------------------------------------------------------------------ */
/* Struct packing                                                      */
/* ------------------------------------------------------------------ */

/**
 * ZORCHARD_PACKED — mark a struct as packed (no padding).
 * Usage:  struct ZORCHARD_PACKED my_struct { ... };
 *     or: } ZORCHARD_PACKED;  (after closing brace)
 */
#ifndef ZORCHARD_PACKED
#  if defined(__GNUC__) || defined(__clang__)
#    define ZORCHARD_PACKED __attribute__((packed))
#  elif defined(_MSC_VER)
#    define ZORCHARD_PACKED
     /* Use #pragma pack(push,1) / #pragma pack(pop) around the struct */
#  else
#    define ZORCHARD_PACKED
#  endif
#endif

/* ------------------------------------------------------------------ */
/* Alignment                                                           */
/* ------------------------------------------------------------------ */

#ifndef ZORCHARD_ALIGNED
#  if defined(__GNUC__) || defined(__clang__)
#    define ZORCHARD_ALIGNED(x) __attribute__((aligned(x)))
#  elif defined(_MSC_VER)
#    define ZORCHARD_ALIGNED(x) __declspec(align(x))
#  else
#    define ZORCHARD_ALIGNED(x)
#  endif
#endif

/* ------------------------------------------------------------------ */
/* Constructor (auto-init at load time)                                */
/* ------------------------------------------------------------------ */

#ifndef ZORCHARD_CONSTRUCTOR
#  if defined(__GNUC__) || defined(__clang__)
#    define ZORCHARD_CONSTRUCTOR __attribute__((constructor))
#  else
     /* Platforms without constructor support must call init explicitly */
#    define ZORCHARD_CONSTRUCTOR
#  endif
#endif

#endif /* ZORCHARD_PLATFORM_H */
