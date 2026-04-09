cmake_minimum_required(VERSION 3.16)
project(zcash-orchard-c
    VERSION 0.1.0
    LANGUAGES C
    DESCRIPTION "Zcash Orchard address generation, signing, and HWP protocol in pure C"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Use -O2 instead of CMake's default -O3 for Release builds.
# GCC ≥13 with -O3 applies aggressive loop unrolling in SHA-2 that
# inflates stack frames beyond the 512-byte embedded budget.
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# --- Library sources ---

set(CRYPTO_SOURCES
    src/orchard.c
    src/pallas.c
    src/redpallas.c
    src/bignum.c
    src/blake2b.c
    src/bip39.c
    src/bip39_english.c
    src/segwit_addr.c
    src/memzero.c
    src/hmac.c
    src/pbkdf2.c
    src/sha2.c
    src/rand.c
    src/hash_stubs.c
    src/aes/aescrypt.c
    src/aes/aeskey.c
    src/aes/aes_modes.c
    src/aes/aestab.c
)

set(PROTOCOL_SOURCES
    src/hwp.c
    src/zip244.c
    src/orchard_signer.c
)

# --- Static library ---

add_library(zcash-orchard-c STATIC
    ${CRYPTO_SOURCES}
    ${PROTOCOL_SOURCES}
)

target_include_directories(zcash-orchard-c
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/aes
)

target_compile_options(zcash-orchard-c PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)


# --- Install ---

include(GNUInstallDirs)

install(TARGETS zcash-orchard-c
    EXPORT zcash-orchard-c-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zcash-orchard-c
)

install(EXPORT zcash-orchard-c-targets
    FILE zcash-orchard-c-config.cmake
    NAMESPACE zcash-orchard-c::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zcash-orchard-c
)

# --- Stack analysis (optional, GCC only) ---

option(STACK_ANALYSIS "Enable -fstack-usage for stack bound analysis" OFF)

if(STACK_ANALYSIS)
    target_compile_options(zcash-orchard-c PRIVATE -fstack-usage)
endif()

# --- Tests (optional) ---

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
