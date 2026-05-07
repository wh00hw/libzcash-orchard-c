# Deterministic test variant of the library:
#   - TEST_DETERMINISTIC_NONCE: redpallas_sign uses fixed 0x42×32 random bytes
#     so signatures are reproducible against test_vectors.h.
#   - USE_PLATFORM_RNG=0 + ZORCHARD_INSECURE_LCG=1: the audit-C-2 hardening
#     makes the library refuse to compile against the LCG by default, but
#     unit tests are exactly the use case the LCG opt-in was designed for.
#     Tests get a deterministic random_buffer body without the integrator
#     having to provide a platform RNG stub.
#   - aes_ct.c (audit H-3): the constant-time AES, replacing the legacy
#     Brian-Gladman files that were removed from the build.
add_library(zcash-orchard-c-deterministic STATIC
    ${CMAKE_SOURCE_DIR}/src/orchard.c
    ${CMAKE_SOURCE_DIR}/src/pallas.c
    ${CMAKE_SOURCE_DIR}/src/redpallas.c
    ${CMAKE_SOURCE_DIR}/src/secp256k1.c
    ${CMAKE_SOURCE_DIR}/src/bip32.c
    ${CMAKE_SOURCE_DIR}/src/bignum.c
    ${CMAKE_SOURCE_DIR}/src/blake2b.c
    ${CMAKE_SOURCE_DIR}/src/bip39.c
    ${CMAKE_SOURCE_DIR}/src/bip39_english.c
    ${CMAKE_SOURCE_DIR}/src/segwit_addr.c
    ${CMAKE_SOURCE_DIR}/src/memzero.c
    ${CMAKE_SOURCE_DIR}/src/hmac.c
    ${CMAKE_SOURCE_DIR}/src/pbkdf2.c
    ${CMAKE_SOURCE_DIR}/src/sha2.c
    ${CMAKE_SOURCE_DIR}/src/rand.c
    ${CMAKE_SOURCE_DIR}/src/hash_stubs.c
    ${CMAKE_SOURCE_DIR}/src/aes/aes_ct.c
    ${CMAKE_SOURCE_DIR}/src/hwp.c
    ${CMAKE_SOURCE_DIR}/src/zip244.c
    ${CMAKE_SOURCE_DIR}/src/orchard_signer.c
)
target_include_directories(zcash-orchard-c-deterministic
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/aes
)
target_compile_definitions(zcash-orchard-c-deterministic PRIVATE
    TEST_DETERMINISTIC_NONCE
    USE_PLATFORM_RNG=0
    ZORCHARD_INSECURE_LCG=1
)
target_compile_options(zcash-orchard-c-deterministic PRIVATE -Wall -Wextra -Wno-unused-parameter)

# All four tests link against the deterministic variant. Tests that don't
# touch crypto (test_hwp) get the same library; the redundancy is harmless
# and the single dependency keeps the build graph simple.
add_executable(test_hwp test_hwp.c)
target_link_libraries(test_hwp PRIVATE zcash-orchard-c-deterministic)
add_test(NAME test_hwp COMMAND test_hwp)

add_executable(test_orchard test_orchard.c)
target_link_libraries(test_orchard PRIVATE zcash-orchard-c-deterministic)
add_test(NAME test_orchard COMMAND test_orchard)

add_executable(test_signer test_signer.c)
target_link_libraries(test_signer PRIVATE zcash-orchard-c-deterministic)
target_include_directories(test_signer PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME test_signer COMMAND test_signer)

add_executable(test_vectors test_vectors.c)
target_link_libraries(test_vectors PRIVATE zcash-orchard-c-deterministic)
add_test(NAME test_vectors COMMAND test_vectors)
