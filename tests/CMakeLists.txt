add_executable(test_hwp test_hwp.c)
target_link_libraries(test_hwp PRIVATE zcash-orchard-c)
add_test(NAME test_hwp COMMAND test_hwp)

add_executable(test_orchard test_orchard.c)
target_link_libraries(test_orchard PRIVATE zcash-orchard-c)
add_test(NAME test_orchard COMMAND test_orchard)

# test_vectors needs its own copy of the library compiled with TEST_DETERMINISTIC_NONCE
# so that RedPallas signing uses fixed random bytes for reproducible signatures.
add_library(zcash-orchard-c-deterministic STATIC
    ${CMAKE_SOURCE_DIR}/src/orchard.c
    ${CMAKE_SOURCE_DIR}/src/pallas.c
    ${CMAKE_SOURCE_DIR}/src/redpallas.c
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
    ${CMAKE_SOURCE_DIR}/src/aes/aescrypt.c
    ${CMAKE_SOURCE_DIR}/src/aes/aeskey.c
    ${CMAKE_SOURCE_DIR}/src/aes/aes_modes.c
    ${CMAKE_SOURCE_DIR}/src/aes/aestab.c
    ${CMAKE_SOURCE_DIR}/src/hwp.c
    ${CMAKE_SOURCE_DIR}/src/zip244.c
    ${CMAKE_SOURCE_DIR}/src/orchard_signer.c
)
target_include_directories(zcash-orchard-c-deterministic
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/aes
)
target_compile_definitions(zcash-orchard-c-deterministic PRIVATE TEST_DETERMINISTIC_NONCE)
target_compile_options(zcash-orchard-c-deterministic PRIVATE -Wall -Wextra -Wno-unused-parameter)

add_executable(test_vectors test_vectors.c)
target_link_libraries(test_vectors PRIVATE zcash-orchard-c-deterministic)
add_test(NAME test_vectors COMMAND test_vectors)
