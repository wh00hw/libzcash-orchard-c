// Stubs for hash functions referenced by hasher.c but unused in FlipZ
// This avoids linking groestl (9KB), sha3 (2.4KB), blake256 (2.2KB), rc4 (124B)

#include <stdint.h>
#include <stddef.h>

// blake256
void blake256_Init(void* ctx) { (void)ctx; }
void blake256_Update(void* ctx, const uint8_t* d, size_t l) { (void)ctx; (void)d; (void)l; }
void blake256_Final(void* ctx, uint8_t* h) { (void)ctx; (void)h; }

// groestl512
void groestl512_Init(void* ctx) { (void)ctx; }
void groestl512_Update(void* ctx, const uint8_t* d, size_t l) { (void)ctx; (void)d; (void)l; }
void groestl512_DoubleTrunc(void* ctx, uint8_t* h) { (void)ctx; (void)h; }

// sha3/keccak
void sha3_256_Init(void* ctx) { (void)ctx; }
void sha3_Update(void* ctx, const uint8_t* d, size_t l) { (void)ctx; (void)d; (void)l; }
void sha3_Final(void* ctx, uint8_t* h) { (void)ctx; (void)h; }
void keccak_Final(void* ctx, uint8_t* h) { (void)ctx; (void)h; }

// rc4
void rc4_init(void* ctx, const uint8_t* k, size_t l) { (void)ctx; (void)k; (void)l; }
void rc4_encrypt(void* ctx, uint8_t* d, size_t l) { (void)ctx; (void)d; (void)l; }
