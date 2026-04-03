#ifndef __MEMZERO_H__
#define __MEMZERO_H__

#include <stddef.h>
#include <stdint.h>

// Secure memory zeroing — resists compiler dead-store elimination.
void memzero(void* const pnt, const size_t len);

// Constant-time memory comparison. Returns 0 if equal, non-zero otherwise.
// Runs in time proportional to len, regardless of where differences occur.
int ct_memequal(const void* a, const void* b, size_t len);

#endif
