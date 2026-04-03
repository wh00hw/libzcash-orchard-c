/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "rand.h"

#if USE_PLATFORM_RNG

/*
 * Platform-specific RNG.
 *
 * The integrator must provide random32() and random_buffer() at link time.
 * They are declared in rand.h but NOT defined here — the platform BSP or
 * application supplies them.
 *
 * Examples:
 *   - Flipper Zero:  furi_hal_random_get() / furi_hal_random_fill_buf()
 *   - ESP32:         esp_random() / esp_fill_random()
 *   - STM32 + HAL:   HAL_RNG_GenerateRandomNumber()
 *   - nRF52 SDK:     nrf_drv_rng_rand()
 *   - Linux test:    getrandom() / /dev/urandom
 */

static uint32_t seed = 0;

void random_reseed(const uint32_t value) {
    seed = value;
    (void)seed; /* platform RNG may ignore reseed */
}

#else /* Portable test-only fallback */

#pragma message("WARNING: Using non-cryptographic LCG for random32(). " \
                "NOT SUITABLE FOR PRODUCTION. Define USE_PLATFORM_RNG=1 " \
                "and provide random32()/random_buffer() for your hardware.")

static uint32_t seed = 0;

void random_reseed(const uint32_t value) {
    seed = value;
}

uint32_t random32(void) {
    /* Linear congruential generator from Numerical Recipes
     * https://en.wikipedia.org/wiki/Linear_congruential_generator */
    seed = 1664525 * seed + 1013904223;
    return seed;
}

void random_buffer(uint8_t *buf, size_t len) {
    uint32_t r = 0;
    for (size_t i = 0; i < len; i++) {
        if (i % 4 == 0) {
            r = random32();
        }
        buf[i] = (r >> ((i % 4) * 8)) & 0xFF;
    }
}

#endif /* USE_PLATFORM_RNG */

uint32_t random_uniform(uint32_t n) {
    uint32_t x = 0, max = 0xFFFFFFFF - (0xFFFFFFFF % n);
    while ((x = random32()) >= max)
        ;
    return x / (max / n);
}

void random_permute(char* str, size_t len) {
    for (int i = len - 1; i >= 1; i--) {
        int j = random_uniform(i + 1);
        char t = str[j];
        str[j] = str[i];
        str[i] = t;
    }
}
