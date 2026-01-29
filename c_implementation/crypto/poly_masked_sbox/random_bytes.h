// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _RANDOMNESS_H
#define _RANDOMNESS_H
#include <stdbool.h>
#include <stdint.h>

/// @brief Initialize the non-cryptographically secure PRNG given `seed`.
void init_rand(uint32_t seed);

/// @brief Initialize AES with the given key
/// @param key seed for the aes encryption
void init_aes_rand_seed(uint8_t *key);

/// @brief Initialize the randomness buffer with AES encryption
void init_aes_rand();

/// @brief Get a random byte from the buffer
/// @return a random byte
uint8_t get_random_byte();

/// @brief Reset the counter for the randomness buffer used for testing purposes
void reset_ctr();
uint32_t get_ctr();
#endif