// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _RANDOMNESS_H
#define _RANDOMNESS_H
#include <stdbool.h>
#include <stdint.h>

/// @brief Initialize the non-cryptographically secure PRNG given `seed`.
/// Mutates the seed.
void init_rand(uint32_t *seed);

/// @brief Get a random byte from the buffer
/// @return a random byte
uint8_t get_random_byte();

/// @brief get a random value in the range [0, max) uniformly distributed
/// through rejection sampling
/// @param max a threshold above (and including which) the random number should
/// be rejected
/// @return a random number smaller than `max`
uint32_t get_random_smaller_than(uint32_t *seed, uint32_t max);

/// @brief Generate NUM_INJECTED_FAULTS unique random fault indices in the range
/// [0, max)
/// @param seed the seed for the random number generator
/// @param indices the array to store the generated fault indices
/// @param max the maximum value for the fault indices
void generate_random_fault_indices(uint32_t *seed,
                                   uint32_t indices[NUM_INJECTED_FAULTS],
                                   uint32_t max);

/// @brief Reset the counter for the randomness buffer used for testing purposes
void reset_ctr();
uint32_t get_ctr();
void zero_randomness();
#endif