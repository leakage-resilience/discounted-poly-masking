// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "error_handler.h"
#include "parameters.h"
#include "poly_masking_parameters.h"
#include "random.h"
#include "uart.h"
#include <stdbool.h>
#include <stdint.h>

#define RANDOMNESS_LEN 1600

// counter that keeps track of the randomness buffer
uint32_t ctr = 0;

// buffer for the randomness
static uint8_t randomness[RANDOMNESS_LEN] = {0};

void init_rand(uint32_t *seed)
{
  if (RANDOMNESS_LEN % 16 != 0)
  {
    handle_error("RANDOMNESS_LEN Buffer size must be a multiple of 16.");
  }

  // fill buffer with sampled randomness.
  uint32_t *rand_buf = (uint32_t *)randomness;
  uint32_t num_words = RANDOMNESS_LEN / 4;
  for (uint32_t i = 0; i < num_words; i++)
  {
    rand_buf[i] = rand(seed);
  }
  ctr = 0;
}

uint8_t get_random_byte()
{
  if (ctr >= RANDOMNESS_LEN - 1)
  {
    handle_error("Ran out of randomness.");
  }
  return randomness[ctr++];
}

uint32_t get_random_smaller_than(uint32_t *seed, uint32_t max)
{
  // calculate number of bits needed to represent max
  uint32_t bits = 0;
  uint32_t tmp = max;
  while (tmp)
  {
    bits++;
    tmp >>= 1;
  }

  // all 32 bits are used
  if (bits >= 32)
  {
    return rand(seed);
  }

  // use mask to extract correct bits from rnd
  uint32_t mask = (1u << bits) - 1;
  uint32_t r;
  // rejection sampling until we have a value in range
  do
  {
    r = rand(seed) & mask;
  } while (r >= max);

  return r;
}

void generate_random_fault_indices(uint32_t *seed,
                                   uint32_t indices[NUM_INJECTED_FAULTS],
                                   uint32_t max_fault_position)
{

  // Ensure there are enough unique values available.
  if (max_fault_position < NUM_INJECTED_FAULTS)
  {
    handle_error("max_fault_position must be at least NUM_INJECTED_FAULTS for "
                 "unique selection.");
  }

  uint32_t count = 0;
  while (count < NUM_INJECTED_FAULTS)
  {

    uint32_t candidate = get_random_smaller_than(seed, max_fault_position);
    // ensure uniqueness of indices
    bool duplicate = false;
    for (uint32_t i = 0; i < count; i++)
    {
      if (indices[i] == candidate)
      {
        duplicate = true;
        break;
      }
    }

    // store unique index
    if (!duplicate)
    {
      indices[count] = candidate;
      count++;
    }
  }
}

void zero_randomness()
{
  for (uint32_t i = 0; i < RANDOMNESS_LEN; i++)
  {
    randomness[i] = 0;
  }
}
/// @brief Reset the counter for the randomness buffer used for testing purposes
void reset_ctr() { ctr = 0; }
