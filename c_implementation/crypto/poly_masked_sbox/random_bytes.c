// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "aes-independant.h"
#include "parameters.h"
#include <stdbool.h>
#include <stdint.h>
// counter that keeps track of the randomness buffer
uint32_t ctr = 0;
// buffer for the randomness
static uint8_t randomness[RANDOMNESS_LEN] = {0};

void init_rand(uint32_t seed)
{
  if (RANDOMNESS_LEN % 16 != 0)
  {
    handle_error("Buffer size must be a multiple of 16.");
  }

  // fill buffer with sampled randomness.
  for (uint32_t i = 0; i < RANDOMNESS_LEN; i++)
  {
    randomness[i] = rand(&seed);
  }
  ctr = 0;
}
/// @brief set the seed for the aes encryption
/// @param key seed for the aes encryption
void init_aes_rand_seed(uint8_t *key)
{
  uint8_t error[16] = {0};

  if (RANDOMNESS_LEN % 16 != 0)
  {
    for (uint8_t i = 0; i < 16; i++)
    {
      error[i] = i;
    }
    simpleserial_put('r', 16, error);
  }
  aes_indep_key(key);
}
/// @brief Initialize the randomness buffer with AES encryption
void init_aes_rand()
{
  uint8_t error[16] = {0};
  if (RANDOMNESS_LEN % 16 != 0)
  {
    for (uint8_t i = 0; i < 16; i++)
    {
      error[i] = i;
    }
    simpleserial_put('r', 16, error);
  }

  for (uint32_t i = 0; i < RANDOMNESS_LEN; i += 16)
  {
    if (i == 0)
    {
      aes_indep_enc(&randomness[i]);
    }

    else
    {
      randomness[i] = randomness[i - 1];
      aes_indep_enc(&randomness[i]);
    }
  }
  ctr = 0;
}
/// @brief Get a random byte from the buffer
/// @return a random byte
uint8_t inline get_random_byte() { return randomness[ctr++]; }

uint32_t get_ctr() { return ctr; }
/// @brief Reset the counter for the randomness buffer used for testing purposes
void reset_ctr() { ctr = 0; }
