// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "cycle_counter.h"
#include "../hal/hal.h"
#include "../hal/stm32f4/CMSIS/device/stm32f415xx.h"

/// @brief initialize the cycle counter for the target and set it to 0
void init_cycle_counter(void)
{
  if (!(DWT->CTRL & DWT_CTRL_CYCCNTENA_Msk))
  {
    CoreDebug->DEMCR |=
        CoreDebug_DEMCR_TRCENA_Msk;      // Enable Trace in Core Debug
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk; // Enable the cycle counter
  }

  DWT->CYCCNT = 0; // Reset the cycle counter
}
/// @brief get the elapsed cycles since the last call to init_cycle_counter
/// @return a 32-bit integer representing the number of elapsed cycles
uint32_t get_elapsed_cycles(void) { return DWT->CYCCNT; }

/// @brief send the cycle count to the host
/// @param cycles elapsed cycles
void send_cycle_count(uint32_t cycles)
{
  // Split the 32-bit cycle count into four 8-bit chunks and send via
  // SimpleSerial
  uint8_t cycle_bytes[4];
  cycle_bytes[0] = (cycles >> 24) & 0xFF; // Most significant byte
  cycle_bytes[1] = (cycles >> 16) & 0xFF;
  cycle_bytes[2] = (cycles >> 8) & 0xFF;
  cycle_bytes[3] = cycles & 0xFF; // Least significant byte
  simpleserial_put('r', 4, cycle_bytes);
}