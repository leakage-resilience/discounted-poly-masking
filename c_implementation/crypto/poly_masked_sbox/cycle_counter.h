// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _CYCLE_COUNTER_H
#define _CYCLE_COUNTER_H
#include <stdint.h>
void init_cycle_counter(void);
void send_cycle_count(uint32_t cycles);
uint32_t get_elapsed_cycles(void);
#endif // _CYCLE_COUNTER_H