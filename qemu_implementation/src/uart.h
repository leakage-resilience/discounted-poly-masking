// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _UART_H
#define _UART_H

#include "stdint.h"

void print(const char *s);
void print_uint(uint32_t n);
void print_byte_hex(uint8_t b);
#endif