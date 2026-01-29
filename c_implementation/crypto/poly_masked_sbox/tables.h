// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _TABLES_H
#define _TABLES_H
#include <stdint.h>
/* Log table */
extern const uint16_t log_table[256];

/* Antilog table */
extern const uint8_t antilog_table[1019];

// lookup table for squaring in GF(2^8)
extern const uint8_t square_table[256];
#endif