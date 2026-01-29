// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _POLY_MASKED_SBOX_H
#define _POLY_MASKED_SBOX_H
#include "poly_masking_parameters.h"
#include <stdint.h>
typedef uint32_t share;

void masked_sbox(share secret_sharing[NUM_SHARES]);

#endif // _POLY_MASKED_SBOX_H
