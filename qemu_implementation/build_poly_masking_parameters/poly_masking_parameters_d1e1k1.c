// SPDX-License-Identifier: MIT
// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
#include "../src/poly_masking_parameters.h"
#include <stdint.h>
__attribute__((section(".data"))) uint8_t secrets_supports[1] = {0};
__attribute__((section(".data"))) uint8_t shares_supports[3] = {188, 189, 1};
// Permutation map for shares squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t shares_permutation_map[3] = {1, 0, 2};
// Permutation map for secrets squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t secrets_permutation_map[1] = {0};
// Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V[3][3] = {
    {1, 188, 189},
    {1, 189, 188},
    {1, 1, 1}
};
// Inverse Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V_inv[3][3] = {
    {1, 1, 1},
    {189, 188, 1},
    {188, 189, 1}
};
__attribute__((section(".data"))) uint8_t M_enc[2][2] = {
    {189, 188},
    {188, 189}
};
__attribute__((section(".data"))) uint8_t M_dec[1][3] = {
    {1, 1, 1}
};
__attribute__((section(".data"))) uint8_t A_tilde[1][3][1] = {
    {
        {1},
        {188},
        {189}
    }
};
__attribute__((section(".data"))) uint8_t lambda_hat[3][3] = {
    {1, 1, 1},
    {1, 1, 1},
    {1, 1, 1}
};
