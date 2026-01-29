// SPDX-License-Identifier: MIT
// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
#include "../src/poly_masking_parameters.h"
#include <stdint.h>
__attribute__((section(".data"))) uint8_t secrets_supports[1] = {0};
__attribute__((section(".data"))) uint8_t shares_supports[5] = {224, 93, 225, 92, 1};
// Permutation map for shares squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t shares_permutation_map[5] = {1, 2, 3, 0, 4};
// Permutation map for secrets squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t secrets_permutation_map[1] = {0};
// Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V[5][5] = {
    {1, 224, 93, 176, 225},
    {1, 93, 225, 237, 92},
    {1, 225, 92, 12, 224},
    {1, 92, 224, 80, 93},
    {1, 1, 1, 1, 1}
};
// Inverse Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V_inv[5][5] = {
    {188, 189, 188, 189, 1},
    {80, 176, 237, 12, 1},
    {224, 93, 225, 92, 0},
    {1, 1, 1, 1, 0},
    {13, 81, 177, 236, 1}
};
__attribute__((section(".data"))) uint8_t M_enc[4][2] = {
    {225, 224},
    {177, 176},
    {80, 81},
    {176, 177}
};
__attribute__((section(".data"))) uint8_t M_dec[1][5] = {
    {188, 189, 188, 189, 1}
};
__attribute__((section(".data"))) uint8_t A_tilde[1][5][1] = {
    {
        {1},
        {224},
        {176},
        {81},
        {177}
    }
};
__attribute__((section(".data"))) uint8_t lambda_hat[5][5] = {
    {188, 189, 188, 189, 1},
    {188, 189, 188, 189, 1},
    {188, 189, 188, 189, 1},
    {188, 189, 188, 189, 1},
    {188, 189, 188, 189, 1}
};
