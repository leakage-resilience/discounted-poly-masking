// SPDX-License-Identifier: MIT
// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
#include "../src/poly_masking_parameters.h"
#include <stdint.h>
__attribute__((section(".data"))) uint8_t secrets_supports[1] = {0};
__attribute__((section(".data"))) uint8_t shares_supports[4] = {224, 93, 225, 92};
// Permutation map for shares squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t shares_permutation_map[4] = {1, 2, 3, 0};
// Permutation map for secrets squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t secrets_permutation_map[1] = {0};
// Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V[4][4] = {
    {1, 224, 93, 176},
    {1, 93, 225, 237},
    {1, 225, 92, 12},
    {1, 92, 224, 80}
};
// Inverse Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V_inv[4][4] = {
    {177, 236, 13, 81},
    {93, 225, 92, 224},
    {224, 93, 225, 92},
    {1, 1, 1, 1}
};
__attribute__((section(".data"))) uint8_t M_enc[1][4] = {
    {92, 81, 237, 225}
};
__attribute__((section(".data"))) uint8_t M_dec[1][4] = {
    {177, 236, 13, 81}
};
__attribute__((section(".data"))) uint8_t A_tilde[3][4][3] = {
    {
        {1, 0, 0},
        {224, 0, 0},
        {176, 0, 0},
        {81, 0, 0}
    },
    {
        {1, 0, 0},
        {0, 1, 0},
        {92, 12, 0},
        {93, 13, 0}
    },
    {
        {1, 0, 0},
        {0, 1, 0},
        {0, 0, 1},
        {81, 237, 225}
    }
};
__attribute__((section(".data"))) uint8_t lambda_hat[4][4] = {
    {1, 81, 93, 12},
    {80, 1, 177, 225},
    {92, 176, 1, 236},
    {13, 224, 237, 1}
};
