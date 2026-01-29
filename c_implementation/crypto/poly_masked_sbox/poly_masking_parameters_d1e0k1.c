// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "poly_masking_parameters.h"
#include <stdint.h>
__attribute__((section(".data"))) uint8_t secrets_supports[1] = {0};
__attribute__((section(".data"))) uint8_t shares_supports[2] = {188, 189};
// Permutation map for shares squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t shares_permutation_map[2] = {1, 0};
// Permutation map for secrets squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t secrets_permutation_map[1] = {0};
// Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V[2][2] = {
    {1, 188},
    {1, 189}};
// Inverse Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V_inv[2][2] = {
    {189, 188},
    {1, 1}};
__attribute__((section(".data"))) uint8_t M_enc[1][2] = {
    {189, 188}};
__attribute__((section(".data"))) uint8_t M_dec[1][2] = {
    {189, 188}};
__attribute__((section(".data"))) uint8_t A_tilde[1][2][1] = {
    {{1},
     {188}}};
__attribute__((section(".data"))) uint8_t lambda_hat[2][2] = {
    {189, 188},
    {189, 188}};
