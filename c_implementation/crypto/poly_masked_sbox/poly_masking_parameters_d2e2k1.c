// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "poly_masking_parameters.h"
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
    {1, 1, 1, 1, 1}};
// Inverse Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V_inv[5][5] = {
    {188, 189, 188, 189, 1},
    {80, 176, 237, 12, 1},
    {224, 93, 225, 92, 0},
    {1, 1, 1, 1, 0},
    {13, 81, 177, 236, 1}};
__attribute__((section(".data"))) uint8_t M_enc[3][3] = {
    {81, 92, 12},
    {81, 93, 13},
    {80, 93, 12}};
__attribute__((section(".data"))) uint8_t M_dec[1][5] = {
    {188, 189, 188, 189, 1}};
__attribute__((section(".data"))) uint8_t A_tilde[2][5][2] = {
    {{1, 0},
     {224, 0},
     {176, 0},
     {81, 0},
     {177, 0}},
    {{1, 0},
     {0, 1},
     {92, 12},
     {93, 13},
     {93, 12}}};
__attribute__((section(".data"))) uint8_t lambda_hat[5][5] = {
    {0, 92, 237, 81, 225},
    {177, 0, 224, 12, 92},
    {80, 236, 0, 93, 224},
    {225, 176, 13, 0, 93},
    {236, 13, 81, 177, 0}};
