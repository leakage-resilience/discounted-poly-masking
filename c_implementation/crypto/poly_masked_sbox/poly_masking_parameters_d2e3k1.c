// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "poly_masking_parameters.h"
#include <stdint.h>
__attribute__((section(".data"))) uint8_t secrets_supports[1] = {0};
__attribute__((section(".data"))) uint8_t shares_supports[6] = {224, 93, 225, 92, 188, 189};
// Permutation map for shares squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t shares_permutation_map[6] = {1, 2, 3, 0, 5, 4};
// Permutation map for secrets squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t secrets_permutation_map[1] = {0};
// Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V[6][6] = {
    {1, 224, 93, 176, 225, 189},
    {1, 93, 225, 237, 92, 188},
    {1, 225, 92, 12, 224, 189},
    {1, 92, 224, 80, 93, 188},
    {1, 188, 189, 1, 188, 189},
    {1, 189, 188, 1, 189, 188}};
// Inverse Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V_inv[6][6] = {
    {225, 92, 224, 93, 189, 188},
    {176, 237, 12, 80, 188, 189},
    {93, 225, 92, 224, 1, 1},
    {1, 1, 1, 1, 0, 0},
    {80, 176, 237, 12, 189, 188},
    {189, 188, 189, 188, 1, 1}};
__attribute__((section(".data"))) uint8_t M_enc[4][3] = {
    {81, 92, 12},
    {81, 93, 13},
    {80, 92, 13},
    {1, 1, 1}};
__attribute__((section(".data"))) uint8_t M_dec[1][6] = {
    {225, 92, 224, 93, 189, 188}};
__attribute__((section(".data"))) uint8_t A_tilde[2][6][2] = {
    {{1, 0},
     {224, 0},
     {176, 0},
     {81, 0},
     {80, 0},
     {225, 0}},
    {{1, 0},
     {0, 1},
     {92, 12},
     {93, 13},
     {92, 13},
     {1, 1}}};
__attribute__((section(".data"))) uint8_t lambda_hat[6][6] = {
    {0, 13, 12, 225, 176, 81},
    {92, 0, 81, 80, 177, 237},
    {176, 224, 0, 177, 12, 236},
    {236, 237, 93, 0, 13, 80},
    {13, 188, 177, 188, 0, 189},
    {189, 81, 189, 236, 188, 0}};
