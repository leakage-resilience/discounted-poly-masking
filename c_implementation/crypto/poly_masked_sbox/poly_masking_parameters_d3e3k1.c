// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "poly_masking_parameters.h"
#include <stdint.h>
__attribute__((section(".data"))) uint8_t secrets_supports[1] = {0};
__attribute__((section(".data"))) uint8_t shares_supports[7] = {224, 93, 225, 92, 188, 189, 1};
// Permutation map for shares squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t shares_permutation_map[7] = {1, 2, 3, 0, 5, 4, 6};
// Permutation map for secrets squaring in GF(2^8)
__attribute__((section(".data"))) uint8_t secrets_permutation_map[1] = {0};
// Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V[7][7] = {
    {1, 224, 93, 176, 225, 189, 237},
    {1, 93, 225, 237, 92, 188, 12},
    {1, 225, 92, 12, 224, 189, 80},
    {1, 92, 224, 80, 93, 188, 176},
    {1, 188, 189, 1, 188, 189, 1},
    {1, 189, 188, 1, 189, 188, 1},
    {1, 1, 1, 1, 1, 1, 1}};
// Inverse Vandermonde matrix in GF(2^8)
__attribute__((section(".data"))) uint8_t V_inv[7][7] = {
    {1, 1, 1, 1, 1, 1, 1},
    {176, 237, 12, 80, 188, 189, 0},
    {93, 225, 92, 224, 1, 1, 0},
    {225, 92, 224, 93, 188, 189, 1},
    {176, 237, 12, 80, 1, 1, 1},
    {93, 225, 92, 224, 189, 188, 1},
    {224, 93, 225, 92, 188, 189, 1}};
__attribute__((section(".data"))) uint8_t M_enc[4][4] = {
    {92, 81, 237, 225},
    {81, 188, 176, 92},
    {225, 92, 236, 80},
    {237, 176, 176, 236}};
__attribute__((section(".data"))) uint8_t M_dec[1][7] = {
    {1, 1, 1, 1, 1, 1, 1}};
__attribute__((section(".data"))) uint8_t A_tilde[3][7][3] = {
    {{1, 0, 0},
     {224, 0, 0},
     {176, 0, 0},
     {81, 0, 0},
     {80, 0, 0},
     {225, 0, 0},
     {177, 0, 0}},
    {{1, 0, 0},
     {0, 1, 0},
     {92, 12, 0},
     {93, 13, 0},
     {92, 13, 0},
     {1, 1, 0},
     {93, 12, 0}},
    {{1, 0, 0},
     {0, 1, 0},
     {0, 0, 1},
     {81, 237, 225},
     {188, 176, 92},
     {92, 236, 80},
     {176, 176, 236}}};
__attribute__((section(".data"))) uint8_t lambda_hat[7][7] = {
    {224, 80, 237, 189, 12, 236, 1},
    {188, 93, 176, 12, 13, 80, 1},
    {80, 189, 225, 237, 176, 81, 1},
    {12, 176, 188, 92, 177, 237, 1},
    {237, 225, 80, 224, 188, 0, 1},
    {93, 12, 92, 176, 0, 189, 1},
    {177, 236, 13, 81, 189, 188, 1}};
