# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
secrets_supports = [0]
shares_supports = [188, 189, 1]
# Permutation map for shares squaring in GF(2^8)
shares_permutation_map = [1, 0, 2]
#Permutation map for secrets squaring in GF(2^8)
secrets_permutation_map = [0]
# Vandermonde matrix in GF(2^8)
V = [
    [1, 188, 189],
    [1, 189, 188],
    [1, 1, 1]
]
# Inverse Vandermonde matrix in GF(2^8)
V_inv = [
    [1, 1, 1],
    [189, 188, 1],
    [188, 189, 1]
]
M_enc = [
    [189, 188],
    [188, 189]
]
M_dec = [
    [1, 1, 1]
]
A_tilde = [
    [
        [1],
        [188],
        [189]
    ]
]
