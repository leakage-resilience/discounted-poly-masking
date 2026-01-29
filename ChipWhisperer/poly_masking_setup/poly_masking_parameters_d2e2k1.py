# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
secrets_supports = [0]
shares_supports = [224, 93, 225, 92, 1]
# Permutation map for shares squaring in GF(2^8)
shares_permutation_map = [1, 2, 3, 0, 4]
#Permutation map for secrets squaring in GF(2^8)
secrets_permutation_map = [0]
# Vandermonde matrix in GF(2^8)
V = [
    [1, 224, 93, 176, 225],
    [1, 93, 225, 237, 92],
    [1, 225, 92, 12, 224],
    [1, 92, 224, 80, 93],
    [1, 1, 1, 1, 1]
]
# Inverse Vandermonde matrix in GF(2^8)
V_inv = [
    [188, 189, 188, 189, 1],
    [80, 176, 237, 12, 1],
    [224, 93, 225, 92, 0],
    [1, 1, 1, 1, 0],
    [13, 81, 177, 236, 1]
]
M_enc = [
    [81, 92, 12],
    [81, 93, 13],
    [80, 93, 12]
]
M_dec = [
    [188, 189, 188, 189, 1]
]
A_tilde = [
    [
        [1, 0],
        [224, 0],
        [176, 0],
        [81, 0],
        [177, 0]
    ],
    [
        [1, 0],
        [0, 1],
        [92, 12],
        [93, 13],
        [93, 12]
    ]
]
