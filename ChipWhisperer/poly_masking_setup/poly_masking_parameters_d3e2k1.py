# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
secrets_supports = [0]
shares_supports = [224, 93, 225, 92, 188, 189]
# Permutation map for shares squaring in GF(2^8)
shares_permutation_map = [1, 2, 3, 0, 5, 4]
#Permutation map for secrets squaring in GF(2^8)
secrets_permutation_map = [0]
# Vandermonde matrix in GF(2^8)
V = [
    [1, 224, 93, 176, 225, 189],
    [1, 93, 225, 237, 92, 188],
    [1, 225, 92, 12, 224, 189],
    [1, 92, 224, 80, 93, 188],
    [1, 188, 189, 1, 188, 189],
    [1, 189, 188, 1, 189, 188]
]
# Inverse Vandermonde matrix in GF(2^8)
V_inv = [
    [225, 92, 224, 93, 189, 188],
    [176, 237, 12, 80, 188, 189],
    [93, 225, 92, 224, 1, 1],
    [1, 1, 1, 1, 0, 0],
    [80, 176, 237, 12, 189, 188],
    [189, 188, 189, 188, 1, 1]
]
M_enc = [
    [92, 81, 237, 225],
    [81, 188, 176, 92],
    [225, 92, 236, 80]
]
M_dec = [
    [225, 92, 224, 93, 189, 188]
]
A_tilde = [
    [
        [1, 0, 0],
        [224, 0, 0],
        [176, 0, 0],
        [81, 0, 0],
        [80, 0, 0],
        [225, 0, 0]
    ],
    [
        [1, 0, 0],
        [0, 1, 0],
        [92, 12, 0],
        [93, 13, 0],
        [92, 13, 0],
        [1, 1, 0]
    ],
    [
        [1, 0, 0],
        [0, 1, 0],
        [0, 0, 1],
        [81, 237, 225],
        [188, 176, 92],
        [92, 236, 80]
    ]
]
