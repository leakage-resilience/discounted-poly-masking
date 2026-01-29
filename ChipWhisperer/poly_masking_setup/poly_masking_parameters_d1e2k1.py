# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
secrets_supports = [0]
shares_supports = [224, 93, 225, 92]
# Permutation map for shares squaring in GF(2^8)
shares_permutation_map = [1, 2, 3, 0]
#Permutation map for secrets squaring in GF(2^8)
secrets_permutation_map = [0]
# Vandermonde matrix in GF(2^8)
V = [
    [1, 224, 93, 176],
    [1, 93, 225, 237],
    [1, 225, 92, 12],
    [1, 92, 224, 80]
]
# Inverse Vandermonde matrix in GF(2^8)
V_inv = [
    [177, 236, 13, 81],
    [93, 225, 92, 224],
    [224, 93, 225, 92],
    [1, 1, 1, 1]
]
M_enc = [
    [225, 224],
    [177, 176],
    [80, 81]
]
M_dec = [
    [177, 236, 13, 81]
]
A_tilde = [
    [
        [1],
        [224],
        [176],
        [81]
    ]
]
