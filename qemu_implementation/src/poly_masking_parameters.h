// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _POLY_MASKING_PARAMETERS_H
#define _POLY_MASKING_PARAMETERS_H
#include <stdint.h>

// Parameters for the masking scheme.
// `DEGREE` is the degree of the polynomial sharing, corresponding to t-SNI
// security.
#ifndef DEGREE
#define DEGREE 1
#endif

// `FAULTS` is the error correction capability of the code.
#ifndef FAULTS
#define FAULTS 1
#endif

// `NUM_INJECTED_FAULTS` is the number of set value faults injected into the
// field operations of the scheme.
#ifndef NUM_INJECTED_FAULTS
#define NUM_INJECTED_FAULTS 0
#endif

// `NUM_SECRETS_PER_ENCODING` is the number of secrets encoded in one polynomial
// sharing.
#ifndef NUM_SECRETS_PER_ENCODING
#define NUM_SECRETS_PER_ENCODING 1
#endif
#if ((NUM_SECRETS_PER_ENCODING > 1) && \
     (NUM_SECRETS_PER_ENCODING > (DEGREE / 2)))
#error DEGREE must be at least as high as NUM_SECRETS_PER_ENCODING.
#endif

// `NUM_SHARES` is the number of shares, based on probes and faults.
#ifdef NUM_SHARES
#error "NUM_SHARES must not be defined externally."
#endif
#define NUM_SHARES (DEGREE + FAULTS + 1)

#define FLOOR_N_HALF (NUM_SHARES / 2)
#define CEIL_N_HALF ((NUM_SHARES + 1) / 2)
#define FLOOR_D_HALF (DEGREE / 2)
#define CEIL_D_HALF ((DEGREE + 1) / 2)

// Support values of the shares in the polynomial sharing.
extern uint8_t shares_supports[NUM_SHARES];
// Permutation map of the shares for squaring in GF(2^8).
extern uint8_t shares_permutation_map[NUM_SHARES];

// Support values of the secrets in the polynomial sharing.
extern uint8_t secrets_supports[NUM_SECRETS_PER_ENCODING];
// Permutation map of the secrets for squaring in GF(2^8).
extern uint8_t secrets_permutation_map[NUM_SECRETS_PER_ENCODING];

// Inverse Vandermonde matrix in GF(2^8).
extern uint8_t V[NUM_SHARES][NUM_SHARES];
extern uint8_t V_inv[NUM_SHARES][NUM_SHARES];

// Required for optimized zero encodings.
extern uint8_t A_tilde[DEGREE][NUM_SHARES]
                      [DEGREE + 1 - NUM_SECRETS_PER_ENCODING];

// Precomputed lambda_hat values for the polynomial masking.
extern uint8_t lambda_hat[NUM_SHARES][NUM_SHARES];

// extern uint8_t lambda_hat_precomputed_mul[NUM_SHARES][NUM_SHARES][256];

// Required for packed secret sharing.
extern uint8_t M_enc[NUM_SHARES - (DEGREE + 1 - NUM_SECRETS_PER_ENCODING)]
                    [DEGREE + 1];
extern uint8_t M_dec[NUM_SECRETS_PER_ENCODING][NUM_SHARES];

#if DEGREE == 1
extern uint8_t M_lambda_u[DEGREE + 1][NUM_SHARES];
extern uint8_t M_lambda_l[DEGREE + 1][NUM_SHARES];
#else
extern uint8_t M_lambda_u[((DEGREE) / 2) + 1][NUM_SHARES];
extern uint8_t M_lambda_l[((DEGREE) / 2) + 1][NUM_SHARES];
#endif

#endif
