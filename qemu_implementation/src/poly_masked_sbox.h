// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _POLY_MASKED_SBOX_H
#define _POLY_MASKED_SBOX_H
#include "poly_masking_parameters.h"
#include <stdbool.h>
#include <stdint.h>
typedef uint32_t share;

/// @brief number of field operations performed during a laola multiplication
/// @return number of field operations
uint32_t get_num_field_ops();

/// @brief reset the field operation counter
void reset_field_op_ctr();

/// @brief enable fault injection
void enable_faults();

/// @brief disable fault injection
void disable_faults();

/// @brief set the indices of the field operations where the set value faults
/// should be injected
void set_fault_indices(uint32_t indices[NUM_INJECTED_FAULTS]);

/// @brief set the values of the faults to be injected
void set_fault_value(uint32_t index, uint8_t value);

/// @brief clear the fault buffers
void clear_fault_buffers();

void sw_mul(share res[NUM_SHARES], share f[NUM_SHARES], share g[NUM_SHARES]);
uint8_t lambda_hat_non_packed(uint8_t i, uint8_t j);
void poly_sharing_enc(share sharing[NUM_SHARES], uint8_t s, uint8_t n_prime,
                      uint8_t d_prime);
uint8_t poly_sharing_dec(share sharing[NUM_SHARES]);

bool fault_detected(share f[NUM_SHARES]);

void poly_packed_sharing_enc(share sharing[NUM_SHARES],
                             share secrets[NUM_SECRETS_PER_ENCODING]);
void poly_packed_sharing_dec(share secrets[NUM_SECRETS_PER_ENCODING],
                             share sharing[NUM_SHARES]);

/// @brief Zero-Encoding of a polynomial
/// @param res Target memory location for resulting shares of the zero encoding
/// @param d_prime The degree of the encoded polynomial.
/// @param randoffset ignored, use optZEnc instead.
void zenc(share res[NUM_SHARES], uint8_t d_prime, uint8_t randoffset);

/// @brief generate a sum of DEGREE many zero encodings
/// @param res buffer for resulting shares of the zero encoding
void szenc(share res[NUM_SHARES]);

/// @brief Compute the optimized zero encoding.
/// @param g the resulting shares of the zero encoding
/// @param o `Rand Offset` parameter for opt-sZenc
void optZEnc(share res[NUM_SHARES], uint8_t d_prime, uint8_t randoffset);

/// @brief Compute the optimised sumerised zero encoding.
/// Improves randomness complexity in higher orders.
/// @param res the resulting shares of the sumarised zero encoding
void optsZEnc(share res[NUM_SHARES]);

/// @brief Add Zenc and apply higher order coefficients refresh depending on if
/// any higher order coefficients are non-zero.
/// @param f Polynomial sharing to be refreshed
void p_refresh(share f[NUM_SHARES]);

void sw_add(share res[NUM_SHARES], share f[NUM_SHARES], share g[NUM_SHARES]);

void poly_masked_square(share res[NUM_SHARES], share f[NUM_SHARES]);

/// @brief Compute the masked multiplication of the shares of two polynomials
/// @param res the resulting shares of the multiplication
/// @param f shares of the first polynomial encoding.
/// @param g shares of the second polynomial encoding.
void poly_masked_multiplication_laola(share res[NUM_SHARES],
                                      share f[NUM_SHARES], share g[NUM_SHARES]);

/// @brief Compute a masked S-box on a polynomial sharing
/// @param res the buffer that the resulting shares will be written to
/// @param f the input polynomial sharing of the initial secret
void poly_masked_sbox(share res[NUM_SHARES], share f[NUM_SHARES]);

#endif // _POLY_MASKED_SBOX_H
