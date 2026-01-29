// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "poly_masked_sbox.h"
#include "cycle_counter.h"
#include "parameters.h"
#include "random_bytes.h"
#include "tables.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if OPT_ZENC == 1
#define ZENC optZEnc
#define SZENC optsZEnc
#define ZENC_ADD optZEnc_add
#else
#define ZENC zenc
#define SZENC szenc
#define ZENC_ADD zenc_add
#endif

/// @brief Multiplication in GF(2^8) through LUT
/// https://eprint.iacr.org/2023/375.pdf, specific to AES irr. pol.
/// @param f first element
/// @param g second element
#define field_mul(f, g) antilog_table[log_table[(f)] + log_table[(g)]]

/// @brief Addition in GF(2^8)
/// @param f first element
/// @param g second element
#define field_add(f, g) ((f) ^ (g))

/// @brief Sharewise addition of a polynomial encoding and a field element in
/// GF(2^8).
/// @param res resulting shares of the addition
/// @param f shares of the polynomial
/// @param c the constant to be added
#if DEGREE == 1
static inline __attribute__((always_inline)) void
add_const(share res[NUM_SHARES], share f[NUM_SHARES], uint8_t c)
{
  for (uint8_t i = 0; i < (NUM_SHARES); i++)
  {
    volatile uint32_t *res_ptr = (uint32_t *)&res[i];
    volatile uint32_t *f_ptr = (uint32_t *)&f[i];
    volatile uint8_t *c_ptr = &c;
    __asm__ volatile("eor %[result], %[op1], %[op2]"
                     : [result] "=r"(*res_ptr)
                     : [op1] "r"(*f_ptr), [op2] "r"(c)
                     : "memory");
  }
}
#else
static inline __attribute__((always_inline)) void
add_const(share res[NUM_SHARES], share f[NUM_SHARES], uint8_t c)
{
  for (int i = 0; i < NUM_SHARES; i++)
  {
    res[i] = field_add(f[i], c);
  }
}
#endif
/// @brief Sharewise multiplication of a polynomial and a constant
/// @param res the resulting shares of the multiplication
/// @param f shares of the polynomial
/// @param c the constant to be added
#if DEGREE == 1
static inline __attribute__((always_inline)) void
mul_const(share res[NUM_SHARES], share f[NUM_SHARES], uint8_t c)
{
  for (uint8_t i = 0; i < NUM_SHARES; i++)
  {
    volatile share *res_ptr = &res[i];
    volatile share *f_ptr = &f[i];
    volatile uint8_t *c_ptr = &c;
    volatile const uint16_t *log_table_ptr = log_table;
    volatile const uint8_t *antilog_table_ptr = antilog_table;

    __asm__ volatile(
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        "ldrb.w    r3, [%[f_ptr]]         \n\t"
        "ldrh.w r3, [%[log_table], r3, lsl #1]\n\t "
        "ldrb.w    r4, [%[g_ptr]]         \n\t"
        "ldrh.w r4, [%[log_table], r4, lsl #1]\n\t "
        // Add the two log table results
        "add    r3, r4            \n\t"
        // Lookup antilog_table[ sum ]
        "ldrb.w    r3, [%[antilog_table], r3]               \n\t"
        // Store the result into res[i]
        "str    r3, [%[res_ptr]]    \n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        :
        : [f_ptr] "r"(f_ptr), [g_ptr] "r"(c_ptr), [res_ptr] "r"(res_ptr),
          [log_table] "r"(log_table_ptr), [antilog_table] "r"(antilog_table_ptr)
        : "r3", "r4", "memory");
  }
}
#else
static inline __attribute__((always_inline)) void
mul_const(share res[NUM_SHARES], share f[NUM_SHARES], uint8_t c)
{
  for (int i = 0; i < NUM_SHARES; i++)
  {
    res[i] = field_mul(f[i], c);
  }
}
#endif
/// @brief Sharewise addition of two polynomials
/// @param res the resulting shares of the addition
/// @param f shares of the first polynomial
/// @param g shares of the second polynomial
#if DEGREE == 1
static inline __attribute__((always_inline)) void sw_add(share *res, share *f,
                                                         share *g)
{
  // TODO: we can probably remove volatiles here for better performance, only
  // need to keep the eor
  for (uint8_t i = 0; i < (NUM_SHARES); i++)
  {
    volatile uint32_t *res_ptr = (uint32_t *)&res[i];
    volatile uint32_t *f_ptr = (uint32_t *)&f[i];
    volatile uint32_t *g_ptr = (uint32_t *)&g[i];
    __asm__ volatile("eor %[result], %[op1], %[op2]"
                     : [result] "=r"(*res_ptr)
                     : [op1] "r"(*f_ptr), [op2] "r"(*g_ptr)
                     : "memory");
  }
}
#else
static inline __attribute__((always_inline)) void
sw_add(share res[NUM_SHARES], share f[NUM_SHARES], share g[NUM_SHARES])
{
  for (uint8_t i = 0; i < NUM_SHARES; i++)
  {
    res[i] = (uint8_t)field_add(f[i], g[i]);
  }
}
#endif

/// @brief Sharewise mulplication of two polynomials
/// @param res the resulting shares of the multiplication
/// @param f shares of the first polynomial
/// @param g shares of the second polynomial
#if DEGREE == 1
static inline void sw_mul(share res[NUM_SHARES], share f[NUM_SHARES],
                          share g[NUM_SHARES])
{
  for (uint8_t i = 0; i < NUM_SHARES; i++)
  {
    volatile share *res_ptr = &res[i];
    volatile share *f_ptr = &f[i];
    volatile share *g_ptr = &g[i];
    volatile const uint16_t *log_table_ptr = log_table;
    volatile const uint8_t *antilog_table_ptr = antilog_table;

    __asm__ volatile(

        "ldrb.w    r3, [%[f_ptr]]         \n\t"
        "ldrh.w r3, [%[log_table], r3, lsl #1]\n\t "
        "ldrb.w    r4, [%[g_ptr]]         \n\t"
        "ldrh.w r4, [%[log_table], r4, lsl #1]\n\t "
        // Add the two log table results
        "add    r3, r4            \n\t"
        // Lookup antilog_table[ sum ]
        "ldrb.w    r3, [%[antilog_table], r3]               \n\t"
        // Store the result into res[i]
        "str    r3, [%[res_ptr]]    \n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        :
        : [f_ptr] "r"(f_ptr), [g_ptr] "r"(g_ptr), [res_ptr] "r"(res_ptr),
          [log_table] "r"(log_table_ptr), [antilog_table] "r"(antilog_table_ptr)
        : "r3", "r4", "memory");
  }
}

#else
static inline void sw_mul(share res[NUM_SHARES], share f[NUM_SHARES],
                          share g[NUM_SHARES])
{
  for (int i = 0; i < NUM_SHARES; i++)
  {
    res[i] = field_mul(f[i], g[i]);
  }
}
#endif

/// @brief Compute the power of a polynomial in GF(2^8) using the square and
/// multiply algorithm
/// @param f polynomial to be raised to the power of `exp`
/// @param exp exponent to raise the polynomial to
/// @return polynomial f raised to the power of `exp`
static inline uint8_t poly_power(uint8_t f, uint8_t exp)
{
  uint8_t res = 0b00000001; // Start with the multiplicative identity
  uint8_t base = f;

  while (exp > 0)
  {
    if (exp & 1)
    {
      res = field_mul(res, base); // multiply by base if bit in `exp` is set
    }
    base = square_table[base]; // square by using LUT
    exp >>= 1;                 // shift exponent to the right by 1 bit
  }

  return res;
}

/// @brief Alters the lambda_hat matrix by rerandomizing the upper fault
/// coefficients, then denoted as A_hat. Corresponds to Algorithm 4 in https://eprint.iacr.org/2025/1275.
/// @param A_hat Buffer to write the resulting matrix into.
/// @param d_prime Coefficients above this degree are randomized, everything
/// below is a zero coefficient.
static inline __attribute__((always_inline)) void compute_A_hat(
    share A_hat[NUM_SHARES]
               [NUM_SHARES], // buffer to write the resulting array into
    uint8_t d_prime          // this is either ceil(DEGREE / 2) or floor(DEGREE / 2),
                             // depending on the split_red call it is generated for
)
{
  // this function only works for n > DEGREE + 1, meaning fault shares are
  // present
  share R_hat[FAULTS][NUM_SHARES];

  for (int k = 0; k < FAULTS; k++)
  {
    share coeffs[NUM_SHARES];
    for (int i = d_prime; i < NUM_SHARES; i++)
    {
      coeffs[i] = get_random_byte();
    }
    for (int i = 0; i < NUM_SHARES; i++)
    {
      share sum = 0;
      for (int j = d_prime; j < NUM_SHARES; j++)
      {
        sum = field_add(sum, field_mul(coeffs[j], V[i][j]));
      }
      R_hat[k][i] = sum;
    }
  }
  for (int i = 0; i < NUM_SHARES; i++)
  {
    for (int j = 0; j < NUM_SHARES; j++)
    {
      share sum = 0;
      for (int k = DEGREE + 1; k < NUM_SHARES; k++)
      {

        sum =
            field_add(sum, field_mul(R_hat[k - (DEGREE + 1)][i], V_inv[k][j]));
      }
      A_hat[i][j] = field_add(lambda_hat[i][j], sum);
    }
  }
}

/// @brief Generate shares of a random polynomial of degree d
/// @param sharing the buffer that the resulting shares will be writter to
/// @param s the secret value of the polynomial
/// @param d_prime the degree of the polynomial
static inline __attribute__((always_inline)) void
polynomial_sharing(share sharing[NUM_SHARES], uint8_t s, uint8_t d_prime)
{
  share f[d_prime + 1];
  f[0] = (s);
  for (int i = 1; i < (d_prime + 1); i++)
  {
    f[i] = get_random_byte();
  }
  for (int i = 0; i < (NUM_SHARES); i++)
  {
    share sum = f[0];
    for (int j = 1; j < (d_prime + 1); j++)
    {
      sum = field_add(sum, field_mul(f[j], poly_power(shares_supports[i], j)));
    }
    (sharing)[i] = sum;
  }
}

static inline __attribute__((always_inline)) void
zenc(share res[NUM_SHARES], uint8_t d_prime, uint8_t offset)
{
  polynomial_sharing(res, 0, d_prime);
}

static inline __attribute__((always_inline)) void
zenc_add(share res[NUM_SHARES], uint8_t d_prime, uint8_t offset)
{
  share ze[NUM_SHARES];
  polynomial_sharing(ze, 0, d_prime);
  sw_add(res, res, ze);
}

static inline __attribute__((always_inline)) void szenc(share res[NUM_SHARES])
{
  zenc(res, DEGREE, 0);
  share ze[NUM_SHARES];
  for (int i = 1; i < DEGREE - NUM_SECRETS_PER_ENCODING + 1; i++)
  {
    zenc(ze, DEGREE, 0);
    sw_add(res, res, ze);
  }
}

static inline __attribute__((always_inline)) void
optZEnc(share res[NUM_SHARES], uint8_t d, uint8_t offset)
{

  for (uint8_t i = 0; i < offset; i++)
  {
    res[i] = 0;
  }
  for (uint8_t i = offset; i < d - NUM_SECRETS_PER_ENCODING + 1; i++)
  {
    res[i] = get_random_byte();
  }
  for (uint8_t i = d - NUM_SECRETS_PER_ENCODING + 1; i < NUM_SHARES; i++)
  {
    res[i] = 0;
  }

  for (uint8_t i = d + 1 - NUM_SECRETS_PER_ENCODING; i < NUM_SHARES; i++)
  {
    for (uint8_t j = offset; j < d - NUM_SECRETS_PER_ENCODING + 1; j++)
    {
      res[i] =
          (uint8_t)field_add(res[i], field_mul(res[j], A_tilde[d - 1][i][j]));
    }
  }
}

static inline __attribute__((always_inline)) void
optZEnc_add(share res[NUM_SHARES], uint8_t d, uint8_t offset)
{

  share tmp[NUM_SHARES];
  for (int i = 0; i < offset; i++)
  {
    tmp[i] = 0;
  }
  for (int i = offset; i < d - NUM_SECRETS_PER_ENCODING + 1; i++)
  {
    tmp[i] = get_random_byte();
  }
  for (int i = d - NUM_SECRETS_PER_ENCODING + 1; i < NUM_SHARES; i++)
  {
    tmp[i] = 0;
  }

  for (int8_t i = d + 1 - NUM_SECRETS_PER_ENCODING; i < NUM_SHARES; i++)
  {
    for (int8_t j = offset; j < d - NUM_SECRETS_PER_ENCODING + 1; j++)
    {
      tmp[i] =
          (uint8_t)field_add(tmp[i], field_mul(tmp[j], A_tilde[d - 1][i][j]));
    }
  }
  sw_add(res, res, tmp);
}

static inline __attribute__((always_inline)) void
optsZEnc(share res[NUM_SHARES])
{
  memset(res, 0, NUM_SHARES * sizeof(share));
  optZEnc(res, DEGREE, 0);

  for (uint8_t j = 1; j < DEGREE - NUM_SECRETS_PER_ENCODING + 1; j++)
  {
    optZEnc_add(res, DEGREE, j);
  }
}

// apply a regular ZENC together with a higher order refresh
static inline __attribute__((always_inline)) void
p_refresh(share f[NUM_SHARES])
{
  share R[FAULTS][NUM_SHARES];
  share S[NUM_SHARES] = {0};
  for (int k = 0; k < FAULTS; k++)
  {
    share rand_coeffs[FAULTS];
    for (int j = 0; j < FAULTS; j++)
    {
      rand_coeffs[j] = get_random_byte();
    }
    for (int i = 0; i < NUM_SHARES; i++)
    {
      share sum = 0;
      for (int j = 0; j < FAULTS; j++)
      {
        sum = field_add(sum, field_mul(rand_coeffs[j], V[i][j]));
      }
      R[k][i] = sum;
    }
  }

  share A[NUM_SHARES][NUM_SHARES] = {{0}};

  for (int i = 0; i < NUM_SHARES; i++)
  {
    A[i][i] = 1;
  }

  for (int i = 0; i < NUM_SHARES; i++)
  {
    share Zi[NUM_SHARES];
    ZENC(Zi, DEGREE, 0);
    for (int j = 0; j < NUM_SHARES; j++)
    {
      for (int k = DEGREE + 1; k < NUM_SHARES; k++)
      {
        A[i][j] =
            field_add(A[i][j], field_mul(R[k - (DEGREE + 1)][j], V_inv[k][i]));
      }
      Zi[j] = field_add(Zi[j], field_mul(A[i][j], f[i]));
      S[j] = field_add(S[j], Zi[j]);
    }
  }
  for (int i = 0; i < NUM_SHARES; i++)
  {
    f[i] = S[i];
  }
}

// use a macro to precompute if CEIL_N_HALF is smaller or larger then
// (DEGREE + 1 - NUM_SECRETS_PER_ENCODING)
#define CEIL_N_HALF_IS_SMALLER_DEGREE \
  (CEIL_N_HALF < DEGREE + 1 - NUM_SECRETS_PER_ENCODING)

/// @brief Split a polynomial f into f_prime and f_double_prime of degree
/// d, where deg(f_prime) + deg(f_double_prime) = d/2 (for first order
/// this is 0)
/// @param f_prime shares of the first split polynomial
/// @param f_double_prime shares of the second split polynomial
/// @param f input polynomial to be split

static inline void split_red(share A_hat[NUM_SHARES][NUM_SHARES],
                             share *f_prime, share *f_double_prime, share *f,
                             uint8_t d)
{
  share g[NUM_SHARES][NUM_SHARES];
  share f_prime_cal[NUM_SHARES][NUM_SHARES];
  share f_cal[NUM_SHARES][NUM_SHARES] = {{0}};

  // This is a really annoying case distinction to provide performant
  // constant time code. The problem is that if CEIL_N_HALF is smaller than
  // (DEGREE + 1 - NUM_SECRETS_PER_ENCODING) then splitting into two loops
  // causes a wrong result since the first loop is until (DEGREE + 1 -
  // NUM_SECRETS_PER_ENCODING). To mitigate this we can conclude that if
  // this case occurs we can always use a reduced degree and not split the
  // loop. When CEIL_N_HALF is not smaller we can safely split the loop into
  // two parts that cover both conditions.
#if CEIL_N_HALF_IS_SMALLER_DEGREE
  for (int j = 0; j < CEIL_N_HALF; j++)
  {
#if OPT_ZENC == 1
    ZENC(g[j], DEGREE - j, 0);
#else
    ZENC(g[j], DEGREE, 0);
#endif
  }
#else
  for (int j = 0; j < DEGREE + 1 - NUM_SECRETS_PER_ENCODING; j++)
  {
#if OPT_ZENC == 1
    ZENC(g[j], DEGREE - j, 0);
#else
    ZENC(g[j], DEGREE, 0);
#endif
  }
  for (int j = DEGREE + 1 - NUM_SECRETS_PER_ENCODING; j < CEIL_N_HALF; j++)
  {
    ZENC(g[j], DEGREE, 0);
  }
#endif
  // if n is odd, then we have to add the last element of g_hat to g,
  // so that g_hat can cancel out by the addition of f' and f''
  for (int j = 0; j < FLOOR_N_HALF; j++)
  {
    for (int i = 0; i < NUM_SHARES; i++)
    {
      g[CEIL_N_HALF + j][i] = g[j][i];
    }
  }

#if (NUM_SHARES % 2 == 1)
  sw_add(g[FLOOR_N_HALF - 1], g[FLOOR_N_HALF - 1], g[CEIL_N_HALF - 1]);
#endif

  // put parts of secret and errors into f_prime_cal
  for (int j = 0; j < FLOOR_N_HALF; j++)
  {
    for (int i = 0; i < NUM_SHARES; i++)
    {
#if FAULTS > 0
      f_prime_cal[j][i] = field_mul(A_hat[i][j], f[j]);
#else
      f_prime_cal[j][i] = field_mul(lambda_hat[i][j], f[j]);
#endif
    }
    sw_add(f_cal[j], f_prime_cal[j], g[j]);
    sw_add(f_prime, f_prime, f_cal[j]);
  }

  // Here we do not need the annoying distinction, as d < CEIL_DEGREE_HALF
  // < CEIL_N_HALF and therefore the loop can always be split safely.

  for (int j = 0; j < d + 1 - NUM_SECRETS_PER_ENCODING; j++)
  {
    // DEGREE = 1 one does not require this encoding since the full encoding
    // before is of degree 1 and this one would be 0, meaning it is not
    // needed.
#if DEGREE > 1
#if OPT_ZENC == 1
    ZENC_ADD(g[FLOOR_N_HALF + j], d - j, 0);
#else
    ZENC_ADD(g[FLOOR_N_HALF + j], d, 0);
#endif
#endif
  }

  for (int j = d + 1 - NUM_SECRETS_PER_ENCODING; j < CEIL_N_HALF; j++)
  {
#if DEGREE > 1
    ZENC_ADD(g[FLOOR_N_HALF + j], d, 0);
#endif
  }

  // add together secret and errors for the second half
  for (int j = 0; j < CEIL_N_HALF; j++)
  {
    for (int i = 0; i < NUM_SHARES; i++)
    {
#if FAULTS > 0
      f_prime_cal[FLOOR_N_HALF + j][i] =
          field_mul(A_hat[i][FLOOR_N_HALF + j], f[FLOOR_N_HALF + j]);
#else
      f_prime_cal[FLOOR_N_HALF + j][i] =
          field_mul(lambda_hat[i][FLOOR_N_HALF + j], f[FLOOR_N_HALF + j]);
#endif
    }
    sw_add(f_cal[FLOOR_N_HALF + j], f_prime_cal[FLOOR_N_HALF + j],
           g[FLOOR_N_HALF + j]);
    sw_add(f_double_prime, f_double_prime, f_cal[FLOOR_N_HALF + j]);
  }
}

static inline void poly_masked_multiplication_laola(share res[NUM_SHARES],
                                                    share f[NUM_SHARES],
                                                    share g[NUM_SHARES])
{
#if DEGREE == 1

  share f_prime[NUM_SHARES] = {0};
  share f_double_prime[NUM_SHARES] = {0};
  share h0[NUM_SHARES];
  share h1[NUM_SHARES];
  share A_hat[NUM_SHARES][NUM_SHARES];
// New fault countermeasures from https://eprint.iacr.org/2025/1275
#if FAULTS > 0
  compute_A_hat(A_hat, DEGREE);
  p_refresh(g);
#endif
  split_red(A_hat, f_prime, f_double_prime, f, DEGREE);

  sw_mul(h0, f_prime, g);
  sw_mul(h1, f_double_prime, g);
  SZENC(res);
  sw_add(res, res, h0);
  sw_add(res, res, h1);
#else
  share f_prime[NUM_SHARES] = {0};
  share f_double_prime[NUM_SHARES] = {0};
  share g_prime[NUM_SHARES] = {0};
  share g_double_prime[NUM_SHARES] = {0};
  share h0[NUM_SHARES];
  share h1[NUM_SHARES];
  share h2[NUM_SHARES];
  share h3[NUM_SHARES];
  share A_hat[NUM_SHARES][NUM_SHARES];
#if FAULTS > 0
  compute_A_hat(A_hat, FLOOR_D_HALF);
#endif
  split_red(A_hat, f_prime, f_double_prime, f, CEIL_D_HALF);
#if FAULTS > 0
  compute_A_hat(A_hat, FLOOR_D_HALF);
#endif
  split_red(A_hat, g_prime, g_double_prime, g, FLOOR_D_HALF);
  sw_mul(h0, f_prime, g_prime);
  sw_mul(h1, f_double_prime, g_prime);
  sw_mul(h2, f_prime, g_double_prime);
  sw_mul(h3, f_double_prime, g_double_prime);
  SZENC(res);
  sw_add(res, res, h0);
  sw_add(res, res, h1);
  sw_add(res, res, h2);
  sw_add(res, res, h3);
#endif
}

/// @brief Compute the square over a polynomial sharing in GF(2^8).
/// @param res the resulting shares.
/// @param f the input shares.
static inline __attribute__((always_inline)) void
poly_masked_square(share res[NUM_SHARES], share f[NUM_SHARES])
{
#if ENABLE_FROBENIUS == 1
#if DEGREE == 1
  for (uint8_t i = 0; i < NUM_SHARES; i++)
  {
    uint8_t res_pos = shares_permutation_map[i];
    volatile share *res_ptr = &res[res_pos];
    volatile share *f_ptr = &f[i];
    volatile const uint8_t *square_table_ptr = square_table;
    __asm__ volatile("mov r3, #0\n\t"
                     "ldrb.w    r3, [%[f_ptr]]         \n\t"
                     "ldrb.w    r3, [%[square_table], r3]               \n\t"
                     "str    r3, [%[res_ptr]]    \n\t"
                     "mov r3, #0\n\t"
                     :
                     : [f_ptr] "r"(f_ptr), [res_ptr] "r"(res_ptr),
                       [square_table] "r"(square_table_ptr)
                     : "r3", "memory");
  }
#else
  for (uint8_t i = 0; i < NUM_SHARES; i++)
  {
    // due to the frobenius endomorphism squaring can be done linearly on
    // shares. However, the coresponding support points also change, which is
    // why the shares need to be permuted. such a permutation map is generated
    // for specific parameters and is therefore only valid for specific support
    // points.
    res[shares_permutation_map[i]] = square_table[(uint8_t)f[i]];
  }
#endif
#else
  poly_masked_multiplication_laola(res, f, f);
#endif
}

static inline void poly_masked_sbox(share res[NUM_SHARES],
                                    share f[NUM_SHARES])
{

  share tmp[NUM_SHARES];
  share f_two[NUM_SHARES];
  share f_four[NUM_SHARES];
  share f_eight[NUM_SHARES];
  share f_nine[NUM_SHARES];
  share f_sixteen[NUM_SHARES];
  share f_eightteen[NUM_SHARES];
  share f_nineteen[NUM_SHARES];
  share f_thirtytwo[NUM_SHARES];
  share f_thirtysix[NUM_SHARES];
  share f_fiftyfive[NUM_SHARES];
  share f_sixtyfour[NUM_SHARES];
  share f_seventytwo[NUM_SHARES];
  share f_onehundrettwentyseven[NUM_SHARES];
  share f_onehundrettwentyeight[NUM_SHARES];
  share f_twohundretfiftyfour[NUM_SHARES];

  // x^254 calculation
  poly_masked_square(f_two, f);

#ifndef ENABLE_TRIGGERS
  poly_masked_square(f_four, f_two);

  poly_masked_square(f_eight, f_four);

  poly_masked_multiplication_laola(f_nine, f_eight, f);

  poly_masked_square(f_eightteen, f_nine);

  poly_masked_multiplication_laola(f_nineteen, f_eightteen, f);

  poly_masked_square(f_thirtysix, f_eightteen);

  poly_masked_multiplication_laola(f_fiftyfive, f_thirtysix, f_nineteen);

  poly_masked_square(f_seventytwo, f_thirtysix);

  poly_masked_multiplication_laola(f_onehundrettwentyseven, f_seventytwo,
                                   f_fiftyfive);

  poly_masked_square(f_twohundretfiftyfour, f_onehundrettwentyseven);

  // affine transform
  add_const(res, res, 0x63);
  mul_const(tmp, f_twohundretfiftyfour, 0x05);
  sw_add(res, res, tmp);

  poly_masked_square(f_two, f_twohundretfiftyfour);
  mul_const(tmp, f_two, 0x09);
  sw_add(res, res, tmp);

  poly_masked_square(f_four, f_two);
  mul_const(tmp, f_four, 0xf9);
  sw_add(res, res, tmp);

  poly_masked_square(f_eight, f_four);
  mul_const(tmp, f_eight, 0x25);
  sw_add(res, res, tmp);

  poly_masked_square(f_sixteen, f_eight);
  mul_const(tmp, f_sixteen, 0xf4);
  sw_add(res, res, tmp);

  poly_masked_square(f_thirtytwo, f_sixteen);
  mul_const(tmp, f_thirtytwo, 0x01);
  sw_add(res, res, tmp);

  poly_masked_square(f_sixtyfour, f_thirtytwo);
  mul_const(tmp, f_sixtyfour, 0xb5);
  sw_add(res, res, tmp);

  poly_masked_square(f_onehundrettwentyeight, f_sixtyfour);
  mul_const(tmp, f_onehundrettwentyeight, 0x8f);
  sw_add(res, res, tmp);

#endif
}

#ifdef ENABLE_CYCLE_COUNT
void benchmark_components(share secret_sharing[NUM_SHARES])
{
  share secret_sharing2[NUM_SHARES] = {0};
  for (int i = 0; i < NUM_SHARES; i++)
  {
    secret_sharing2[i] = secret_sharing[i];
  }
  // rerandomize the second secret sharing
  ZENC(secret_sharing2, DEGREE, 0);
  share share_one = secret_sharing[0];
  share share_two = secret_sharing2[0];
  share share_res = 0;
  share res[NUM_SHARES] = {0};
  uint32_t ctr_pre = 0;
  uint32_t ctr_post = 0;

  ctr_pre = get_ctr();
  init_cycle_counter();
  ZENC(res, DEGREE, 0);
  send_cycle_count(get_elapsed_cycles());
  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);

  ctr_pre = get_ctr();
  init_cycle_counter();
  ZENC(res, CEIL_D_HALF, 0);
  send_cycle_count(get_elapsed_cycles());
  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);

  ctr_pre = get_ctr();
  init_cycle_counter();
  ZENC(res, FLOOR_D_HALF, 0);
  send_cycle_count(get_elapsed_cycles());
  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);

  ctr_pre = get_ctr();
  init_cycle_counter();
  SZENC(res);
  send_cycle_count(get_elapsed_cycles());
  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);

  share A_hat[NUM_SHARES][NUM_SHARES];
  compute_A_hat(A_hat, CEIL_D_HALF);

  ctr_pre = get_ctr();
  init_cycle_counter();
  split_red(A_hat, res, secret_sharing2, secret_sharing, CEIL_D_HALF);
  send_cycle_count(get_elapsed_cycles());
  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);

  compute_A_hat(A_hat, FLOOR_D_HALF);

  ctr_pre = get_ctr();
  init_cycle_counter();
  split_red(A_hat, res, secret_sharing2, secret_sharing, FLOOR_D_HALF);
  send_cycle_count(get_elapsed_cycles());
  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);

  ctr_pre = get_ctr();
  init_cycle_counter();
  poly_masked_multiplication_laola(res, secret_sharing, secret_sharing2);
  send_cycle_count(get_elapsed_cycles());
  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);

  ctr_pre = get_ctr();
  init_cycle_counter();
  poly_masked_sbox(res, secret_sharing);
  send_cycle_count(get_elapsed_cycles());

  ctr_post = get_ctr();
  send_cycle_count(ctr_post - ctr_pre);
}
#endif

/// @brief Compute the first-order S-box on a secret
/// @param secret the secret to be processed
/// @return the result of the S-box computation
void masked_sbox(share secret_sharing[NUM_SHARES])
{
  share result[NUM_SHARES] = {0};

#ifdef ENABLE_CYCLE_COUNT
  benchmark_components(secret_sharing);
#elif ENABLE_TRIGGERS
  trigger_high();
  poly_masked_sbox(result, secret_sharing);
  trigger_low();
#else
  poly_masked_sbox(result, secret_sharing);
  for (int i = 0; i < NUM_SHARES; i++)
  {
    secret_sharing[i] = result[i];
  }
#endif
}