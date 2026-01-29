// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "crt0.h"
#include "parameters.h"
#include "poly_masked_sbox.h"
#include "random_bytes.h"
#include "uart.h"
#include <stdbool.h>
#include <stdint.h>

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

bool test_sbox_exhaustive_non_packed(void)
{
    uint8_t expected_result = 0;
    share poly_masked_secrets[NUM_SHARES] = {0};
    share poly_masked_result[NUM_SHARES] = {0};
    uint32_t num_tests_performed = 0;
    uint32_t seed = 0x66303ECE;

    for (uint16_t secret_input_value = 0; secret_input_value <= UINT8_MAX;
         secret_input_value++)
    {
        init_rand(&seed);

        poly_sharing_enc(poly_masked_secrets, secret_input_value, NUM_SHARES,
                         DEGREE);
        poly_masked_sbox(poly_masked_result, poly_masked_secrets);
        uint8_t res = poly_sharing_dec(poly_masked_result);

        expected_result = aes_sbox[secret_input_value];
        if (res != expected_result)
        {
            print("Error, mismatching results in test_sbox_exhaustive_non_packed: "
                  "got: ");
            print_byte_hex(res);
            print(" vs. expected: ");
            print_byte_hex(expected_result);
            print("\n");
            return false;
        }
        num_tests_performed += 1;
    }
    print_uint(num_tests_performed);
    print(" test passed in test_sbox_exhaustive_non_packed\n");
    return (num_tests_performed > 0);
}

bool test_sbox_exhaustive(void)
{
    uint32_t expected_result;
    share poly_masked_secrets[NUM_SHARES];
    share poly_masked_result[NUM_SHARES];
    share unmasked_secrets[NUM_SECRETS_PER_ENCODING] = {0};
    share unmasked_results[NUM_SECRETS_PER_ENCODING] = {0};
    uint32_t num_tests_performed = 0;
    uint32_t seed = 0x66303ECE;

    for (uint32_t secret_input_value = 0; secret_input_value <= UINT8_MAX;
         secret_input_value++)
    {
        init_rand(&seed);
        unmasked_secrets[0] = (uint8_t)secret_input_value;
        for (int i = 1; i < NUM_SECRETS_PER_ENCODING; i++)
        {
            unmasked_secrets[i] = 0;
        }

        poly_packed_sharing_enc(poly_masked_secrets, unmasked_secrets);

        poly_masked_sbox(poly_masked_result, poly_masked_secrets);

        poly_packed_sharing_dec(unmasked_results, poly_masked_result);

        expected_result = aes_sbox[unmasked_secrets[0]];

        if ((uint8_t)unmasked_results[0] != (uint8_t)expected_result)
        {
            print("Error, mismatching results in test_sbox_exhaustive_packed: got: ");
            print_byte_hex(unmasked_results[0]);
            print(" vs. expected: ");
            print_byte_hex(expected_result);
            print("\n");
            return false;
        }
        num_tests_performed += 1;
    }
    print_uint(num_tests_performed);
    print(" test passed in test_sbox_exhaustive_packed\n");
    return (num_tests_performed > 0);
}

uint8_t gf8_multiply(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }
        uint8_t carry = a & 0x80;
        a <<= 1;
        if (carry)
        {
            a ^= 0x11b; // AES polynomial: x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p & 0xFF;
}

bool test_non_packed_interpolation_d_plus_one_shares(void)
{

    share shares[NUM_SHARES];

    for (uint8_t secret_value = 0; secret_value <= UINT8_MAX; secret_value++)
    {
        zero_randomness();
        reset_ctr();
        poly_sharing_enc(shares, secret_value, NUM_SHARES, DEGREE);
        uint8_t result = poly_sharing_dec(shares);
        if (result != secret_value)
        {
            print("Error, mismatching results in "
                  "test_non_packed_interpolation_d_plus_one_shares: got: ");
            print_uint(result);
            print(" vs. expected: ");
            print_uint(secret_value);
            print("\n");
            return false;
        }
    }
    print("test passed in test_non_packed_interpolation_d_plus_one_shares\n");
    return true;
}

bool test_multiplication_laola_exhaustive_non_packed(void)
{
    uint8_t expected_result = 0;
    share poly_masked_secret_A[NUM_SHARES] = {0};
    share poly_masked_secret_B[NUM_SHARES] = {0};
    share poly_masked_result[NUM_SHARES] = {0};
    uint8_t res = 0;
    uint32_t seed = 0x66303ECE;
    uint32_t num_tests_performed = 0;

    for (uint32_t secret_input_value_A = 0; secret_input_value_A <= UINT8_MAX;
         secret_input_value_A++)
    {

        for (uint32_t secret_input_value_B = 0; secret_input_value_B <= UINT8_MAX;
             secret_input_value_B++)
        {
            init_rand(&seed);

            poly_sharing_enc(poly_masked_secret_A, (uint8_t)secret_input_value_A,
                             NUM_SHARES, DEGREE);
            poly_sharing_enc(poly_masked_secret_B, (uint8_t)secret_input_value_B,
                             NUM_SHARES, DEGREE);

            poly_masked_multiplication_laola(poly_masked_result, poly_masked_secret_A,
                                             poly_masked_secret_B);

            res = poly_sharing_dec(poly_masked_result);

            expected_result = gf8_multiply((uint8_t)secret_input_value_A,
                                           (uint8_t)secret_input_value_B);
            if (res != expected_result)
            {
                print("Error, mismatching results: got: ");
                print_uint(res);
                print(" vs. expected: ");
                print_uint(expected_result);
                print(" in test_multiplication_laola_exhaustive_non_packed(");
                print_uint(secret_input_value_A);
                print(", ");
                print_uint(secret_input_value_B);
                print(")");
                print("\n");

                return false;
            }
            num_tests_performed += 1;
        }
    }

    print_uint(num_tests_performed);
    print(" test passed in test_multiplication_laola_exhaustive_non_packed\n");
    return (num_tests_performed > 0);
}

bool test_multiplication_laola_exhaustive(void)
{
    uint32_t expected_result = 0;
    share poly_masked_secret_A[NUM_SHARES] = {0};
    share poly_masked_secret_B[NUM_SHARES] = {0};
    share poly_masked_result[NUM_SHARES] = {0};
    share secrets_A[NUM_SECRETS_PER_ENCODING] = {0};
    share secrets_B[NUM_SECRETS_PER_ENCODING] = {0};
    share unmasked_results[NUM_SECRETS_PER_ENCODING] = {0};

    uint32_t seed = 0x66303ECE;
    uint32_t num_tests_performed = 0;

    for (uint32_t secret_input_value_A = 0; secret_input_value_A <= UINT8_MAX;
         secret_input_value_A++)
    {

        for (uint32_t secret_input_value_B = 0; secret_input_value_B <= UINT8_MAX;
             secret_input_value_B++)
        {
            init_rand(&seed);

            secrets_A[0] = (uint8_t)secret_input_value_A;
            secrets_B[0] = (uint8_t)secret_input_value_B;
            for (int i = 1; i < NUM_SECRETS_PER_ENCODING; i++)
            {
                secrets_A[i] = 0;
                secrets_B[i] = 0;
            }

            poly_packed_sharing_enc(poly_masked_secret_A, secrets_A);
            poly_packed_sharing_enc(poly_masked_secret_B, secrets_B);

            poly_masked_multiplication_laola(poly_masked_result, poly_masked_secret_A,
                                             poly_masked_secret_B);

            poly_packed_sharing_dec(unmasked_results, poly_masked_result);

            expected_result = gf8_multiply((uint8_t)secret_input_value_A,
                                           (uint8_t)secret_input_value_B);

            if (unmasked_results[0] != expected_result)
            {
                print("Error, mismatching results: got: ");
                print_uint(unmasked_results[0]);
                print(" vs. expected: ");
                print_uint(expected_result);
                print(" in test_multiplication_laola_exhaustive(");
                print_uint(secret_input_value_A);
                print(", ");
                print_uint(secret_input_value_B);
                print(")");
                print("\n");

                return false;
            }
            num_tests_performed += 1;
        }
    }

    print_uint(num_tests_performed);
    print(" test passed in test_multiplication_laola_exhaustive\n");
    return (num_tests_performed > 0);
}

bool test_square_exhaustive(void)
{
    uint32_t expected_result = 0;
    share poly_masked_secret[NUM_SHARES];
    share poly_masked_zero[NUM_SHARES];
    share poly_masked_result[NUM_SHARES];
    share secrets[NUM_SECRETS_PER_ENCODING] = {0};
    share unmasked_results[NUM_SECRETS_PER_ENCODING];
    bool ran_some_tests = false;
    bool success = true;

    uint32_t seed = 0x66303ECE;
    uint32_t num_tests_completed = 0;

    for (uint32_t test_round = 0; test_round <= UINT8_MAX; test_round++)
    {
        init_rand(&seed);

        for (int i = 1; i < NUM_SECRETS_PER_ENCODING; i++)
        {
            secrets[i] = get_random_byte();
        }

        poly_packed_sharing_enc(poly_masked_secret, secrets);
        optZEnc(poly_masked_zero, DEGREE, 0);
        sw_add(poly_masked_secret, poly_masked_secret, poly_masked_zero);

        poly_masked_square(poly_masked_result, poly_masked_secret);

        poly_packed_sharing_dec(unmasked_results, poly_masked_result);

        // check the results
        for (int i = 0; i < NUM_SECRETS_PER_ENCODING; i++)
        {
            expected_result = gf8_multiply((uint8_t)secrets[i], (uint8_t)secrets[i]);
            uint32_t permuted_index = secrets_permutation_map[i];
            if (unmasked_results[permuted_index] != expected_result)
            {
                print("Error, mismatching results: ");
                print(" in index i=");
                print_uint(permuted_index);
                print(" got:");
                print_uint(unmasked_results[permuted_index]);
                print(" vs. expected: ");
                print_uint(expected_result);
                print(" in poly_masked_square(");
                print_uint(secrets[i]);
                print(")");
                print("\n");

                success = false;
            }
            ran_some_tests = true;
        }
        if (!success)
        {
            return false;
        }
        num_tests_completed += 1;
    }

    print_uint(num_tests_completed);
    print(" test passed in square_exhaustive\n");
    return ran_some_tests & success;
}

bool test_packed_secret_sharing(void)
{
    share secrets[NUM_SECRETS_PER_ENCODING] = {0};
    share encoded_secrets[NUM_SHARES];
    share encoded_zero[NUM_SHARES];
    share reconstruct_secrets[NUM_SECRETS_PER_ENCODING];

    uint32_t seed = 0x12345ECD;

    for (int j = 0; j < UINT8_MAX; j++)
    {
        init_rand(&seed);

        // generate `NUM_SECRETS_PER_ENCODING` secrets to encode in one polynomial
        for (int i = 0; i < NUM_SECRETS_PER_ENCODING; i++)
        {
            secrets[i] = get_random_byte();
        }

        poly_packed_sharing_enc(encoded_secrets, secrets);

        // perform a dummy operation
        optZEnc(encoded_zero, DEGREE, 0);
        sw_add(encoded_secrets, encoded_secrets, encoded_zero);

        poly_packed_sharing_dec(reconstruct_secrets, encoded_secrets);

        for (int i = 0; i < NUM_SECRETS_PER_ENCODING; i++)
        {
            if (secrets[i] != reconstruct_secrets[i])
            {
                return false;
            }
        }
    }
    return true;
}

bool test_opt_Zenc(void)
{

    bool passed = false;
    uint32_t expected_result = 0;
    share secrets[NUM_SECRETS_PER_ENCODING] = {0};
    share encoded_secrets[NUM_SHARES] = {0};
    share encoded_zero[NUM_SHARES] = {0};
    share refreshed_encoded_secrets[NUM_SHARES] = {0};
    share squared_refreshed_encoded_secrets[NUM_SHARES] = {0};
    share squared_refreshed_unmasked_secrets[NUM_SECRETS_PER_ENCODING] = {0};

    uint32_t seed = 0x12345ECD;
    uint32_t num_tests_completed = 0;
    uint8_t d = DEGREE;
    // for (int d = 1; d < DEGREE + 1; d++) {
    for (uint8_t o = 0; o <= DEGREE - NUM_SECRETS_PER_ENCODING; o++)
    {
        for (int n = 0; n <= UINT8_MAX * 4; n++)
        {
            passed = true;
            // uint32_t test_seed = seed ^ num_tests_completed;
            // init_rand(&test_seed);
            init_rand(&seed);

            memset(encoded_zero, -1, NUM_SHARES * sizeof(share));
            memset(squared_refreshed_unmasked_secrets, -1,
                   NUM_SECRETS_PER_ENCODING * sizeof(share));
            // generate `NUM_SECRETS_PER_ENCODING` secrets to encode in one
            // polynomial

            for (int i = 0; i < NUM_SECRETS_PER_ENCODING; i++)
            {
                secrets[i] = get_random_byte();
            }

            poly_packed_sharing_enc(encoded_secrets, secrets);
            optZEnc(encoded_zero, d, o);

            sw_add(refreshed_encoded_secrets, encoded_secrets, encoded_zero);

#if OPT_FROBENIUS == 1
            // HARDER TEST
            poly_masked_square(squared_refreshed_encoded_secrets,
                               refreshed_encoded_secrets);
#else
            for (uint8_t i = 0; i < NUM_SHARES; i++)
            {
                squared_refreshed_encoded_secrets[i] = refreshed_encoded_secrets[i];
            }
#endif
            memset(encoded_zero, 0, NUM_SHARES * sizeof(share));
            optZEnc(encoded_zero, d, o);
            sw_add(refreshed_encoded_secrets, squared_refreshed_encoded_secrets,
                   encoded_zero);
            poly_packed_sharing_dec(squared_refreshed_unmasked_secrets,
                                    squared_refreshed_encoded_secrets);

            for (int i = 0; i < NUM_SECRETS_PER_ENCODING; i++)
            {
                uint8_t permuted_index = i;
#if OPT_FROBENIUS == 1
                // HARDER TEST
                expected_result =
                    gf8_multiply((uint8_t)secrets[i], (uint8_t)secrets[i]);
                permuted_index = secrets_permutation_map[i];
#else
                expected_result = secrets[i];
#endif
                if (squared_refreshed_unmasked_secrets[permuted_index] !=
                    expected_result)
                {
                    print("Testing optZEnc failed for o=");
                    print_uint(o);
                    print(", d=");
                    print_uint(d);
                    print(" got reconstructed value: ");
                    print_uint(squared_refreshed_unmasked_secrets[permuted_index]);
                    print(" vs. expected value: ");
                    print_uint(expected_result);
                    print("\n");
                    passed = false;
                }
            }
            if (!passed)
            {
                print("Testing optZEnc failed in test #");
                print_uint(num_tests_completed + 1);
                print(".\n");
                return false;
            }
            num_tests_completed += 1;
        }
    }
    //}
    print_uint(num_tests_completed);
    print(" test passed in test_opt_Zenc\n");
    return passed;
}

bool test_sw_mul(void)
{
    // take random sharings

    share a[NUM_SHARES];
    share b[NUM_SHARES];
    share c[NUM_SHARES];
    uint32_t num_tests_completed = 0;
    uint32_t seed = 0x12345ECD;
    for (int i = 0; i < 10000; i++)
    {
        init_rand(&seed);
        for (int n = 0; n < NUM_SHARES; n++)
        {
            a[n] = get_random_byte();
            b[n] = get_random_byte();
            c[n] = get_random_byte();
        }
        sw_mul(c, a, b);
        for (int n = 0; n < NUM_SHARES; n++)
        {
            if (c[n] != gf8_multiply(a[n], b[n]))
            {
                print("num tests completed: ");
                print_uint(num_tests_completed);
                print("\n");
                print("Error, mismatching results: got: ");
                print_uint(c[n]);
                print(" vs. expected: ");
                print_uint(gf8_multiply(a[n], b[n]));
                print(" in test_sw_mul(");
                print_uint(a[n]);
                print(", ");
                print_uint(b[n]);
                print(")");
                print("\n");
                return false;
            }
        }
        num_tests_completed += 1;
    }
    print_uint(num_tests_completed);
    print(" tests passed in test_sw_mult\n");
    return true;
}

bool test_opt_sZenc(void)
{
    bool passed = false;
    uint32_t expected_result = 0;
    share secrets[NUM_SECRETS_PER_ENCODING] = {0};
    share encoded_secrets[NUM_SHARES] = {0};
    share encoded_zero[NUM_SHARES] = {0};
    share refreshed_encoded_secrets[NUM_SHARES] = {0};
    share squared_refreshed_encoded_secrets[NUM_SHARES] = {0};
    share squared_refreshed_unmasked_secrets[NUM_SECRETS_PER_ENCODING];

    uint32_t seed = 0x12345ECD;
    uint32_t num_tests_completed = 0;

    for (int n = 0; n <= UINT8_MAX * 4; n++)
    {
        passed = true;
        init_rand(&seed);

        memset(encoded_zero, -1, NUM_SHARES * sizeof(share));
        memset(squared_refreshed_unmasked_secrets, -1,
               NUM_SECRETS_PER_ENCODING * sizeof(share));
        // generate `NUM_SECRETS_PER_ENCODING` secrets to encode in one polynomial
        for (int i = 0; i < NUM_SECRETS_PER_ENCODING; i++)
        {
            secrets[i] = get_random_byte();
        }

        poly_packed_sharing_enc(encoded_secrets, secrets);
        optsZEnc(encoded_zero);
        sw_add(refreshed_encoded_secrets, encoded_secrets, encoded_zero);

#if OPT_FROBENIUS == 1
        // HARDER TEST
        poly_masked_square(squared_refreshed_encoded_secrets,
                           refreshed_encoded_secrets);
#else

        for (uint8_t i = 0; i < NUM_SHARES; i++)
        {
            // removing this cast breaks things
            squared_refreshed_encoded_secrets[i] = refreshed_encoded_secrets[i];
        }
#endif

        optsZEnc(encoded_zero);

        sw_add(squared_refreshed_encoded_secrets, squared_refreshed_encoded_secrets,
               encoded_zero);

        poly_packed_sharing_dec(squared_refreshed_unmasked_secrets,
                                squared_refreshed_encoded_secrets);

        for (int i = 0; i < NUM_SECRETS_PER_ENCODING; i++)
        {
            uint8_t permuted_index = i;
#if OPT_FROBENIUS == 1
            // HARDER TEST
            expected_result = gf8_multiply((uint8_t)secrets[i], (uint8_t)secrets[i]);
            permuted_index = secrets_permutation_map[i];
#else
            expected_result = secrets[i];
#endif

            if (squared_refreshed_unmasked_secrets[permuted_index] !=
                expected_result)
            {
                print("Testing optsZEnc failed got reconstructed value: ");
                print_uint(squared_refreshed_unmasked_secrets[permuted_index]);
                print(" vs. expected value: ");
                print_uint(expected_result);
                print("\n");
                passed = false;
            }
        }
        if (!passed)
        {
            print("Testing optsZEnc failed in test #");
            print_uint(num_tests_completed + 1);
            print(".\n");
            return false;
        }
        num_tests_completed += 1;
    }
    print_uint(num_tests_completed);
    print(" test passed in test_opt_sZenc\n");
    return passed;
}

bool test_lambda_hat_lut(void)
{
    for (int i = 0; i < NUM_SHARES; i++)
    {
        for (int j = 0; j < NUM_SHARES; j++)
        {
            if (lambda_hat[i][j] != lambda_hat_non_packed(i, j))
            {
                print("Error, mismatching results: got: ");
                print_uint(lambda_hat[i][j]);
                print(" vs. expected: ");
                print_uint(lambda_hat_non_packed(i, j));
                print(" in test_lambda_hat_lut(");
                print_uint(i);
                print(", ");
                print_uint(j);
                print(")");
                print("\n");
                return false;
            }
        }
    }
    print("All tests passed in test_lambda_hat_lut\n");
    return true;
}

bool test_p_refresh_correctness_non_packed(void)
{
    share encoded_secret[NUM_SHARES];

    uint32_t seed = 0x12345ECD;

    for (uint8_t secret = 0; secret < UINT8_MAX; secret++)
    {
        init_rand(&seed);
        poly_sharing_enc(encoded_secret, secret, NUM_SHARES, DEGREE);

        p_refresh(encoded_secret);
        if (fault_detected(encoded_secret))
        {
            print("Error, fault detected in test_p_refresh_correctness_non_packed\n");
            return false;
        }
        share dec_secret;
        dec_secret = poly_sharing_dec(encoded_secret);
        if (secret != dec_secret)
        {
            print("Error, mismatching results in "
                  "test_p_refresh_correctness_non_packed: "
                  "got: ");
            print_uint(dec_secret);
            print(" vs. expected: ");
            print_uint(secret);
            print("\n");
            return false;
        }
    }
    print("All tests passed in test_p_refresh_correctness_non_packed\n");
    return true;
}

bool test_correctness(void)
{
    bool tests_passed = true;
    // tests_passed &= test_lambda_hat_lut();
    tests_passed &= test_sw_mul();
    tests_passed &= test_opt_Zenc();
    tests_passed &= test_opt_sZenc();
    tests_passed &= test_packed_secret_sharing();
    tests_passed &= test_p_refresh_correctness_non_packed();
#if OPT_FROBENIUS == 1
    tests_passed &= test_square_exhaustive();
#endif
    tests_passed &= test_multiplication_laola_exhaustive_non_packed();
    tests_passed &= test_multiplication_laola_exhaustive();
    tests_passed &= test_sbox_exhaustive_non_packed();
    tests_passed &= test_sbox_exhaustive();
    return tests_passed;
}