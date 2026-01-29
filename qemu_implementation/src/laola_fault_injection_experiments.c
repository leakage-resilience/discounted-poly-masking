// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "crt0.h"
#include "parameters.h"
#include "poly_masked_sbox.h"
#include "random_bytes.h"
#include "uart.h"
#include <stdbool.h>
#include <stdint.h>

#ifndef NUM_FAULT_EXPERIMENTS
#define NUM_FAULT_EXPERIMENTS 100000
#endif

#if NUM_INJECTED_FAULTS > 0 && FAULT_LAOLA

bool test_fault_detection_mechanism(void)
{
    share poly_masked_secret_A[NUM_SHARES] = {0};
    share faulted_masked_secret_A[NUM_SHARES] = {0};
    share poly_masked_secret_B[NUM_SHARES] = {0};
    share poly_masked_result[NUM_SHARES] = {0};
    share faulted_masked_result[NUM_SHARES] = {0};
    share res = 0;
    share faulted_res = 0;
    uint32_t seed = 0x66303ECE;
    uint32_t num_tests_performed = 0;
    uint32_t num_faults_detected = 0;
    uint32_t num_faults_undetected = 0;
    uint8_t fault_value = 0;
    uint32_t num_impactful_undetected_faults = 0;
    uint32_t num_unimpactful_undetected_faults = 0;
    for (uint32_t secret_input_value_A = 0; secret_input_value_A <= UINT8_MAX;
         secret_input_value_A++)
    {

        for (uint32_t secret_input_value_B = 0; secret_input_value_B <= UINT8_MAX;
             secret_input_value_B++)
        {
            init_rand(&seed);
            bool fault_happened = false;

            poly_sharing_enc(poly_masked_secret_A, (uint8_t)secret_input_value_A,
                             NUM_SHARES, DEGREE);
            poly_sharing_enc(poly_masked_secret_B, (uint8_t)secret_input_value_B,
                             NUM_SHARES, DEGREE);

            for (uint8_t i = 0; i < NUM_SHARES; i++)
            {
                faulted_masked_secret_A[i] = poly_masked_secret_A[i];
            }

            // fault the input share 0 of the second polynomial
            fault_value = get_random_byte();
            // make sure the fault is effective
            while (fault_value == faulted_masked_secret_A[0])
            {
                fault_value = get_random_byte();
            }
            faulted_masked_secret_A[0] = fault_value;
            poly_masked_multiplication_laola(poly_masked_result, poly_masked_secret_A,
                                             poly_masked_secret_B);
            poly_masked_multiplication_laola(
                faulted_masked_result, faulted_masked_secret_A, poly_masked_secret_B);

            fault_happened = fault_detected(faulted_masked_result);
            if (fault_happened)
            {
                num_faults_detected += 1;
            }
            else
            {
                // compare if the fault actually changed the result
                res = poly_sharing_dec(poly_masked_result);
                faulted_res = poly_sharing_dec(faulted_masked_result);
                if (res != faulted_res)
                {
                    num_impactful_undetected_faults += 1;
                }
                else
                {
                    num_unimpactful_undetected_faults += 1;
                }
                num_faults_undetected += 1;
            }
            num_tests_performed += 1;
        }
    }

    print_uint(num_faults_detected);
    print(" detected faults and ");
    print_uint(num_faults_undetected);
    print(" undetected faults using higher order coefficient evaluation\n");
    print_uint(num_impactful_undetected_faults);
    print(" impactful faults undetected ");
    print_uint(num_unimpactful_undetected_faults);
    print(" unimpactful faults undetected\n");
    return (num_faults_detected > 0);
}

uint8_t inject_set_value_fault_with_inputs(
    uint32_t *seed, uint32_t fault_indices[NUM_INJECTED_FAULTS],
    uint8_t fault_values[NUM_INJECTED_FAULTS], uint8_t secret_a,
    uint8_t secret_b, uint32_t max_fault_index)
{
    share poly_masked_secret_A[NUM_SHARES] = {0};
    share poly_masked_secret_B[NUM_SHARES] = {0};
    share poly_masked_result[NUM_SHARES] = {0};
    share faulted_masked_result[NUM_SHARES] = {0};
    uint8_t fault_values_shares[2 * NUM_SHARES] = {0};

    init_rand(seed);
    poly_sharing_enc(poly_masked_secret_A, secret_a, NUM_SHARES, DEGREE);
    poly_sharing_enc(poly_masked_secret_B, secret_b, NUM_SHARES, DEGREE);
    uint32_t seed1 = *seed;

    init_rand(&seed1);

    poly_masked_multiplication_laola(poly_masked_result, poly_masked_secret_A,
                                     poly_masked_secret_B);

    enable_faults();

    // TODO: use back part of 2*NUM_SHARES to not have to subtract 2*NUM_SHARES
    // check if any of the fault indices are in the input shares
    for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
    {
        if (fault_indices[i] < 2 * NUM_SHARES)
        {
            // if so, we need to inject the fault in the i-th input share
            fault_values_shares[fault_indices[i]] = fault_values[i];
            // now we ensure that this is not used as an internal fault by setting its
            // index to the max_field_op + 1, so that it is disregarded
            fault_indices[i] = max_fault_index + 1;
        }
        // if the fault index is not a share we need to subtract 2 * NUM_SHARES from
        // its index to ensure that the correct field operations are targeted (since
        // faulting in the algorithms starts at index 0)
        // the values remain unchanged since they are set later
        else
        {
            fault_indices[i] -= 2 * NUM_SHARES;
        }
    }

    // set the faults in the input shares
    for (uint8_t i = 0; i < NUM_SHARES; i++)
    {
        if (fault_values_shares[i] != 0)
        {
            poly_masked_secret_A[i] = fault_values_shares[i];
        }
        if (fault_values_shares[i + NUM_SHARES] != 0)
        {
            poly_masked_secret_B[i] = fault_values_shares[i + NUM_SHARES];
        }
    }

    //  set the remaining faults for the field operations
    set_fault_indices(fault_indices);
    for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
    {
        set_fault_value(fault_indices[i], fault_values[i]);
    }
    init_rand(seed);
    poly_masked_multiplication_laola(faulted_masked_result, poly_masked_secret_A,
                                     poly_masked_secret_B);
    disable_faults();
    clear_fault_buffers();
    bool fault_was_detected = fault_detected(faulted_masked_result);
    if (fault_was_detected)
    {
        // cool, fault was detected the result was an invalid encoding
        return 0;
    }
    else
    {
        // this means that despite the fault we have a valid encoding
        // we now need to check if the fault actually resulted in a different
        // encoding than the unfaulted computation
            if (poly_sharing_dec(faulted_masked_result) !=
                poly_sharing_dec(poly_masked_result))
            {
                //  if an effective fault occured (decoded secrets are different) we
                //  return 1
                return 1;
            }
        
        // if the fault was both undetected and ineffective we return 2
        return 2;
    }
}

uint32_t possible_fault_positions(void)
{
    // run laola mult once to determine the number of field operations
    // randomness doesnt really matter here since it is precalculated and the
    // implementation is constant time
    share poly_masked_secret_A[NUM_SHARES] = {0};
    share poly_masked_secret_B[NUM_SHARES] = {0};
    share poly_masked_result[NUM_SHARES] = {0};

    poly_sharing_enc(poly_masked_secret_A, 0, NUM_SHARES, DEGREE);
    poly_sharing_enc(poly_masked_secret_B, 0, NUM_SHARES, DEGREE);
    enable_faults();
    poly_masked_multiplication_laola(poly_masked_result, poly_masked_secret_A,
                                     poly_masked_secret_B);
    disable_faults();
    print("Number of field operations: ");
    print_uint(get_num_field_ops());
    print("\n");
    return get_num_field_ops();
}

/// perform additive fault injection on the laola multiplication
/// return if all faults were either detected or undetetected + effective or
/// undetected + ineffective
bool set_value_fault_injection_with_input_shares(void)
{

    uint32_t seed = 0x66303ECE + DEGREE + FAULTS + PROCESS_ID;
    uint32_t num_faults_detected = 0;
    uint32_t num_faults_undetected = 0;
    uint32_t num_faults_undetected_effective = 0;
    uint32_t num_faults_undetected_ineffective = 0;
    uint32_t num_tests_performed = 0;
    uint32_t max_fault_index = possible_fault_positions();
    // we also want to allow injecting faults into the input shares
    uint32_t max_fault_index_with_shares = max_fault_index + 2 * NUM_SHARES;

    // because we are in qemu we print to terminal and build a csv file from this
    // later by filtering the output
    print("###PRINTING CSV###\n");
    print("rndseed,secret_a,secret_b,");
    for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
    {
        print("fault_index_");
        print_uint(i);
        print(",");
    }
    for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
    {
        print("fault_value_");
        print_uint(i);
        print(",");
    }
    print("fault_result\n");
    init_rand(&seed);
    for (; num_tests_performed < NUM_FAULT_EXPERIMENTS; num_tests_performed++)
    {

        uint8_t fault_values[NUM_INJECTED_FAULTS] = {0};
        uint32_t fault_indices[NUM_INJECTED_FAULTS] = {0};

        uint8_t secret_a = get_random_byte();
        uint8_t secret_b = get_random_byte();
        uint8_t fault_result = 0;

#if SET_ZERO_FAULTS == 0
        // only if random faults are used, meaning SET_ZERO_FAULTS == 0 we use
        // random values, else we use the already initialized 0 values
        for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
        {
            fault_values[i] = get_random_byte();
        }
#endif

        generate_random_fault_indices(&seed, fault_indices,
                                      max_fault_index_with_shares);

        fault_result =
            inject_set_value_fault_with_inputs(&seed, fault_indices, fault_values,
                                               secret_a, secret_b, max_fault_index);

        // print to terminal here and generate a csv file from this in a later
        print_uint(seed);
        print(",");
        print_uint(secret_a);
        print(",");
        print_uint(secret_b);
        print(",");
        for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
        {
            print_uint(fault_indices[i]);
            print(",");
        }
        for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
        {
            print_uint(fault_values[i]);
            print(",");
        }
        print_uint(fault_result);
        print("\n");

        // afterwards
        if (fault_result == 0)
        {
            num_faults_detected += 1;
        }
        else if (fault_result == 1)
        {
            num_faults_undetected_effective += 1;
            num_faults_undetected += 1;
        }
        else if (fault_result == 2)
        {
            num_faults_undetected_ineffective += 1;
            num_faults_undetected += 1;
        }
        else
        {
            print("Error, invalid fault result: ");
            print_uint(fault_result);
            print("\n");
            return false;
        }
    }
    print("###END PRINTING CSV###\n");

    print_uint(num_faults_detected);
    print(" detected faults and ");
    print_uint(num_faults_undetected);
    print(" undetected faults.\n");
    print("Among the undetected faults there were ");
    print_uint(num_faults_undetected_ineffective);
    print(" undetected ineffective faults and ");
    print_uint(num_faults_undetected_effective);
    print(" undetected effective faults for additive fault injection with random "
          "secrets, random additive values and random fault positions.\n");

    return 1;
}

/// perform additive fault injection on the laola multiplication
/// return if all faults were either detected or undetetected + effective or
/// undetected + ineffective
bool adaptive_fault_injection(void)
{
    uint32_t seed = 0x66303ECE + DEGREE + FAULTS;
    uint32_t num_faults_detected = 0;
    uint32_t num_faults_undetected = 0;
    uint32_t num_faults_undetected_effective = 0;
    uint32_t num_faults_undetected_ineffective = 0;
    uint32_t num_tests_performed = 0;
    uint32_t max_fault_index = possible_fault_positions();
    // we also want to allow injecting faults into the input shares
    uint32_t max_fault_index_with_shares = max_fault_index + 2 * NUM_SHARES;

    // because we are in qemu we print to terminal and build a csv file from this
    // later by filtering the output
    print("###PRINTING CSV###\n");
    print("rndseed,secret_a,secret_b,");
    for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
    {
        print("fault_index_");
        print_uint(i);
        print(",");
    }
    for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
    {
        print("fault_value_");
        print_uint(i);
        print(",");
    }
    print("fault_result\n");
    init_rand(&seed);
    for (; num_tests_performed < NUM_FAULT_EXPERIMENTS; num_tests_performed++)
    {

        uint8_t fault_values[NUM_INJECTED_FAULTS] = {0};
        uint32_t fault_indices[NUM_INJECTED_FAULTS] = {0};

        uint8_t secret_a = get_random_byte();
        uint8_t secret_b = get_random_byte();
        uint8_t fault_result = 0;

#if SET_ZERO_FAULTS == 0
        // only if random faults are used, meaning SET_ZERO_FAULTS == 0 we use
        // random values, else we use the already initialized 0 values
        for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
        {
            fault_values[i] = get_random_byte();
        }
#endif

        generate_random_fault_indices(&seed, fault_indices,
                                      max_fault_index_with_shares);

        fault_result =
            inject_set_value_fault_with_inputs(&seed, fault_indices, fault_values,
                                               secret_a, secret_b, max_fault_index);
        // print to terminal here and generate a csv file from this in a later
        print_uint(seed);
        print(",");
        print_uint(secret_a);
        print(",");
        print_uint(secret_b);
        print(",");
        for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
        {
            print_uint(fault_indices[i]);
            print(",");
        }
        for (uint8_t i = 0; i < NUM_INJECTED_FAULTS; i++)
        {
            print_uint(fault_values[i]);
            print(",");
        }
        print_uint(fault_result);
        print("\n");

        if (fault_result == 0)
        {
            num_faults_detected += 1;
        }
        else if (fault_result == 1)
        {
            num_faults_undetected_effective += 1;
            num_faults_undetected += 1;
        }
        else if (fault_result == 2)
        {
            num_faults_undetected_ineffective += 1;
            num_faults_undetected += 1;
        }
        else
        {
            print("Error, invalid fault result: ");
            print_uint(fault_result);
            print("\n");
            return false;
        }

        uint32_t num_adaptive_faults =
            fault_result == 1 && num_tests_performed + 1000 < NUM_FAULT_EXPERIMENTS
                ? 1000
                : 0;
        uint32_t end_tests = num_tests_performed + 1 + num_adaptive_faults;
        for (; num_tests_performed < end_tests; num_tests_performed++)
        {
            // if we have an effective fault we aim to explore if we can get more
            // effective faults using, the same secrets, fault values and fault
            // indices
            fault_result = inject_set_value_fault_with_inputs(
                &seed, fault_indices, fault_values, secret_a, secret_b,
                max_fault_index);

            if (fault_result == 0)
            {
                num_faults_detected += 1;
            }
            else if (fault_result == 1)
            {
                num_faults_undetected_effective += 1;
                num_faults_undetected += 1;
            }
            else if (fault_result == 2)
            {
                num_faults_undetected_ineffective += 1;
                num_faults_undetected += 1;
            }
            else
            {
                print("Error, invalid fault result: ");
                print_uint(fault_result);
                print("\n");
                return false;
            }
        }
    }
    print("###END PRINTING CSV###\n");

    print_uint(num_faults_detected);
    print(" detected faults and ");
    print_uint(num_faults_undetected);
    print(" undetected faults.\n");
    print("Among the undetected faults there were ");
    print_uint(num_faults_undetected_ineffective);
    print(" undetected ineffective faults and ");
    print_uint(num_faults_undetected_effective);
    print(" undetected effective faults for additive fault injection with random "
          "secrets, random additive values and random fault positions.\n");

    return 1;
}

bool run_laola_fault_injection(void)
{
    bool tests_passed = true;
    tests_passed &= test_fault_detection_mechanism();
    tests_passed &= set_value_fault_injection_with_input_shares();
    // tests_passed &= adaptive_fault_injection();
    return tests_passed;
}

#endif