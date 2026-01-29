// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "crt0.h"
#include "parameters.h"
#include "poly_masked_sbox.h"
#include "random_bytes.h"
#include "uart.h"
#include <stdbool.h>
#include <stdint.h>

#ifndef PROCESS_ID
#define PROCESS_ID 0
#endif

#ifndef FAULT_LAOLA
#define FAULT_LAOLA 0
#endif

void main(void)
{
  bool tests_passed = true;

  print("Running tests for:\n");
  print("NUM_SHARES = ");
  print_uint(NUM_SHARES);
  print("\n");
  print("DEGREE = ");
  print_uint(DEGREE);
  print("\n");
  print("FAULTS = ");
  print_uint(FAULTS);
  print("\n");
  print("NUM_SECRETS_PER_ENCODING = ");
  print_uint(NUM_SECRETS_PER_ENCODING);
  print("\n");
  print("OPT_FROBENIUS = ");
  print_uint(OPT_FROBENIUS);
  print("\n");
  print("OPT_ZENC = ");
  print_uint(OPT_ZENC);
  print("\n\n\n");

  tests_passed &= test_correctness();

#if FAULTS > 0 && NUM_INJECTED_FAULTS > 0
#if FAULT_LAOLA == 1
  tests_passed &= run_laola_fault_injection();
#endif
#endif

  if (tests_passed)
  {
    print("\n\n\nAll tests passed.\n");
    qemu_exit(EXIT_SUCCESS);
  }
  else
  {
    print("\n\n\nSome tests failed.\n");
    qemu_exit(EXIT_FAILURE);
  }
}