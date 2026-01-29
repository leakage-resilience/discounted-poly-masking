#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck

# Loop through all combinations of x, y, and z from 0 to 4
for x in {1..3}; do
  for y in {0..3}; do
    # Call the Sage script with the current combination of parameters
    sage generate_python_variables.sage $x $y 1
  done
done