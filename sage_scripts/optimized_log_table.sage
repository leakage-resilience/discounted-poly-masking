# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck

# Define the finite field GF(2^8) using the AES irreducible polynomial
F = GF(2^8, name='a', modulus=x^8 + x^4 + x^3 + x + 1)

# Get the primitive element of the field (the generator)
g = F.fetch_int(3)

# Opitimized log and antilog tables based poly multiplication based on https://eprint.iacr.org/2023/375.pdf
# Initialize log and antilog tables with the required sizes
log_table = [0] * 256
# Antilog table should have length 2^(k+2) - 5, where k is the degree of the field
antilog_table = [0] * (2**(F.degree()+2)-5)  

# Fill the antilog table for the field elements
for i in range(((2**(F.degree()+1)-3))):
    antilog_table[i] = (g**i).integer_representation()

# Set log[0] to a 2^(k+1) - 3, which exceeds the range of any addition of two non zero log_table entries, therefore leading to antilog[log_table[x] + log_table[y]] = 0 iff x = 0 or y = 0
log_table[0] = 2**(F.degree()+1) - 3

# Fill the log table
for i in range(1, 256):
    log_table[(g**(i - 1)).integer_representation()] = i - 1

# Print C code for log and antilog tables in decimal format
print("/* Log table */")
print(" __attribute__((section(\".data\"))) uint16_t log_table[256] = {")  # Use uint16_t to accommodate the high value for log[0]
for i in range(256):
    if i % 16 == 0:
        print("\n   ", end="")
    print(f"{log_table[i]}, ", end="")
print("\n};")

print("\n/* Antilog table */")
print(f" __attribute__((section(\".data\"))) uint8_t antilog_table[{(2**(F.degree()+2)-5)}] = {{") 
for i in range(((2**(F.degree()+2)-5))):
    if i % 16 == 0:
        print("\n   ", end="")
    print(f"{antilog_table[i]}, ", end="")
print("\n};")


def test_log_antilog_tables(log_table, antilog_table):
    """
    Test the correctness of the log and antilog tables.
    """
    assert len(log_table) == 256, "Log table must have length 256."
    assert len(antilog_table) == (2**(F.degree()+2)-5), "Antilog table must have length 1019."

    # Test 1: Logarithm and Antilogarithm Consistency
    for i in range(1, 256):  # Exclude 0 because log(0) is undefined
        x = antilog_table[log_table[i]]
        assert x == i, f"Failed: antilog(log({i})) = {x}, expected {i}"

    print("Test 1 passed: log and antilog are consistent.")

    # Test 2: Multiplicative Property
    for x in range(1, 256):
        for y in range(1, 256):
            log_x = log_table[x]
            log_y = log_table[y]
            log_product = log_x + log_y
            product = antilog_table[log_product] if log_product < 255 else antilog_table[log_product - 255]
            expected_product = (F.fetch_int(x) * F.fetch_int(y))
            assert product == expected_product.integer_representation(), (
                f"Failed: {x} * {y} = {product}, expected {expected_product.integer_representation()} "
                f"(log_x={log_x}, log_y={log_y}, log_product={log_product})"
            )

    print("Test 2 passed: Multiplication in GF(2^8) is consistent.")

    # Test 3: Verify Zero Multiplication
    for x in range(1, 256):
        product = antilog_table[log_table[0] + log_table[x]]
        assert product == 0, f"Failed: 0 * {x} = {product}, expected 0"

    print("Test 3 passed: Zero multiplication is correct.")

    # Test 4: Verify Multiplication Identity
    for x in range(1, 256):
        identity = antilog_table[log_table[x] + log_table[1]]
        assert identity == x, f"Failed: {x} * 1 = {identity}, expected {x}"

    print("Test 4 passed: Multiplicative identity is correct.")

    # Test 5: Full Table Coverage
    covered_elements = set(antilog_table[:255])
    assert covered_elements == set(range(1, 256)), (
        f"Failed: Not all elements of GF(2^8) are covered in the antilog table. "
        f"Missing: {set(range(1, 256)) - covered_elements}"
    )

    print("Test 5 passed: Full coverage of GF(2^8) is correct.")


test_log_antilog_tables(log_table, antilog_table)
