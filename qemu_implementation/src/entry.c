// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "stdint.h"

static volatile uint8_t *uart = (volatile uint8_t *)0x4000C000;

void print(const char *s)
{
    while (*s) {
        *uart = (uint8_t)*s++;
    }
}

void print_uint(uint32_t n)
{
  char buf[16];
  uint32_t r;

  buf[15] = '\0';
  char *ptr = buf + 14;

  if (!n)
    *ptr-- = '0';

  while (n)
  {
    r = n % 10;
    n = n / 10;
    *ptr-- = r + '0';
  }
  print(ptr + 1);
}

void print_byte_hex(uint8_t b)
{
  char buf[3];
  buf[2] = '\0';
  char *ptr = buf + 1;

  for (int i = 0; i < 2; i++)
  {
    uint8_t nibble = (b >> (4 * i)) & 0xF;
    if (nibble < 10)
      *ptr-- = nibble + '0';
    else
      *ptr-- = nibble - 10 + 'A';
  }
  print(ptr + 1);
}

void main(void);
void entry() { main(); }