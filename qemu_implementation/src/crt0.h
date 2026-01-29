// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _CRT0_H
#define _CRT0_H

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);

/// @brief Cleanly exit QEMU semihosting on ARM targets.
/// @param retcode C stdlib exit() code, i.e., EXIT_SUCCESS = 0 and EXIT_FAILURE = 1.
void qemu_exit(int retcode);

#define EXIT_SUCCESS (0)
#define EXIT_FAILURE (1)

#endif // _CRT0_H
