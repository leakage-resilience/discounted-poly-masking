// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _ERROR_HANDLER_H
#define _ERROR_HANDLER_H
#include "uart.h"
#include "crt0.h"
static inline void handle_error(const char *message)
{
  print(message);
  qemu_exit(EXIT_FAILURE);
}

#endif // ERROR_HANDLER_H