// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#include "crt0.h"
#include <stdint.h>

void *memcpy(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;
    while (n--)
    {
        *d++ = *s++;
    }
    return dest;
}

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    while (n--)
    {
        *p++ = (unsigned char)c;
    }
    return s;
}

__attribute__((noreturn)) void qemu_exit(int retcode)
{
    // ret[0] = 0x20026 => ADP_Stopped_ApplicationExit
    // ret[1] = retcode => C stdlib exit() code
    volatile int ret[2];
    ret[0] = 0x20026;
    ret[1] = retcode;

    __asm__ volatile(
        "mov r0, %0\n\t"
        "mov r1, %1\n\t"
        "bkpt #0xAB\n\t"
        :
        : "r"((uint32_t)0x20), // SYS_EXIT_EXTENDED (0x20) (https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst#sys-exit-extended-0x20).
          "r"((uint32_t)ret)   // ADP_Stopped_ApplicationExit with return code passed as argument.
        : "r0", "r1", "memory");
    __builtin_unreachable();
}
