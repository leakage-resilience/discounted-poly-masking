// Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
// SPDX-License-Identifier: MIT
#ifndef _PARAMETERS_H
#define _PARAMETERS_H

// Whether to use the frobenius optimization, enabled iff OPT_FROBENIUS=1.
#ifndef OPT_FROBENIUS
#define OPT_FROBENIUS 1
#endif
#if OPT_FROBENIUS != 0 && OPT_FROBENIUS != 1
#error "OPT_FROBENIUS must be defined as 0 or 1"
#endif

// Whether to use the optimized zero encodings, enabled iff OPT_ZENC=1.
#ifndef OPT_ZENC
#define OPT_ZENC 1
#endif
#if OPT_ZENC != 0 && OPT_ZENC != 1
#error "OPT_ZENC must be defined as 0 or 1"
#endif

#endif