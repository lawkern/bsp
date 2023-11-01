#if !defined(PLATFORM_INTRINSICS_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2023 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <stdint.h>

static uint64_t
platform_cpu_timestamp_counter(void)
{
   uint64_t result;

#if defined(__aarch64__) || defined(_M_ARM64)
   __asm volatile("mrs %0, cntvct_el0" : "=r" (result));
#else
   result = __rdtsc();
#endif

   return result;
}

#define PLATFORM_INTRINSICS_H
#endif
