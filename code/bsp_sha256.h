#if !defined(BSP_SHA256_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <stdint.h>

typedef struct
{
   unsigned char bytes[32];
   char text[65]; // Includes null terminator.
} SHA256;

typedef struct
{
   uint32_t h[8];
} SHA256_State;

#define BSP_SHA256_H
#endif
