#if !defined(BSP_MEMORY_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2023 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#define KILOBYTES(v) (1000LL * (v))
#define MEGABYTES(v) (1000LL * KILOBYTES(v))
#define GIGABYTES(v) (1000LL * MEGABYTES(v))

#define KIBIBYTES(v) (1024LL * (v))
#define MEBIBYTES(v) (1024LL * KIBIBYTES(v))
#define GIBIBYTES(v) (1024LL * MEBIBYTES(v))

typedef struct
{
   unsigned char *base_address;
   size_t size;
   size_t used;
} Memory_Arena;

#define BSP_MEMORY_H
#endif
