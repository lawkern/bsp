#if !defined(PLATFORM_LINUX_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

// NOTE(law): Direct references to FCGX functionality provided by fcgiapp.h are
// isolated in this header file.

#include <fcgiapp.h>

#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

// NOTE(law): The header bsp.h is included here for the definition of
// Request_State needed by Linux_Request_State. That means that the #include in
// bsp.c is unnecessary. It's still there for the moment in case this is split
// into multiple translation units.

#include "bsp.h"

// NOTE(law): The platform-agnostic Request_State struct is the first field of
// the platform-dependent version. That way it is possible to cast between them,
// while including any platform-specific fields after Request_State (as in the
// macro functions below).

typedef struct
{
   Request_State request;
   FCGX_Request fcgx;
} Linux_Request_State;

#define OUT(...) FCGX_FPrintF(((Linux_Request_State *)request)->fcgx.out, __VA_ARGS__)
#define ERR(...) FCGX_FPrintF(((Linux_Request_State *)request)->fcgx.err, __VA_ARGS__)

#define GET_ENVIRONMENT_PARAMETER(name) \
   FCGX_GetParam((name), ((Linux_Request_State *)request)->fcgx.envp)

#define GET_STRING_FROM_INPUT_STREAM(destination, length) \
   FCGX_GetStr((destination), (length), ((Linux_Request_State *)request)->fcgx.in)

#define PLATFORM_LINUX_H
#endif
