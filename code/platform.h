#if !defined(PLATFORM_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2023 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

// NOTE(law): Direct references to FCGX functionality provided by fcgiapp.h are
// isolated in this header file.

#include <fcgiapp.h>

// NOTE(law): The header bsp.h is included here for the definition of
// Request_State needed by Platform_Request_State. That means that the #include
// in bsp.c is unnecessary. It's still there for the moment in case this is
// split into multiple translation units.

#include "platform_intrinsics.h"

// NOTE(law): The platform-agnostic Request_State struct is the first field of
// the platform-dependent version. That way it is possible to cast between them,
// while including any platform-specific fields after Request_State (as in the
// macro functions below).

typedef struct
{
   Request_State request;
   FCGX_Request fcgx;
} Platform_Request_State;

#ifdef OUT
#undef OUT
#endif

#ifdef ERR
#undef ERR
#endif

#define OUT(...) FCGX_FPrintF(((Platform_Request_State *)request)->fcgx.out, __VA_ARGS__)
#define ERR(...) FCGX_FPrintF(((Platform_Request_State *)request)->fcgx.err, __VA_ARGS__)

#define GET_ENVIRONMENT_PARAMETER(name) \
   FCGX_GetParam((name), ((Platform_Request_State *)request)->fcgx.envp)

#define GET_STRING_FROM_INPUT_STREAM(destination, length) \
   FCGX_GetStr((destination), (length), ((Platform_Request_State *)request)->fcgx.in)


// NOTE(law): The following function prototypes are implemented once and shared
// with each platform implementation.

#define BSP_INITIALIZE_APPLICATION(name) void name(void)
extern BSP_INITIALIZE_APPLICATION(bsp_initialize_application);

#define BSP_PROCESS_REQUEST(name) \
   void name(Request_State *request, unsigned char *arena_base_address, size_t arena_size)
extern BSP_PROCESS_REQUEST(bsp_process_request);


// NOTE(law): The following function prototypes must be implemented on a
// per-platform basis.

#define PLATFORM_ALLOCATE(name) void *name(size_t size)
extern PLATFORM_ALLOCATE(platform_allocate);

#define PLATFORM_DEALLOCATE(name) void name(void *memory)
extern PLATFORM_DEALLOCATE(platform_deallocate);

#define PLATFORM_LOG_MESSAGE(name) void name(char *format, ...)
extern PLATFORM_LOG_MESSAGE(platform_log_message);

typedef struct
{
   size_t size;
   unsigned char *memory;
} Platform_File;

#define PLATFORM_FREE_FILE(name) void name(Platform_File *file)
extern PLATFORM_FREE_FILE(platform_free_file);

#define PLATFORM_READ_FILE(name) Platform_File name(char *file_name)
extern PLATFORM_READ_FILE(platform_read_file);

#define PLATFORM_APPEND_FILE(name) bool name(char *file_name, void *memory, size_t size)
extern PLATFORM_APPEND_FILE(platform_append_file);

#define PLATFORM_GENERATE_RANDOM_BYTES(name) void name(void *destination, size_t size)
extern PLATFORM_GENERATE_RANDOM_BYTES(platform_generate_random_bytes);

#define PLATFORM_INITIALIZE_SEMAPHORE(name) struct Platform_Semaphore *name(void)
extern PLATFORM_INITIALIZE_SEMAPHORE(platform_initialize_semaphore);

#define PLATFORM_LOCK(name) void name(struct Platform_Semaphore *semaphore)
extern PLATFORM_LOCK(platform_lock);

#define PLATFORM_UNLOCK(name) void name(struct Platform_Semaphore *semaphore)
extern PLATFORM_UNLOCK(platform_unlock);


#define PLATFORM_H
#endif
