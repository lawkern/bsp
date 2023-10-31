#if !defined(PLATFORM_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2023 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

// NOTE(law): Direct references to FCGX functionality provided by fcgiapp.h are
// isolated in this header file.

#include <fcgiapp.h>

typedef enum
{
   PLATFORM_TIMER_process_request,
   PLATFORM_TIMER_initialize_request,
   PLATFORM_TIMER_output_html_template,
   PLATFORM_TIMER_pbkdf2_hmac_sha256,

   PLATFORM_TIMER_COUNT,
} Platform_Timer_Id;

typedef struct
{
   Platform_Timer_Id id;
   char *label;

   unsigned long long start;
   unsigned long long elapsed;
   unsigned long long hits;
} Platform_Timer;

// NOTE(law): The header bsp.h is included here for the definition of
// Request_State needed by Platform_Request_State. That means that the #include
// in bsp.c is unnecessary. It's still there for the moment in case this is
// split into multiple translation units.

#include "bsp.h"

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


// NOTE(law): The following function prototypes must be implemented on a
// per-platform basis.

#define PLATFORM_ALLOCATE(name) void *name(size_t size)
static PLATFORM_ALLOCATE(platform_allocate);

#define PLATFORM_DEALLOCATE(name) void name(void *memory)
static PLATFORM_DEALLOCATE(platform_deallocate);

#define PLATFORM_LOG_MESSAGE(name) void name(char *format, ...)
static PLATFORM_LOG_MESSAGE(platform_log_message);

#define PLATFORM_READ_FILE(name) char *name(char *file_name)
static PLATFORM_READ_FILE(platform_read_file);

#define PLATFORM_GENERATE_RANDOM_BYTES(name) void name(void *destination, size_t size)
static PLATFORM_GENERATE_RANDOM_BYTES(platform_generate_random_bytes);

#define PLATFORM_INITIALIZE_SEMAPHORE(name) void name(Platform_Semaphore *semaphore)
static PLATFORM_INITIALIZE_SEMAPHORE(platform_initialize_semaphore);

#define PLATFORM_LOCK(name) void name(Platform_Semaphore *semaphore)
static PLATFORM_LOCK(platform_lock);

#define PLATFORM_UNLOCK(name) void name(Platform_Semaphore *semaphore)
static PLATFORM_UNLOCK(platform_unlock);

#define PLATFORM_TIMER_BEGIN(name) void name(Thread_Context *thread, Platform_Timer_Id id, char *label)
static PLATFORM_TIMER_BEGIN(platform_timer_begin);

#define PLATFORM_TIMER_END(name) void name(Thread_Context *thread, Platform_Timer_Id id)
static PLATFORM_TIMER_END(platform_timer_end);

#define TIMER_BLOCK_BEGIN(label) platform_timer_begin(&request->thread, (PLATFORM_TIMER_##label), (#label))
#define TIMER_BLOCK_END(label) platform_timer_end(&request->thread, (PLATFORM_TIMER_##label))

#define PLATFORM_H
#endif
