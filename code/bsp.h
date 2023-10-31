#if !defined(BSP_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bsp_sha256.h"

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

#define ASSERT(expression)                                                     \
   do                                                                          \
   {                                                                           \
      if(!(expression))                                                        \
      {                                                                        \
         platform_log_message("Assertion fired on %s:%d", __FILE__, __LINE__); \
         assert(expression);                                                   \
      }                                                                        \
   } while(0)

#define KILOBYTES(v) (1000LL * (v))
#define MEGABYTES(v) (1000LL * KILOBYTES(v))
#define GIGABYTES(v) (1000LL * MEGABYTES(v))

#define KIBIBYTES(v) (1024LL * (v))
#define MEBIBYTES(v) (1024LL * KIBIBYTES(v))
#define GIBIBYTES(v) (1024LL * MEBIBYTES(v))

#define ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))

#define CGI_METAVARIABLES_LIST                  \
   X(AUTH_TYPE)                                 \
   X(CONTENT_LENGTH)                            \
   X(CONTENT_TYPE)                              \
   X(GATEWAY_INTERFACE)                         \
   X(PATH_INFO)                                 \
   X(PATH_TRANSLATED)                           \
   X(QUERY_STRING)                              \
   X(REMOTE_ADDR)                               \
   X(REMOTE_HOST)                               \
   X(REMOTE_IDENT)                              \
   X(REMOTE_USER)                               \
   X(REQUEST_METHOD)                            \
   X(SCRIPT_NAME)                               \
   X(SERVER_ADDR)                               \
   X(SERVER_NAME)                               \
   X(SERVER_PORT)                               \
   X(SERVER_PROTOCOL)                           \
   X(SERVER_SOFTWARE)                           \
   X(HTTP_COOKIE)                               \
   X(HTTP_ACCEPT)                               \
   X(HTTP_ACCEPT_CHARSET)                       \
   X(HTTP_ACCEPT_ENCODING)                      \
   X(HTTP_ACCEPT_LANGUAGE)                      \
   X(HTTP_FORWARDED)                            \
   X(HTTP_HOST)                                 \
   X(HTTP_PROXY_AUTHORIZATION)                  \
   X(HTTP_REFERER)                              \
   X(HTTP_USER_AGENT)

typedef struct
{
   unsigned char *base_address;
   size_t size;
   size_t used;
} Memory_Arena;

typedef struct
{
   char *key;
   char *value;
} Key_Value_Pair;

typedef struct
{
   unsigned int count;
   Key_Value_Pair entries[1024];
} Key_Value_Table;

#define MAX_USERNAME_LENGTH 32
#define MAX_PASSWORD_LENGTH 512
#define SESSION_ID_LENGTH 64

typedef struct
{
   char username[MAX_USERNAME_LENGTH + 1]; // includes null terminator
   unsigned char salt[16];
   unsigned char password_hash[32]; // Width of SHA256 output
   unsigned int iteration_count;

   char session_id[SESSION_ID_LENGTH + 1]; // Include null terminator
} User_Account;

typedef struct
{
   Platform_Semaphore semaphore;

   unsigned int count;
   User_Account users[2 * 1024 * 1024];
} User_Account_Table;

typedef enum
{
   CPU_TIMER_process_request,
   CPU_TIMER_initialize_request,
   CPU_TIMER_output_html_template,
   CPU_TIMER_pbkdf2_hmac_sha256,

   CPU_TIMER_COUNT,
} Cpu_Timer_Id;

typedef struct
{
   Cpu_Timer_Id id;
   char *label;

   unsigned long long start;
   unsigned long long elapsed;
   unsigned long long hits;
} Cpu_Timer;

typedef struct
{
   // NOTE(law): Add any thread-related information that should persist beyond
   // the lifetime of a single request here.

   unsigned int index;
   Memory_Arena arena;
   Cpu_Timer timers[CPU_TIMER_COUNT];
} Thread_Context;

typedef struct
{
   // NOTE(law): The contents of Request_State is intended to persist for the
   // lifetime of a single request made by a single user.

   Thread_Context thread;
   User_Account user;

#define X(v) char *(v);
   CGI_METAVARIABLES_LIST
#undef X

   Key_Value_Table url;
   Key_Value_Table form;
   Key_Value_Table cookies;
} Request_State;

#define BSP_H
#endif
