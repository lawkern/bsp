#if !defined(BSP_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bsp_sha256.h"

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

#define KILOBYTES(v) (1000LL * (v))
#define MEGABYTES(v) (1000LL * KILOBYTES(v))

#define KIBIBYTES(v) (1024LL * (v))
#define MEBIBYTES(v) (1024LL * KIBIBYTES(v))

#define ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))

#define PLATFORM_ALLOCATE(name) void *name(size_t size)
static PLATFORM_ALLOCATE(allocate);

#define PLATFORM_DEALLOCATE(name) void name(void *memory)
static PLATFORM_DEALLOCATE(deallocate);

#define PLATFORM_LOG_MESSAGE(name) void name(char *format, ...)
static PLATFORM_LOG_MESSAGE(log_message);

#define PLATFORM_READ_FILE(name) char *name(char *file_name)
static PLATFORM_READ_FILE(read_file);

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

typedef struct
{
   char username[33]; // includes null terminator
   SHA256_Hash password_hash;
   unsigned short salt;
} User_Account;

typedef struct
{
   unsigned int count;
   User_Account users[1024];
} User_Account_Table;

typedef struct
{
   // NOTE(law): The contents of Request_State is intended to persist for the
   // lifetime of a single request made by a single user.

   Memory_Arena arena;
   long thread_id;

#define X(v) char *(v);
   CGI_METAVARIABLES_LIST
#undef X

   Key_Value_Table url;
   Key_Value_Table form;
} Request_State;

#define BSP_H
#endif
