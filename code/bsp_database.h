#if !defined(BSP_DATABASE_H)
/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2023 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#define MAX_USERNAME_LENGTH 31
#define MAX_PASSWORD_LENGTH 512

#define SALT_LENGTH 16
#define PASSWORD_HASH_LENGTH 32
#define SESSION_ID_LENGTH 64

#pragma pack(push, 1)
typedef struct
{
   char username[MAX_USERNAME_LENGTH + 1]; // includes null terminator
   unsigned char salt[SALT_LENGTH];
   unsigned char password_hash[PASSWORD_HASH_LENGTH]; // Width of SHA256 output
   unsigned int iteration_count;
   char session_id[SESSION_ID_LENGTH + 1]; // Include null terminator
} User_Account;
#pragma pack(pop)

typedef struct
{
   Platform_Semaphore semaphore;
   char *file_path;

   unsigned int max_row_count;
   unsigned int row_count;
   void *rows;
} Database_Table;

#define BSP_DATABASE_H
#endif
