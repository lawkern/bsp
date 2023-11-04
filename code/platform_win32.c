#include <windows.h>
#include <wincrypt.h>

#include <stdarg.h>
#include <string.h>
#include <time.h>

typedef struct Platform_Semaphore
{
   volatile LONG count;
   HANDLE handle;
} Platform_Semaphore;

#include "bsp.h"
#include "platform.h"

static HANDLE win32_global_request_mutex;
static HANDLE win32_global_log_mutex;

extern
PLATFORM_LOG_MESSAGE(platform_log_message)
{
   char *file_path = "logs/bsp.log";

   __time64_t source_time;
   _time64(&source_time);

   struct tm time;
   _localtime64_s(&time, &source_time);

   char timestamp[32] = {0};
   strftime(timestamp, ARRAY_LENGTH(timestamp), "%FT%T%z\t", &time);

   char message[1024];
   va_list arguments;
   va_start(arguments, format);
   {
      vsnprintf(message, ARRAY_LENGTH(message), format, arguments);
   }
   va_end(arguments);

   char log[ARRAY_LENGTH(timestamp) + ARRAY_LENGTH(message) + 1];
   snprintf(log, ARRAY_LENGTH(log), "%s%s\n", timestamp, message);

   WaitForSingleObject(win32_global_log_mutex, INFINITE);
   {
      HANDLE file = CreateFileA(file_path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
      if(file != INVALID_HANDLE_VALUE)
      {
         DWORD bytes_written;
         BOOL success = WriteFile(file, log, (DWORD)strlen(log), &bytes_written, 0);
         CloseHandle(file);
      }
      else
      {
         OutputDebugString("[ERROR] Failed to log the following message:\n");
         OutputDebugString(log);
      }
   }
   ReleaseMutex(win32_global_log_mutex);
}

extern
PLATFORM_ALLOCATE(platform_allocate)
{
   void *result = VirtualAlloc(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
   return result;
}

extern
PLATFORM_DEALLOCATE(platform_deallocate)
{
   if(!VirtualFree(memory, 0, MEM_RELEASE))
   {
      OutputDebugStringA("Failed to free virtual memory.\n");
   }
}

extern
PLATFORM_FREE_FILE(platform_free_file)
{
   if(file->memory)
   {
      if(!VirtualFree(file->memory, 0, MEM_RELEASE))
      {
         platform_log_message("[ERROR] Failed to free virtual memory.");
      }
   }

   ZeroMemory(file, sizeof(*file));
}

extern
PLATFORM_READ_FILE(platform_read_file)
{
   // TODO(law): Better file I/O once file access is needed anywhere besides
   // program startup.

   // TODO(law): Handle file sizes exceeding 2^32 bytes.

   Platform_File result = {0};

   WIN32_FIND_DATAA file_data;
   HANDLE find_file = FindFirstFileA(file_name, &file_data);
   if(find_file == INVALID_HANDLE_VALUE)
   {
      platform_log_message("[ERROR] Failed to read size of file: %s.", file_name);
      return result;
   }
   FindClose(find_file);

   size_t size = (file_data.nFileSizeHigh * (MAXDWORD + 1)) + file_data.nFileSizeLow;
   size_t allocation_size = size + 1;
   result.memory = platform_allocate(allocation_size);
   if(!result.memory)
   {
      platform_log_message("[ERROR] Failed to allocate memory for file: %s.", file_name);
      return result;
   }

   HANDLE file = CreateFileA(file_name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
   DWORD bytes_read;
   if(ReadFile(file, result.memory, (DWORD)size, &bytes_read, 0) || size != bytes_read)
   {
      result.size = size;
   }
   else
   {
      platform_log_message("[ERROR] Failed to read file: %s.", file_name);
      platform_free_file(&result);
   }
   CloseHandle(file);

   // NOTE(law): Append a null-terminator to the end of the file contents, in
   // cases where it's convenient to access as a C-style string.
   result.memory[size] = 0;

   return result;
}

extern
PLATFORM_APPEND_FILE(platform_append_file)
{
   bool result = false;

   HANDLE file = CreateFileA(file_name, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
   if(file != INVALID_HANDLE_VALUE)
   {
      DWORD bytes_written;
      BOOL success = WriteFile(file, memory, (DWORD)size, &bytes_written, 0);
      if(success)
      {
         result = true;
      }
      else
      {
         platform_log_message("[ERROR] Failed to write file: \"%s\".", file_name);
      }

      CloseHandle(file);
   }
   else
   {
      platform_log_message("[ERROR] Failed to open file: \"%s\".", file_name);
   }

   return result;
}

static HCRYPTPROV win32_global_cryptography_handle;

static void
win32_initialize_random_number_generator(void)
{
   BOOL succeeded = CryptAcquireContextA(&win32_global_cryptography_handle, 0, 0, PROV_RSA_FULL, 0);
   if(!succeeded)
   {
      platform_log_message("[ERROR] Failed to initialize random number generation.");
      assert(0);
   }
}

extern
PLATFORM_GENERATE_RANDOM_BYTES(platform_generate_random_bytes)
{
   SecureZeroMemory(destination, size);

   BOOL succeeded = CryptGenRandom(win32_global_cryptography_handle, (DWORD)size, destination);
   if(!succeeded)
   {
      platform_log_message("[ERROR] Failed to generate a random number.");
   }
}

static unsigned int win32_global_semaphore_count;
static Platform_Semaphore win32_global_semaphores[128];

extern
PLATFORM_INITIALIZE_SEMAPHORE(platform_initialize_semaphore)
{
   ASSERT(win32_global_semaphore_count < ARRAY_LENGTH(win32_global_semaphores));
   struct Platform_Semaphore *result = win32_global_semaphores + win32_global_semaphore_count++;

   result->count = 0;
   result->handle = CreateSemaphoreA(0, 0, REQUEST_THREAD_COUNT, 0);

   return result;
}

extern
PLATFORM_LOCK(platform_lock)
{
   if(InterlockedIncrement(&semaphore->count) > 1)
   {
      WaitForSingleObject(semaphore->handle, INFINITE);
   }
}

extern
PLATFORM_UNLOCK(platform_unlock)
{
   if(InterlockedDecrement(&semaphore->count) > 0)
   {
      ReleaseSemaphore(semaphore->handle, 1, 0);
   }
}

static bool
win32_accept_request(FCGX_Request *fcgx)
{
   WaitForSingleObject(win32_global_request_mutex, INFINITE);
   int accept_result = FCGX_Accept_r(fcgx);
   ReleaseMutex(win32_global_request_mutex);

   bool result = (accept_result >= 0);
   return result;
}

static int win32_global_socket;

static DWORD
win32_launch_request_thread(VOID *data)
{
   Thread_Context thread = *(Thread_Context *)data;

   platform_log_message("Request thread %d launched.", thread.index);

   size_t arena_size = MEBIBYTES(512);
   unsigned char *base_address = platform_allocate(arena_size);

   FCGX_Request fcgx;
   FCGX_InitRequest(&fcgx, win32_global_socket, 0);

   while(win32_accept_request(&fcgx))
   {
      ZeroMemory(thread.timers, sizeof(thread.timers));

      Platform_Request_State platform_request = {0};
      platform_request.fcgx = fcgx;
      platform_request.request.thread = thread;

      bsp_process_request(&platform_request.request, base_address, arena_size);

      FCGX_Finish_r(&fcgx);
   }

   platform_deallocate(base_address);

   return 0;
}

int
main(int argument_count, char **arguments)
{
   (void)argument_count;
   (void)arguments;

   win32_initialize_random_number_generator();

   bsp_initialize_application();

   FCGX_Init();
   win32_global_socket = FCGX_OpenSocket(":" STRINGIFY(APPLICATION_PORT), 1024);

   win32_global_request_mutex = CreateMutexA(0, 0, 0);
   win32_global_log_mutex = CreateMutexA(0, 0, 0);

   Thread_Context threads[REQUEST_THREAD_COUNT] = {0};
   for(long index = 1; index < ARRAY_LENGTH(threads); ++index)
   {
      Thread_Context *thread = threads + index;
      thread->index = index;

      HANDLE thread_handle = CreateThread(0, 0, win32_launch_request_thread, (void *)thread, 0, 0);
      CloseHandle(thread_handle);
   }

   win32_launch_request_thread(threads + 0);

   return 0;
}
