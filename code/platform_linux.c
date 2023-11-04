/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>

typedef struct Platform_Semaphore
{
   volatile unsigned int count;
   sem_t handle;
} Platform_Semaphore;

#include "bsp.h"
#include "platform.h"

extern
PLATFORM_LOG_MESSAGE(platform_log_message)
{
   char *file_path = "logs/bsp.log";

   time_t raw_time = time(0);
   struct tm time;
   localtime_r(&raw_time, &time);

   char timestamp[32];
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

   int file = open(file_path, O_CREAT|O_WRONLY|O_APPEND, 0666);
   if(file >= 0)
   {
      write(file, log, strlen(log));
      close(file);
   }
   else
   {
      assert(0);
   }
}

extern
PLATFORM_ALLOCATE(platform_allocate)
{
   // NOTE(law): munmap() requires the size of the allocation in order to free
   // the virtual memory. This function smuggles the allocation size just before
   // the address that it actually returns.

   size_t allocation_size = size + sizeof(size_t);
   void *allocation = mmap(0, allocation_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

   if(allocation == MAP_FAILED)
   {
      platform_log_message("[ERROR] Failed to allocate virtual memory.");
      return 0;
   }

   *(size_t *)allocation = allocation_size;

   void *result = (void *)((unsigned char *)allocation + sizeof(size_t));
   return result;
}

extern
PLATFORM_DEALLOCATE(platform_deallocate)
{
   // NOTE(law): munmap() requires the size of the allocation in order to free
   // the virtual memory. We always just want to dump the entire thing, so
   // allocate() hides the allocation size just before the address it returns.

   void *allocation = (void *)((unsigned char *)memory - sizeof(size_t));
   size_t allocation_size = *(size_t *)allocation;

   if(munmap(allocation, allocation_size) != 0)
   {
      platform_log_message("[ERROR] Failed to deallocate virtual memory.");
   }
}

extern
PLATFORM_FREE_FILE(platform_free_file)
{
   if(file->memory)
   {
      platform_deallocate(file->memory);
   }

   memset(file, 0, sizeof(*file));
}

extern
PLATFORM_READ_FILE(platform_read_file)
{
   // TODO(law): Better file I/O once file access is needed anywhere besides
   // program startup.

   Platform_File result = {0};

   int file = open(file_name, O_RDONLY);
   if (file >= 0)
   {
      struct stat file_information;
      if(stat(file_name, &file_information) == 0)
      {
         size_t size = file_information.st_size;

         // NOTE(law): Null terminate memory so it can be used as a string.
         result.memory = platform_allocate(size + 1);
         if(result.memory)
         {
            result.size = size;
            read(file, result.memory, result.size);
            result.memory[result.size] = 0;
         }
         else
         {
            platform_log_message("[ERROR] Failed to allocate memory for file: %s.", file_name);
         }
      }
      else
      {
         platform_log_message("[ERROR] Failed to read file size of file: %s.", file_name);
      }

      close(file);
   }
   else
   {
      platform_log_message("[ERROR] Failed to open file: %s.", file_name);
   }

   return result;
}

extern
PLATFORM_APPEND_FILE(platform_append_file)
{
   bool result = false;

   int file = open(file_name, O_CREAT|O_WRONLY|O_APPEND, 0666);
   if(file != -1)
   {
      ssize_t bytes_written = write(file, memory, size);
      result = (bytes_written == size);

      if(!result)
      {
         platform_log_message("[ERROR] (%d) Failed to write file: \"%s\".", errno, file_name);
      }

      close(file);
   }
   else
   {
      platform_log_message("[ERROR] (%d) Failed to open file: \"%s\".", errno, file_name);
   }

   return result;
}

extern
PLATFORM_GENERATE_RANDOM_BYTES(platform_generate_random_bytes)
{
   memset(destination, 0, size);

   int file = open("/dev/urandom", O_RDONLY);
   if(file >= 0)
   {
      ssize_t bytes_generated = read(file, destination, size);
      if(bytes_generated < 0)
      {
         if(bytes_generated < 0)
         {
            platform_log_message("[ERROR] Failed to generate a random number.");
         }
         else if(bytes_generated < size)
         {
            platform_log_message("[WARNING] Only generated %ld of requested %ld bytes.", bytes_generated, size);
         }
      }
   }
   else
   {
      platform_log_message("[ERROR] Failed to open /dev/urandom.");
   }
}

static unsigned int linux_global_semaphore_count;
static Platform_Semaphore linux_global_semaphores[128];

extern
PLATFORM_INITIALIZE_SEMAPHORE(platform_initialize_semaphore)
{
   ASSERT(linux_global_semaphore_count < ARRAY_LENGTH(linux_global_semaphores));
   Platform_Semaphore *result = linux_global_semaphores + linux_global_semaphore_count++;

   result->count = 0;
   sem_init(&result->handle, 0, 0);

   return result;
}

extern
PLATFORM_LOCK(platform_lock)
{
   if(__sync_add_and_fetch(&semaphore->count, 1) > 1)
   {
      sem_wait(&semaphore->handle);
   }
}

extern
PLATFORM_UNLOCK(platform_unlock)
{
   if(__sync_sub_and_fetch(&semaphore->count, 1) > 0)
   {
      sem_post(&semaphore->handle);
   }
}

static bool
linux_accept_request(FCGX_Request *fcgx)
{
   static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

   pthread_mutex_lock(&mutex);
   int accept_result = FCGX_Accept_r(fcgx);
   pthread_mutex_unlock(&mutex);

   bool result = (accept_result >= 0);
   return result;
}

static void *
linux_launch_request_thread(void *data)
{
   Thread_Context thread = *(Thread_Context *)data;

   platform_log_message("Request thread %d launched.", thread.index);

   size_t arena_size = MEBIBYTES(512);
   unsigned char *base_address = platform_allocate(arena_size);

   FCGX_Request fcgx;
   FCGX_InitRequest(&fcgx, 0, 0);

   while(linux_accept_request(&fcgx))
   {
      memset(thread.timers, 0, sizeof(thread.timers));

      Platform_Request_State platform_request = {0};
      platform_request.fcgx = fcgx;
      platform_request.request.thread = thread;

      bsp_process_request(&platform_request.request, base_address, arena_size);

      FCGX_Finish_r(&fcgx);
   }

   platform_deallocate(base_address);

   platform_log_message("Request thread %d terminated.", thread.index);

   return 0;
}

int
main(int argument_count, char **arguments)
{
   (void)argument_count;
   (void)arguments;

   // NOTE(law): Set the working directory up front to enable consistent access
   // to data assets (html, css, logs, etc.).
   chdir(STRINGIFY(WORKING_DIRECTORY));

   bsp_initialize_application();

   FCGX_Init();

   Thread_Context threads[REQUEST_THREAD_COUNT] = {0};
   for(long index = 1; index < ARRAY_LENGTH(threads); ++index)
   {
      Thread_Context *thread = threads + index;
      thread->index = index;

      pthread_t id;
      pthread_create(&id, 0, linux_launch_request_thread, (void *)thread);
      pthread_detach(id);
   }

   linux_launch_request_thread(threads + 0);

   return 0;
}
