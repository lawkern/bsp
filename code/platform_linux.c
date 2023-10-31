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

typedef struct
{
   volatile unsigned int count;
   sem_t handle;
} Platform_Semaphore;

#include "platform.h"
#include "bsp.c"

static
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
      format_string_list(message, ARRAY_LENGTH(message), format, arguments);
   }
   va_end(arguments);

   char log[ARRAY_LENGTH(timestamp) + ARRAY_LENGTH(message) + 1];
   format_string(log, ARRAY_LENGTH(log), "%s%s\n", timestamp, message);

   int file = open(file_path, O_CREAT|O_WRONLY|O_APPEND, 0666);
   if(file >= 0)
   {
      write(file, log, string_length(log));
      close(file);
   }
   else
   {
      assert(0);
   }
}

static
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

static
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

static
PLATFORM_READ_FILE(platform_read_file)
{
   // TODO(law): Better file I/O once file access is needed anywhere besides
   // program startup.

   char *result = 0;

   int file = open(file_name, O_RDONLY);
   if (file >= 0)
   {
      struct stat file_information;
      if(stat(file_name, &file_information) == 0)
      {
         size_t size = file_information.st_size;

         // NOTE(law): Null terminate memory so it can be used as a string.
         result = platform_allocate(size + 1);
         if(result)
         {
            read(file, result, size);
            result[size] = 0;
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

static
PLATFORM_GENERATE_RANDOM_BYTES(platform_generate_random_bytes)
{
   zero_memory(destination, size);
   size_t bytes_generated = getentropy(destination, size);

   if(bytes_generated < 0)
   {
      platform_log_message("[ERROR] Failed to generate a random number.");
   }
   else if(bytes_generated < size)
   {
      platform_log_message("[WARNING] Only generated %ld of requested %ld bytes.", bytes_generated, size);
   }
}

static
PLATFORM_INITIALIZE_SEMAPHORE(platform_initialize_semaphore)
{
   semaphore->count = 0;
   sem_init(&semaphore->handle, 0, 0);
}

static
PLATFORM_LOCK(platform_lock)
{
   if(__sync_add_and_fetch(&semaphore->count, 1) > 1)
   {
      sem_wait(&semaphore->handle);
   }
}

static
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
      initialize_arena(&thread.arena, base_address, arena_size);
      zero_memory(thread.timers, sizeof(thread.timers));

      Platform_Request_State platform_request = {0};
      platform_request.fcgx = fcgx;
      platform_request.request.thread = thread;

      process_request(&platform_request.request);

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

   initialize_application();

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
