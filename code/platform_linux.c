/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "platform_linux.h"
#include "bsp.c"

static
PLATFORM_LOG_MESSAGE(log_message)
{
   char *log_path = "../data/bsp.log";

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

   int file = open(log_path, O_CREAT|O_WRONLY|O_APPEND, 0666);
   if(file >= 0)
   {
      write(file, log, string_length(log));
      close(file);
   }
}

static
PLATFORM_ALLOCATE(allocate)
{
   // NOTE(law): munmap() requires the size of the allocation in order to free
   // the virtual memory. This function smuggles the allocation size just before
   // the address that it actually returns.

   size_t allocation_size = size + sizeof(size_t);
   void *allocation = mmap(0, allocation_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

   if(allocation == MAP_FAILED)
   {
      log_message("[ERROR] Failed to allocate virtual memory.");
      return 0;
   }

   *(size_t *)allocation = allocation_size;

   void *result = (void *)((unsigned char *)allocation + sizeof(size_t));
   return result;
}

static
PLATFORM_DEALLOCATE(deallocate)
{
   // NOTE(law): munmap() requires the size of the allocation in order to free
   // the virtual memory. We always just want to dump the entire thing, so
   // allocate() hides the allocation size just before the address it returns.

   void *allocation = (void *)((unsigned char *)memory - sizeof(size_t));
   size_t allocation_size = *(size_t *)allocation;

   if(munmap(allocation, allocation_size) != 0)
   {
      log_message("[ERROR] Failed to deallocate virtual memory.");
   }
}

static
PLATFORM_READ_FILE(read_file)
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
         result = allocate(size + 1);
         if(result)
         {
            read(file, result, size);
            result[size] = 0;
         }
         else
         {
            log_message("[ERROR] Failed to allocate memory for file: %s.", file_name);
         }
      }
      else
      {
         log_message("[ERROR] Failed to read file size of file: %s.", file_name);
      }

      close(file);
   }
   else
   {
      log_message("[ERROR] Failed to open file: %s.", file_name);
   }

   return result;
}

static bool
accept_request(FCGX_Request *fcgx)
{
   static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

   pthread_mutex_lock(&mutex);
   int accept_result = FCGX_Accept_r(fcgx);
   pthread_mutex_unlock(&mutex);

   bool result = (accept_result >= 0);
   return result;
}

static void *
launch_request_thread(void *data)
{
   long thread_id = (long)data;
   log_message("Request thread %ld launched.", thread_id);

   Memory_Arena arena;
   size_t size = MEGABYTES(512);
   unsigned char *base_address = allocate(size);

   FCGX_Request fcgx;
   FCGX_InitRequest(&fcgx, 0, 0);

   while(accept_request(&fcgx))
   {
      initialize_arena(&arena, base_address, size);

      Linux_Request_State linux_request_ = {0};
      Linux_Request_State *linux_request = &linux_request_;
      linux_request->fcgx = fcgx;

      Request_State *request = (Request_State *)linux_request;
      request->arena = arena;
      request->thread_id = thread_id;

      initialize_request(request);
      process_request(request);

      FCGX_Finish_r(&fcgx);
   }

   deallocate(base_address);

   log_message("Request thread %ld terminated.", thread_id);

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

   pthread_t threads[REQUEST_THREAD_COUNT];
   for(long index = 1; index < ARRAY_LENGTH(threads); ++index)
   {
      pthread_t *thread = threads + index;
      pthread_create(thread, 0, launch_request_thread, (void *)index);
   }

   launch_request_thread(0);

   return 0;
}
