/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "platform_linux.h"
#include "bsp.c"

static
PLATFORM_ALLOCATE(allocate)
{
   // TODO(law): replace with mmap().
   void *result = calloc(1, size);
   return result;
}

static
PLATFORM_DEALLOCATE(deallocate)
{
   if(memory)
   {
      free(memory);
   }
}

static
PLATFORM_READ_FILE(read_file)
{
   // TODO(law): Implement this with os primitives.

   Platform_File result = {0};

   FILE *file = fopen(file_name, "rb");
   if (file)
   {
      fseek(file, 0, SEEK_END);
      long size = ftell(file);
      fseek(file, 0, SEEK_SET);

      if(size >= 0 && size <= UINT32_MAX)
      {
         result.size = size;

         // NOTE(law): This explicitly null terminates the file contents so it
         // can be used as a string.
         result.memory = allocate(result.size + 1);
         if(result.memory)
         {
            result.memory[result.size] = 0;
            fread(result.memory, 1, result.size, file);
         }
         else
         {
            // TODO(law): Log error.
            result.size = 0;
         }
      }
      else
      {
         // TODO(law): Log error.
      }

      fclose(file);
   }
   else
   {
      // TODO(law): Log error.
   }

   return result;
}

int
main(int argument_count, char **arguments)
{
   (void)argument_count;
   (void)arguments;

   initialize_templates(&global_html_templates);

   FCGX_Request fcgx;
   FCGX_Init();

   Memory_Arena arena;
   size_t size = MEGABYTES(512);
   unsigned char *base_address = allocate(size);

   FCGX_InitRequest(&fcgx, 0, 0);
   while(FCGX_Accept_r(&fcgx) >= 0)
   {
      initialize_arena(&arena, base_address, size);

      Linux_Request_State linux_request_ = {0};
      Linux_Request_State *linux_request = &linux_request_;
      linux_request->fcgx = fcgx;

      Request_State *request = (Request_State *)linux_request;
      request->arena = arena;

      initialize_request(request);
      process_request(request);

      FCGX_Finish_r(&fcgx);
   }

   return 0;
}
