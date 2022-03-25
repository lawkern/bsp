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

int
main(int argument_count, char **arguments)
{
   (void)argument_count;
   (void)arguments;

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
