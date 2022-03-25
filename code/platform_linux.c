/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <fcgiapp.h>
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
   size_t size = MEGABYTES(64);
   unsigned char *base_address = allocate(size);

   FCGX_InitRequest(&fcgx, 0, 0);
   while(FCGX_Accept_r(&fcgx) >= 0)
   {
      initialize_arena(&arena, base_address, size);

      Request_State request_ = {fcgx, arena};
      Request_State *request = &request_;

      initialize_request(request);
      process_request(request);

      FCGX_Finish_r(&fcgx);
   }

   return 0;
}
