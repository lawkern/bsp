/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <fcgiapp.h>

#include "bsp.c"

int
main(int argument_count, char **arguments)
{
   (void)argument_count;
   (void)arguments;

   FCGX_Request fcgx;
   FCGX_Init();

   FCGX_InitRequest(&fcgx, 0, 0);
   while(FCGX_Accept_r(&fcgx) >= 0)
   {
      Request_State request_ = {fcgx};
      Request_State *request = &request_;

      initialize_request(request);

      OUT("Content-type: text/html\n");
      OUT("Status: 200\n");
      OUT("\n");
      OUT("<h1>Welcome to the next big shitty platform!</h1>");

      debug_output_cgi_metavariables(request);

      FCGX_Finish_r(&fcgx);
   }

   return 0;
}
