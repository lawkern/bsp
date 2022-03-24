/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <fcgiapp.h>

#define OUT(...) FCGX_FPrintF(fcgx.out, __VA_ARGS__)
#define ERR(...) FCGX_FPrintF(fcgx.err, __VA_ARGS__)

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
      OUT("Content-type: text/html\n");
      OUT("Status: 200\n");
      OUT("\n");

      OUT("<h1>Welcome to the next big shitty platform!</h1>");

      FCGX_Finish_r(&fcgx);
   }

   return 0;
}
