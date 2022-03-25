/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "bsp.h"

static bool
strings_are_equal(char *a, char *b)
{
   // TODO(law): Remove dependency on string.h.
   bool result = (strcmp(a, b) == 0);
   return result;
}

static void
initialize_request(Request_State *request)
{
#define X(v) request->v = FCGX_GetParam(#v, request->fcgx.envp);
   CGI_METAVARIABLES_LIST
#undef X
}

static void
debug_output_cgi_metavariables(Request_State *request)
{
#if DEVELOPMENT_BUILD
   OUT("<table border=\"1\">");
   OUT("<tr><th>CGI Metavariable</th><th>Value</th></tr>");

#define X(v) OUT("<tr><td>" #v "</td><td>%s</td></tr>", (request->v) ? request->v : "");
   CGI_METAVARIABLES_LIST
#undef X

   OUT("</table>");
#endif
}

static void
output_request_header(Request_State *request, int error_code)
{
   OUT("Content-type: text/html\n");
   OUT("Status: %d\n", error_code);
   OUT("\n");
}

static void
process_request(Request_State *request)
{
   if(strings_are_equal(request->SCRIPT_NAME, "/"))
   {
      output_request_header(request, 200);
      OUT("<!DOCTYPE html>");
      OUT("<h1>Welcome to the next big shitty platform!</h1>");
   }
   else
   {
      output_request_header(request, 404);
      OUT("<!DOCTYPE html>");
      OUT("<h1>404: Page not found</h1>");
   }

   debug_output_cgi_metavariables(request);
}
