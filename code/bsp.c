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
   OUT("<section id=\"debug-information\">");
   OUT("<table>");
   OUT("<tr><th>CGI Metavariable</th><th>Value</th></tr>");

#define X(v) OUT("<tr><td>" #v "</td><td>%s</td></tr>", (request->v) ? request->v : "");
   CGI_METAVARIABLES_LIST
#undef X

   OUT("</table>");
   OUT("</section>");
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
redirect_request(Request_State *request, char *path)
{
   OUT("Content-type: text/html\n");
   OUT("Status: 303\n");
   OUT("Location: %s\n", path);
   OUT("\n");
}

static void
output_html_header(Request_State *request)
{
   OUT("<!DOCTYPE html>");
   OUT("<link rel=\"stylesheet\" type=\"text/css\" href=\"/css/style.css\">");
   OUT("<header><h1><a href=\"/\">Big Shitty Platform</a></h1></header>");
}

static void
process_request(Request_State *request)
{
   if(strings_are_equal(request->SCRIPT_NAME, "/"))
   {
      output_request_header(request, 200);
      output_html_header(request);

      OUT("<main>");
      OUT("  <form method=\"post\" action=\"/login\" style=\"text-align: center; margin: auto; padding: 0; width: 50ch; max-width: 95%%;\">");
      OUT("    <br>");
      OUT("    <input type=\"text\" name=\"username\" placeholder=\"Username\" style=\"width: 100%%;\" required>");
      OUT("    <br>");
      OUT("    <br>");
      OUT("    <input type=\"password\" name=\"password\" placeholder=\"Password\" style=\"width: 100%%;\" required>");
      OUT("    <br>");
      OUT("    <br>");
      OUT("    <button type=\"submit\">Log in to BSP</button>");
      OUT("  </form>");
      OUT("</main>");
   }
   else if(strings_are_equal(request->SCRIPT_NAME, "/login"))
   {
      if(strings_are_equal(request->REQUEST_METHOD, "POST"))
      {
         output_request_header(request, 200);
         output_html_header(request);

         OUT("<main>");
         OUT("  <p style=\"text-align: center;\">That account does not exist.</p>");
         OUT("</main>");
      }
      else
      {
         redirect_request(request, "/");
         return;
      }
   }
   else
   {
      output_request_header(request, 404);
      output_html_header(request);

      OUT("<main>");
      OUT("  <h2>404: Page not found</h2>");
      OUT("</main>");
   }

   debug_output_cgi_metavariables(request);
}
