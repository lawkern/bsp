/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "bsp.h"

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
   OUT("<table border=\"1\">");
   OUT("<tr><th>CGI Metavariable</th><th>Value</th></tr>");

#define X(v) OUT("<tr><td>" #v "</td><td>%s</td></tr>", (request->v) ? request->v : "");
   CGI_METAVARIABLES_LIST
#undef X

   OUT("</table>");
}
