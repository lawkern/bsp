/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "bsp.h"
#include "platform.h"

#include "bsp_memory.c"
#include "bsp_sha256.c"
#include "bsp_database.c"

static Key_Value_Table global_html_templates;

#define CPU_TIMER_BEGIN(label) cpu_timer_begin(&request->thread, (CPU_TIMER_##label), (#label))
#define CPU_TIMER_END(label) cpu_timer_end(&request->thread, (CPU_TIMER_##label))

static void
cpu_timer_begin(Thread_Context *thread, Cpu_Timer_Id id, char *label)
{
   Cpu_Timer *timer = thread->timers + id;
   timer->id = id;
   timer->label = label;
   timer->start = platform_cpu_timestamp_counter();
}

static void
cpu_timer_end(Thread_Context *thread, Cpu_Timer_Id id)
{
   Cpu_Timer *timer = thread->timers + id;
   timer->elapsed += (platform_cpu_timestamp_counter() - timer->start);
   timer->hits++;
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
generate_session_id(char *destination, size_t size)
{
   ASSERT(size == 64);

   unsigned char message[4096];
   platform_generate_random_bytes(message, sizeof(message));

   SHA256 hash = hash_sha256(message, sizeof(message));
   memory_copy(destination, hash.text, size);
}

#define SESSION_COOKIE_KEY "id"

static void
clear_session(Request_State *request)
{
   zero_memory(&request->user, sizeof(request->user));

   OUT("Content-type: text/html\n");
#if DEVELOPMENT_BUILD
   OUT("Set-Cookie: " SESSION_COOKIE_KEY "=; SameSite=Strict; HttpOnly\n");
#else
   OUT("Set-Cookie: " SESSION_COOKIE_KEY "=; SameSite=Strict; Secure; HttpOnly\n");
#endif

   OUT("Status: 303\n");
   OUT("Location: /\n");
   OUT("\n");
}

static void
create_session(Request_State *request, char *username)
{
   char session_id[SESSION_ID_LENGTH + 1] = {0};
   generate_session_id(session_id, SESSION_ID_LENGTH);

   database_update_user_session_id(username, session_id);

   OUT("Content-type: text/html\n");
#if DEVELOPMENT_BUILD
   OUT("Set-Cookie: " SESSION_COOKIE_KEY "=%s; SameSite=Strict; HttpOnly\n", session_id);
#else
   OUT("Set-Cookie: " SESSION_COOKIE_KEY "=%s; SameSite=Strict; Secure; HttpOnly\n", session_id);
#endif

   // TODO(law): Should updating the session cookie redirect back to the
   // referer? Or to a specific page?

   // OUT("Location: %s\n", request->HTTP_REFERER);

   OUT("Location: /\n");
   OUT("\n");
}

static void
decode_query_string(char *destination, char *source, size_t size)
{
   while(*source && size-- > 1)
   {
      if(source[0] == '%' &&
         source[1] &&
         source[2] &&
         is_hexadecimal_digit(source[1]) &&
         is_hexadecimal_digit(source[2]))
      {
         char x1 = source[1];
         char x2 = source[2];

         // NOTE(law): If in the range of lowercase hexadecimal characters,
         // shift into the range of uppercase characters.
         if(x1 >= 'a') {x1 -= ('a' - 'A');}
         if(x2 >= 'a') {x2 -= ('a' - 'A');}

         // NOTE(law): If the character is a letter (A-F), then shift down to
         // its equivalent decimal value (10-15). Otherwise shift down to the
         // single decimal digit range.
         x1 -= (x1 >= 'A') ? ('A' - 10) : '0';
         x2 -= (x2 >= 'A') ? ('A' - 10) : '0';

         // NOTE(law): Assemble hex digits into a single base-16 value.
         *destination++ = (16 * x1) + x2;
         source += 3;
      }
      else if(source[0] == '+')
      {
         // NOTE(law): Convert '+' back to a space character.
         *destination++ = ' ';
         source++;
      }
      else
      {
         *destination++ = *source++;
      }
   }

   // Null terminate the string.
   *destination = 0;
}

static unsigned long
hash_key_string(char *string)
{
   // This is the djb2 hash function referenced at
   // http://www.cse.yorku.ca/~oz/hash.html

   unsigned long result = 5381;

   int character = *string++;
   while(character)
   {
      result = ((result << 5) + result) + character; /* result * 33 + c */
      character = *string++;
   }

   return result;
}

static Key_Value_Pair
consume_key_value_pair(Memory_Arena *arena, char **key_value_string, char delimiter)
{
   // NOTE(law): The convention here is that result.key == "" (i.e. *result.key
   // == 0) implies that a pair could not be pulled from the parsed string. In
   // cases where a key exists but a value does not (e.g. the "baz" in
   // "foo=bar&baz"), the value defaults to an empty string.

   Key_Value_Pair result = {0};

   if(*key_value_string)
   {
      // Consume key of parameter:
      char *start = *key_value_string;
      char *scan = start;

      while(*scan && *scan != delimiter && *scan != '=')
      {
         scan++;
      }

      size_t key_size = scan - start;
      result.key = PUSH_SIZE(arena, key_size + 1);
      if(!result.key)
      {
         return result;
      }

      memory_copy(result.key, start, key_size);
      result.key[key_size] = 0;

      if(*scan == '=')
      {
         // Skip '=' character:
         ++scan;

         // Consume value of parameter:
         start = scan;
         while(*scan && *scan != delimiter)
         {
            scan++;
         }

         size_t value_size = scan - start;
         result.value = PUSH_SIZE(arena, value_size + 1);
         if(!result.value)
         {
            result.key = 0;
            return result;
         }

         memory_copy(result.value, start, value_size);
         result.value[value_size] = 0;
      }

      if(*scan == delimiter)
      {
         // Skip delimiter character:
         scan++;

         // NOTE(law): If the delimiter is a ';' (i.e. we are parsing a cookie
         // string) skip any whitespace between the delimiter and the next
         // entry.
         while(delimiter == ';' && is_whitespace(*scan))
         {
            scan++;
         }
      }

      if(result.key && !result.value)
      {
         // NOTE(law): Default non-existent values to an empty string.
         result.value = PUSH_SIZE(arena, 1);
         if(!result.value)
         {
            result.key = 0;
            return result;
         }
         result.value[0] = 0;
      }

      *key_value_string = scan;
   }

   return result;
}

static void
insert_key_value(Key_Value_Table *table, char *key, char *value)
{
   // TODO(law): Resizable table?
   if(table->count >= ARRAY_LENGTH(table->entries))
   {
      platform_log_message("[WARNING] Failed to insert key/value - table was full.");
      return;
   }

   for(unsigned int hash_index = hash_key_string(key); ; ++hash_index)
   {
      hash_index %= ARRAY_LENGTH(table->entries);

      Key_Value_Pair *entry = table->entries + hash_index;
      if(!strings_are_equal(key, entry->key) && entry->key)
      {
         continue;
      }

      entry->key = key;
      entry->value = value;

      table->count++;
      break;
   }
}

static char *
get_value(Key_Value_Table *table, char *key)
{
   char *result = 0;

   for(unsigned int hash_index = hash_key_string(key); ; ++hash_index)
   {
      hash_index %= ARRAY_LENGTH(table->entries);

      Key_Value_Pair *entry = table->entries + hash_index;
      if(!entry->key)
      {
         break;
      }
      else if(strings_are_equal(key, entry->key))
      {
         result = entry->value;
         break;
      }
   }

   return result;
}

static void
initialize_request(Request_State *request, unsigned char *arena_base_address, size_t arena_size)
{
   CPU_TIMER_BEGIN(initialize_request);

   // Update request data with CGI metavariables from host environment.
#define X(v) request->v = GET_ENVIRONMENT_PARAMETER(#v);  \
   if(!request->v) request->v = "";

   CGI_METAVARIABLES_LIST
#undef X

   Memory_Arena *arena = &request->thread.arena;
   initialize_arena(arena, arena_base_address, arena_size);

   Key_Value_Table *url = &request->url;
   Key_Value_Table *form = &request->form;
   Key_Value_Table *cookies = &request->cookies;

   char *cookie_string = request->HTTP_COOKIE;
   if(cookie_string)
   {
      Key_Value_Pair parameter = consume_key_value_pair(arena, &cookie_string, ';');
      while(*parameter.key)
      {
         insert_key_value(cookies, parameter.key, parameter.value);
         parameter = consume_key_value_pair(arena, &cookie_string, ';');
      }
   }

   char *session_id = get_value(cookies, SESSION_COOKIE_KEY);
   if(session_id && *session_id)
   {
      // TODO(law): Check for valid existing session that matches the id
      // provided by the client.
      User_Account user = database_get_user_by_session(session_id);
      memory_copy(&request->user, &user, sizeof(user));
   }

   // Update request data with URL parameters from query string.
   char *query_string = request->QUERY_STRING;
   Key_Value_Pair url_parameter = consume_key_value_pair(arena, &query_string, '&');
   while(*url_parameter.key)
   {
      size_t key_size   = string_length(url_parameter.key) + 1;
      size_t value_size = string_length(url_parameter.value) + 1;

      char *decoded_key   = PUSH_SIZE(arena, key_size);
      char *decoded_value = PUSH_SIZE(arena, value_size);

      if(!decoded_key || !decoded_value)
      {
         break;
      }

      decode_query_string(decoded_key, url_parameter.key, key_size);
      decode_query_string(decoded_value, url_parameter.value, value_size);

      insert_key_value(url, decoded_key, decoded_value);
      url_parameter = consume_key_value_pair(arena, &query_string, '&');
   }

   // Update request data with form parameters from POST request.
   if(strings_are_equal(request->REQUEST_METHOD, "POST") && request->CONTENT_LENGTH)
   {
      int content_length = decimal_string_to_integer(request->CONTENT_LENGTH);
      char *post_data = PUSH_SIZE(arena, content_length + 1);
      if(post_data)
      {
         GET_STRING_FROM_INPUT_STREAM(post_data, content_length + 1);

         Key_Value_Pair post_parameter = consume_key_value_pair(arena, &post_data, '&');
         while(*post_parameter.key)
         {
            size_t key_size   = string_length(post_parameter.key) + 1;
            size_t value_size = string_length(post_parameter.value) + 1;

            char *decoded_key   = PUSH_SIZE(arena, key_size);
            char *decoded_value = PUSH_SIZE(arena, value_size);

            if(!decoded_key || !decoded_value)
            {
               break;
            }

            decode_query_string(decoded_key, post_parameter.key, key_size);
            decode_query_string(decoded_value, post_parameter.value, value_size);

            insert_key_value(form, decoded_key, decoded_value);
            post_parameter = consume_key_value_pair(arena, &post_data, '&');
         }
      }
   }

   CPU_TIMER_END(initialize_request);
}

extern
BSP_INITIALIZE_APPLICATION(bsp_initialize_application)
{
   // NOTE(law): This function is called once at program startup. It assumes
   // resources are released automatically when the program exits (i.e. this
   // will leak if called more than once).

#if DEVELOPMENT_BUILD
   // NOTE(law): Perform any automated testing.
   test_hash_sha256(2048);
   test_hmac_sha256(2048);
   test_pbkdf2_hmac_sha256(8);
#endif

   // NOTE(law): Read user accounts into memory.
   database_initialize(MEBIBYTES(512));

   // NOTE(law): Read html tempates into memory.
   char *template_paths[] =
   {
      // TODO(law): New templates need to be manually added to the list here (it
      // doesn't just scan the html directory).

      "html/head.html",
      "html/footer.html",
      "html/authentication-form.html",
      "html/404.html",
   };

   for(unsigned int index = 0; index < ARRAY_LENGTH(template_paths); ++index)
   {
      // TODO(law): Performing a lot of individually small allocations with
      // read_file() is pretty wasteful. Allocate a big chunk of memory up front
      // just for template data.

      char *path = template_paths[index];
      char *template = (char *)platform_read_file(path).memory;
      insert_key_value(&global_html_templates, path, template);
   }
}

static char *
encode_for_html(Memory_Arena *arena, char *input_string)
{
   size_t size = 1;
   char *result = PUSH_SIZE(arena, size);

   while(*input_string)
   {
      if(input_string[0] == '&')
      {
         PUSH_SIZE(arena, 5);

         result[size++ - 1] = '&';
         result[size++ - 1] = 'a';
         result[size++ - 1] = 'm';
         result[size++ - 1] = 'p';
         result[size++ - 1] = ';';
      }
      else if(input_string[0] == '<')
      {
         PUSH_SIZE(arena, 4);

         result[size++ - 1] = '&';
         result[size++ - 1] = 'l';
         result[size++ - 1] = 't';
         result[size++ - 1] = ';';
      }
      else if(input_string[0] == '>')
      {
         PUSH_SIZE(arena, 4);

         result[size++ - 1] = '&';
         result[size++ - 1] = 'g';
         result[size++ - 1] = 't';
         result[size++ - 1] = ';';
      }
      else if(input_string[0] == '"')
      {
         PUSH_SIZE(arena, 6);

         result[size++ - 1] = '&';
         result[size++ - 1] = 'q';
         result[size++ - 1] = 'u';
         result[size++ - 1] = 'o';
         result[size++ - 1] = 't';
         result[size++ - 1] = ';';
      }
      else
      {
         PUSH_SIZE(arena, 1);

         result[size++ - 1] = input_string[0];
      }

      input_string++;
   }

   // Null terminate
   result[size - 1] = 0;

   return result;
}

#define OUTPUT_HTML_TEMPLATE(name) output_html_template(request, "html/" name)

static void
output_html_template(Request_State *request, char *path)
{
   CPU_TIMER_BEGIN(output_html_template);

   // NOTE(law): Because of the way this output method works, the contents of
   // the html file is treated as a format string. Therefore, % symbols need to
   // be escaped to work normally (assuming that no additional arguments are
   // passed to OUT()).

   char *html = get_value(&global_html_templates, path);
   if(html)
   {
      OUT(html);
   }
   else
   {
      platform_log_message("[WARNING] HTML template \"%s\" could not be found.", path);
#if DEVELOPMENT_BUILD
      OUT("<p class=\"warning\">MISSING TEMPLATE: %s</p>", path);
#endif
   }

   CPU_TIMER_END(output_html_template);
}

static void
debug_output_request_data(Request_State *request)
{
#if DEVELOPMENT_BUILD
   OUT("<style>"
       "/* Debug Information */"
       "section#debug-information {padding: 0 1em; border-top: 1px solid #444; background: #181818;}"
       "section#debug-information section {display: flex; align-items: flex-start;}"
       "section#debug-information table {font-family: monospace; min-width:250px; margin: 1em;}"
       "section#debug-information caption {text-align: left; font-weight: bold;}"
       "section#debug-information th {background: #444; white-space: nowrap;}"
       "section#debug-information td.debug-empty {text-align: center;}"
       "</style>");

   Memory_Arena *arena = &request->thread.arena;
   Key_Value_Table *url = &request->url;
   Key_Value_Table *form = &request->form;
   Key_Value_Table *cookies = &request->cookies;

   OUT("<section id=\"debug-information\">");

   float arena_size = (float)arena->size;
   char *units_size = "B";
   if(arena_size >= MEBIBYTES(1))
   {
      arena_size /= MEBIBYTES(1);
      units_size = "MiB";
   }
   else if(arena_size >= KIBIBYTES(1))
   {
      arena_size /= KIBIBYTES(1);
      units_size = "KiB";
   }

   float arena_used = (float)arena->used;
   char *units_used = "B";
   if(arena_used >= MEBIBYTES(1))
   {
      arena_used /= MEBIBYTES(1);
      units_used = "MiB";
   }
   else if(arena_used >= KIBIBYTES(1))
   {
      arena_used /= KIBIBYTES(1);
      units_used = "KiB";
   }

   OUT("<section>");
   // Output arena data
   OUT("<table>");
   OUT("<tr><th colspan=\"2\">Memory Arena</th></tr>");
   OUT("<tr><td>Thread</td><td>%ld</td></tr>", request->thread.index);
   OUT("<tr><td>Arena Size</td><td>%0.1f%s</td></tr>", arena_size, units_size);
   OUT("<tr><td>Arena Used</td><td>%0.1f%s</td></tr>", arena_used, units_used);
   OUT("</table>");

   // Output performance timers
   OUT("<table>");
   OUT("<tr>");
   OUT("<th>Timed Profiler Block</th>");
   OUT("<th>Hits</th>");
   OUT("<th>Total Cycles</th>");
   OUT("<th>Cycles per Hit</th>");
   OUT("</tr>");
   for(unsigned int index = 0; index < CPU_TIMER_COUNT; ++index)
   {
      Cpu_Timer *timer = request->thread.timers + index;
      if(timer->hits > 0)
      {
         OUT("<tr>");
         OUT("<td>%s</td>", encode_for_html(arena, timer->label));
         OUT("<td>%5u</td>", timer->hits);
         OUT("<td>%10u</td>", timer->elapsed);
         OUT("<td>%10u</td>", timer->elapsed / timer->hits);
         OUT("</tr>");
      }
   }
   OUT("</table>");
   OUT("</section>");

   OUT("<section>");

   // Output url parameters
   OUT("<table>");
   OUT("<tr><th>URL Parameter</th><th>Value</th></tr>");
   unsigned int url_parameter_count = 0;
   for(unsigned int index = 0; index < ARRAY_LENGTH(url->entries); ++index)
   {
      Key_Value_Pair *parameter = url->entries + index;
      if(parameter->key && *parameter->key)
      {
         char *value = (parameter->value) ? parameter->value : "";
         OUT("<tr>");
         OUT("<td>%s</td>", encode_for_html(arena, parameter->key));
         OUT("<td>%s</td>", encode_for_html(arena, value));
         OUT("</tr>");
         url_parameter_count++;
      }
   }
   if(url_parameter_count == 0)
   {
      OUT("<tr><td colspan=\"2\" class=\"debug-empty\">No entries</td></tr>");
   }
   OUT("</table>");

   // Output form parameters
   OUT("<table>");
   OUT("<tr><th>Form Parameter</th><th>Value</th></tr>");
   unsigned int form_parameter_count = 0;
   for(unsigned int index = 0; index < ARRAY_LENGTH(form->entries); ++index)
   {
      Key_Value_Pair *parameter = form->entries + index;
      if(parameter->key && *parameter->key)
      {
         char *value = (parameter->value) ? parameter->value : "";
         OUT("<tr>");
         OUT("<td>%s</td>", encode_for_html(arena, parameter->key));
         OUT("<td>%s</td>", encode_for_html(arena, value));
         OUT("</tr>");
         form_parameter_count++;
      }
   }
   if(form_parameter_count == 0)
   {
      OUT("<tr><td colspan=\"2\" class=\"debug-empty\">No entries</td></tr>");
   }
   OUT("</table>");

   // Output cookies
   OUT("<table>");
   OUT("<tr><th>Cookie</th><th>Value</th></tr>");
   unsigned int cookie_count = 0;
   for(unsigned int index = 0; index < ARRAY_LENGTH(cookies->entries); ++index)
   {
      Key_Value_Pair *parameter = cookies->entries + index;
      if(parameter->key && *parameter->key)
      {
         char *value = (parameter->value) ? parameter->value : "";
         OUT("<tr>");
         OUT("<td>%s</td>", encode_for_html(arena, parameter->key));
         OUT("<td>%s</td>", encode_for_html(arena, value));
         OUT("</tr>");
         cookie_count++;
      }
   }
   if(cookie_count == 0)
   {
      OUT("<tr><td colspan=\"2\" class=\"debug-empty\">No entries</td></tr>");
   }
   OUT("</table>");

   OUT("</section>");

   // Output user accounts
   OUT("<table>");
   OUT("<tr>");
   OUT("<th>Username</th>");
   OUT("<th>Salt</th>");
   OUT("<th>Password Hash</th>");
   OUT("<th>Iteration Count</th>");
   OUT("<th>Session ID</th>");
   OUT("</tr>");

   for(unsigned int index = 0; index < database.users.row_count; ++index)
   {
      User_Account *user = (User_Account *)database.users.rows + index;
      OUT("<tr>");
      OUT("<td>%s</td>", encode_for_html(arena, user->username));
      OUT("<td>");
      print_bytes(request, user->salt, SALT_LENGTH);
      OUT("</td>");
      OUT("<td>");
      print_bytes(request, user->password_hash, PASSWORD_HASH_LENGTH);
      OUT("</td>");
      OUT("<td>%d</td>", user->iteration_count);
      char *session_id = encode_for_html(arena, user->session_id);
      if(string_length(session_id) > 20)
      {
         OUT("<td>%.*s...</td>", 20, session_id);
      }
      else
      {
         OUT("<td>%s</td>", session_id);
      }
      OUT("</tr>");
   }
   if(database.users.row_count == 0)
   {
      OUT("<tr><td colspan=\"5\" class=\"debug-empty\">No entries</td></tr>");
   }
   OUT("</table>");

   // Output CGI metavariables
   OUT("<table>");
   OUT("<tr><th>CGI Metavariable</th><th>Value</th></tr>");

#define X(v) OUT("<tr><td>" #v "</td><td>%s</td></tr>", encode_for_html(arena, request->v));
   CGI_METAVARIABLES_LIST
#undef X

   OUT("</table>");

   OUT("</section>");
#endif
}

static void
login_user(Request_State *request, char *username, char *password)
{
   // NOTE(law): This and the account registration code are the only areas of
   // the codebase that work with the user's password directly. It only ever
   // exists in working memory - only the salt value and resulting hash are ever
   // saved to disc.

   if(!*username || !*password)
   {
      // "Please supply both a username and password."
      redirect_request(request, "/?error=missing-auth");
      return;
   }

   User_Account user = database_get_user_by_username(username);

   if(*user.username == 0)
   {
      // "That account does not exist."
      redirect_request(request, "/?error=not-account");
      return;
   }

   unsigned char password_hash[sizeof(user.password_hash)];
   unsigned char *password_bytes = (unsigned char *)password;
   size_t password_size = string_length(password);

   CPU_TIMER_BEGIN(pbkdf2_hmac_sha256);
   pbkdf2_hmac_sha256(password_hash,
                      sizeof(password_hash),
                      password_bytes,
                      password_size,
                      user.salt,
                      sizeof(user.salt),
                      user.iteration_count);
   CPU_TIMER_END(pbkdf2_hmac_sha256);

   if(!bytes_are_equal(password_hash, user.password_hash, sizeof(user.password_hash)))
   {
      // "The provided username/password was incorrect."
      redirect_request(request, "/?error=wrong-password");
      return;
   }

   create_session(request, username);
}

#define PBKDF2_PASSWORD_ITERATION_ACCOUNT 100000

static void
register_user(Request_State *request, char *username, char *password)
{
   // TODO(law): Add validation for evil characters.

   if(!*username || !*password)
   {
      // "Please supply both a username and password."
      redirect_request(request, "/?error=missing-auth");
      return;
   }

   if(string_length(username) > MAX_USERNAME_LENGTH)
   {
      // "A username cannot exceed %d characters."
      redirect_request(request, "/?error=username-too-long");
      return;
   }

   if(string_length(password) > MAX_PASSWORD_LENGTH)
   {
      // "A password cannot exceed %d characters.", MAX_PASSWORD_LENGTH
      redirect_request(request, "/?error=password-too-long");
      return;
   }

   User_Account existing_user = database_get_user_by_username(username);
   if(*existing_user.username)
   {
      // "That username already exists."
      redirect_request(request, "/?error=user-exists");
      return;
   }

   // NOTE(law): Generate the random bytes that will act as the user's salt
   // value for producing their password hash.
   unsigned char salt[sizeof(existing_user.salt)];
   platform_generate_random_bytes(salt, sizeof(salt));

   unsigned char password_hash[sizeof(existing_user.password_hash)];
   unsigned char *password_bytes = (unsigned char *)password;
   size_t password_size = string_length(password);

   CPU_TIMER_BEGIN(pbkdf2_hmac_sha256);
   pbkdf2_hmac_sha256(password_hash, sizeof(password_hash),
                      password_bytes, password_size,
                      salt, sizeof(salt),
                      PBKDF2_PASSWORD_ITERATION_ACCOUNT);
   CPU_TIMER_END(pbkdf2_hmac_sha256);

   database_insert_user(username, salt, password_hash, PBKDF2_PASSWORD_ITERATION_ACCOUNT);

   // NOTE(Law): Perform the login with the initial password as a sanity check
   // that things worked.
   login_user(request, username, password);
}

static bool
is_logged_in(Request_State *request)
{
   bool result = false;

   char *session_id = get_value(&request->cookies, SESSION_COOKIE_KEY);
   if(session_id && *session_id && strings_are_equal(request->user.session_id, session_id))
   {
      result = true;
   }

   return result;
}

static void
output_html_header(Request_State *request, bool logged_in)
{
   // TODO(law): Replace with some form of HTML templating.

   OUTPUT_HTML_TEMPLATE("head.html");
   OUT("<header>");

   OUT("<strong>"
       "<a href=\"/\">BSP</a>"
       "</strong>");

   if(logged_in)
   {
      char *username = encode_for_html(&request->thread.arena, request->user.username);

      OUT("<span>");
      OUT("<a href=\"/user?id=%s\">%s</a>", username, username);
      OUT(" | ");
      OUT("<a href=\"/logout\">Log Out</a>");
      OUT("</span>");
   }

   OUT("</header>");
}

extern
BSP_PROCESS_REQUEST(bsp_process_request)
{
   CPU_TIMER_BEGIN(process_request);

   initialize_request(request, arena_base_address, arena_size);
   platform_log_message("%s request to \"%s\" received by thread %ld.",
                        request->REQUEST_METHOD,
                        request->SCRIPT_NAME,
                        request->thread.index);

   Memory_Arena *arena = &request->thread.arena;
   Key_Value_Table *url = &request->url;
   Key_Value_Table *form = &request->form;

   bool logged_in = is_logged_in(request);

   if(strings_are_equal(request->SCRIPT_NAME, "/"))
   {
      if(strings_are_equal(request->REQUEST_METHOD, "POST"))
      {
         if(get_value(form, "login"))
         {
            // Account login was attempted.
            char *username = get_value(form, "username");
            char *password = get_value(form, "password");

            login_user(request, username, password);
         }
         else if(get_value(form, "register"))
         {
            // Account registration was submitted.
            char *username = get_value(form, "username");
            char *password = get_value(form, "password");

            register_user(request, username, password);
         }
         else
         {
            // Unhandled POST request
            redirect_request(request, "/");
         }
      }
      else
      {
         output_request_header(request, 200);
         output_html_header(request, logged_in);

         char *error = get_value(url, "error");
         if(error)
         {
            OUT("<p class=\"warning\">%s</p>", encode_for_html(arena, error));
         }

         if(logged_in)
         {
            OUT("<p class=\"success\">You are logged in!</p>");
         }
         else
         {
            OUTPUT_HTML_TEMPLATE("authentication-form.html");
         }

         OUTPUT_HTML_TEMPLATE("footer.html");
      }
   }
   else if(strings_are_equal(request->SCRIPT_NAME, "/user"))
   {
      output_request_header(request, 200);
      output_html_header(request, logged_in);
      OUT("<main style=\"text-align: center;\">");

      char *username = get_value(url, "id");
      if(username)
      {
         User_Account user = database_get_user_by_username(username);
         if(strings_are_equal(username, request->user.username))
         {
            OUT("<p>This page is yours.</p>");
            OUT("<p>Customization coming soon!</p>");
         }
         else if(*user.username)
         {
            OUT("<p>This page belongs to <strong>%s</strong>.</p>", encode_for_html(arena, user.username));
         }
         else
         {
            OUT("<p>This user does not exist.</p>");
         }
      }

      OUT("</main>");
      OUTPUT_HTML_TEMPLATE("footer.html");
   }
   else if(strings_are_equal(request->SCRIPT_NAME, "/logout"))
   {
      clear_session(request);
   }
   else
   {
      output_request_header(request, 404);
      output_html_header(request, logged_in);
      OUTPUT_HTML_TEMPLATE("404.html");
      OUTPUT_HTML_TEMPLATE("footer.html");
   }

   CPU_TIMER_END(process_request);

   debug_output_request_data(request);
}
