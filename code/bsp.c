/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "bsp.h"
#include "bsp_memory.c"

static Key_Value_Table    global_html_template_table;
static User_Account_Table global_user_account_table;

static void
import_users_from_database(User_Account_Table *table)
{
   // NOTE(law): User entries are stored in a flat file with the following
   // format:
   //
   //   <salt><TAB><password_hash><TAB><username><NEWLINE>
   //
   // <salt> is four hexadecimal characters representing a 16-bit
   // integer. <password_hash> is 64 hexadecimal characters representing a
   // 256-bit integer. <username> is a string of up to 32 characters.

   // TODO(law): This structure is mainly for development purposes. I'd like to
   // get away without needing a database indefinitely, but at the very least
   // this could be stored more efficiently in binary.

   char *database_contents = read_file("users.dbsp");

   if(database_contents)
   {
      char *scan = database_contents;
      while(*scan)
      {
         User_Account user = {0};

         // Consume salt
         char *salt_start = scan;
         while(*scan && *scan != '\t')
         {
            ++scan;
         }
         assert((scan - salt_start) == 4);
         user.salt = strtol(salt_start, 0, 16);

         // Skip tab
         ++scan;

         // Consume password hash
         char *hash_start = scan;
         while(*scan && *scan != '\t')
         {
            ++scan;
         }
         assert((scan - hash_start) == 64);
         memory_copy(user.password_hash, hash_start, 64);

         // Skip tab
         ++scan;

         // Consume username
         char *username_start = scan;
         while(*scan && *scan != '\n')
         {
            ++scan;
         }
         assert((scan - username_start) <= (ARRAY_LENGTH(user.username) - 1));
         memcpy(user.username, username_start, scan - username_start);

         // Skip newline
         ++scan;

         table->users[table->count++] = user;
      }

      deallocate(database_contents);
   }
   else
   {
      log_message("[WARNING] Failed to open the user database.");
   }
}

static unsigned long
hash_string(char *string)
{
   // This is the djb2 hash function referenced at
   // http://www.cse.yorku.ca/~oz/hash.html

    unsigned long result = 5381;

    int c;
    while((c = *string++))
    {
       result = ((result << 5) + result) + c; /* result * 33 + c */
    }

    return result;
}

static Key_Value_Pair
consume_key_value_pair(Memory_Arena *arena, char **key_value_string)
{
   // NOTE(law): The convention here is that *result.key == 0 implies that
   // another pair could not be found in the parsed string.

   Key_Value_Pair result = {0};

   if(*key_value_string)
   {
      // Consume key of parameter:
      char *start = *key_value_string;
      char *scan = start;

      while(*scan && *scan != '&' && *scan != '=')
      {
         scan++;
      }

      size_t key_size = scan - start;
      result.key = PUSH_SIZE(arena, key_size + 1);
      memcpy(result.key, start, key_size);
      result.key[key_size] = 0;

      if(*scan == '=')
      {
         // Skip '=' character:
         ++scan;

         // Consume value of parameter:
         start = scan;
         while(*scan && *scan != '&')
         {
            scan++;
         }

         size_t value_size = scan - start;
         result.value = PUSH_SIZE(arena, value_size + 1);
         memcpy(result.value, start, value_size);
         result.value[value_size] = 0;
      }

      if(*scan == '&')
      {
         // Skip '&' character:
         scan++;
      }

      *key_value_string = scan;
   }

   return result;
}

static void
insert_key_value(Key_Value_Table *table, char *key, char *value)
{
   // TODO(law): Resizable table?
   unsigned int max_hash_count = ARRAY_LENGTH(table->entries);
   assert(table->count < max_hash_count);
   table->count++;

   unsigned long hash_value = hash_string(key);
   unsigned int hash_index = hash_value % max_hash_count;

   Key_Value_Pair *entry = table->entries + hash_index;
   while(entry->key)
   {
      hash_index++;
      if(hash_index >= max_hash_count)
      {
         hash_index = 0;
      }

      entry = table->entries + hash_index;
   }

   entry->key = key;
   entry->value = value;
}

static char *
get_value(Key_Value_Table *table, char *key)
{
   char *result = 0;

   unsigned long hash_value = hash_string(key);
   unsigned int hash_index = hash_value % ARRAY_LENGTH(table->entries);

   Key_Value_Pair *entry = table->entries + hash_index;
   while(entry->key)
   {
      if(strings_are_equal(key, entry->key))
      {
         result = entry->value;
         break;
      }
      else
      {
         hash_index++;
         if(hash_index >= ARRAY_LENGTH(table->entries))
         {
            hash_index = 0;
         }

         entry = table->entries + hash_index;
      }
   }

   return result;
}

static void
initialize_request(Request_State *request)
{
   // Update request data with CGI metavariables from host environment.
#define X(v) request->v = GET_ENVIRONMENT_PARAMETER(#v);
   CGI_METAVARIABLES_LIST
#undef X

   // Update request data with URL parameters from query string.
   char *query_string = request->QUERY_STRING;
   Key_Value_Pair parameter = consume_key_value_pair(&request->arena, &query_string);
   while(*parameter.key)
   {
      insert_key_value(&request->url, parameter.key, parameter.value);
      parameter = consume_key_value_pair(&request->arena, &query_string);
   }

   // Update request data with form parameters from POST request.
   if(strings_are_equal(request->REQUEST_METHOD, "POST") && request->CONTENT_LENGTH)
   {
      size_t content_length = strtol(request->CONTENT_LENGTH, 0, 10);
      char *post_data = allocate(sizeof(char) * (content_length + 1));
      char *free_data = post_data;
      {
         GET_STRING_FROM_INPUT_STREAM(post_data, content_length + 1);

         Key_Value_Pair parameter = consume_key_value_pair(&request->arena, &post_data);
         while(*parameter.key)
         {
            insert_key_value(&request->form, parameter.key, parameter.value);
            parameter = consume_key_value_pair(&request->arena, &post_data);
         }
      }
      deallocate(free_data);
   }
}

static void
initialize_application()
{
   // NOTE(law): This function is called once at program startup. It assumes
   // resources are released automatically when the program exits (i.e. this
   // will leak if called more than once).

   // NOTE(law): Read user accounts into memory.
   import_users_from_database(&global_user_account_table);

   // NOTE(law): Read html tempates into memory.
   char *template_paths[] =
   {
      // TODO(law): New templates need to be manually added to the list here (it
      // doesn't just scan the html directory).

     "html/header.html",
     "html/index.html",
     "html/login.html",
     "html/404.html",
   };

   for(unsigned int index = 0; index < ARRAY_LENGTH(template_paths); ++index)
   {
      char *path = template_paths[index];
      char *template = read_file(path);
      insert_key_value(&global_html_template_table, path, template);
   }
}

#define OUTPUT_HTML_TEMPLATE(name) output_html_template(request, "html/" name)

static void
output_html_template(Request_State *request, char *path)
{
   // NOTE(law): Because of the way this output method works, the contents of
   // the html file is treated as a format string. Therefore, % symbols need to
   // be escaped to work normally (assuming that no addtional arguments are
   // passed to OUT()).

   char *html = get_value(&global_html_template_table, path);
   if(html)
   {
      OUT(html);
   }
   else
   {
      log_message("[WARNING] HTML template \"%s\" could not be found.", path);
#if DEVELOPMENT_BUILD
      OUT("<p>MISSING TEMPLATE: %s</p>", path);
#endif
   }
}

static void
debug_output_request_data(Request_State *request)
{
#if DEVELOPMENT_BUILD
   Key_Value_Table *url = &request->url;
   Key_Value_Table *form = &request->form;

   OUT("<section id=\"debug-information\">");

   // Output thread data
   OUT("<table>");
   OUT("<tr><td>Thread ID</td><td>%ld</td></tr>", request->thread_id);
   OUT("</table>");

   // Output url parameters
   OUT("<table>");
   OUT("<tr><th>URL Parameter</th><th>Value</th></tr>");
   for(unsigned int index = 0; index < ARRAY_LENGTH(url->entries); ++index)
   {
      Key_Value_Pair *parameter = url->entries + index;
      if(parameter->key && *parameter->key)
      {
         char *value = (parameter->value) ? parameter->value : "";
         OUT("<tr><td>%s</td><td>%s</td></tr>", parameter->key, value);
      }
   }
   OUT("</table>");

   // Output form parameters
   OUT("<table>");
   OUT("<tr><th>Form Parameter</th><th>Value</th></tr>");
   for(unsigned int index = 0; index < ARRAY_LENGTH(form->entries); ++index)
   {
      Key_Value_Pair *parameter = form->entries + index;
      if(parameter->key && *parameter->key)
      {
         char *value = (parameter->value) ? parameter->value : "";
         OUT("<tr><td>%s</td><td>%s</td></tr>", parameter->key, value);
      }
   }
   OUT("</table>");

   // Output user accounts
   OUT("<table>");
   OUT("<tr><th>Username</th><th>Salt</th><th>Password Hash</th></tr>");
   for(unsigned int index = 0; index < global_user_account_table.count; ++index)
   {
      User_Account *user = global_user_account_table.users + index;
      OUT("<tr><td>%s</td><td>%x</td><td>%s</td></tr>", user->username, user->salt, user->password_hash);
   }
   OUT("</table>");

   // Output CGI metavariables
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
process_request(Request_State *request)
{
   log_message("%s request to \"%s\" received by thread %ld.",
               request->REQUEST_METHOD,
               request->SCRIPT_NAME,
               request->thread_id);


   if(strings_are_equal(request->SCRIPT_NAME, "/"))
   {
      output_request_header(request, 200);
      OUTPUT_HTML_TEMPLATE("header.html");
      OUTPUT_HTML_TEMPLATE("index.html");

   }
   else if(strings_are_equal(request->SCRIPT_NAME, "/login"))
   {
      if(strings_are_equal(request->REQUEST_METHOD, "POST"))
      {
         output_request_header(request, 200);
         OUTPUT_HTML_TEMPLATE("header.html");
         OUTPUT_HTML_TEMPLATE("login.html");
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
      OUTPUT_HTML_TEMPLATE("header.html");
      OUTPUT_HTML_TEMPLATE("404.html");
   }

   debug_output_request_data(request);
}
