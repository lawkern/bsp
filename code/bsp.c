/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "bsp.h"
#include "bsp_memory.c"
#include "bsp_sha256.c"

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
   // <salt> is 32 hexadecimal characters representing a 128-bit
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
         size_t salt_start_length = 2 * sizeof(user.salt);
         assert((scan - salt_start) == salt_start_length);

         hexadecimal_string_to_bytes((unsigned char *)user.salt,
                                     sizeof(user.salt),
                                     salt_start,
                                     salt_start_length);

         // Skip tab
         ++scan;

         // Consume password hash
         char *hash_start = scan;
         while(*scan && *scan != '\t')
         {
            ++scan;
         }
         size_t hash_start_length = 2 * sizeof(user.password_hash);
         assert((scan - hash_start) == hash_start_length);

         hexadecimal_string_to_bytes((unsigned char *)user.password_hash,
                                     sizeof(user.password_hash),
                                     hash_start,
                                     hash_start_length);

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

static User_Account
get_user(char *username)
{
   // TODO(law): Restructure this to use a hash lookup on the user name.

   User_Account result = {0};
   for(unsigned int index = 0; index < global_user_account_table.count; ++index)
   {
      User_Account account = global_user_account_table.users[index];
      if(strings_are_equal(account.username, username))
      {
         result = account;
         break;
      }
   }

   return result;
}

static bool
is_hexadecimal_digit(char character)
{
   bool result = (character == '0' || character == '1' ||
                  character == '2' || character == '3' ||
                  character == '4' || character == '5' ||
                  character == '6' || character == '7' ||
                  character == '8' || character == '9' ||
                  character == 'A' || character == 'a' ||
                  character == 'B' || character == 'b' ||
                  character == 'C' || character == 'c' ||
                  character == 'D' || character == 'd' ||
                  character == 'E' || character == 'e' ||
                  character == 'F' || character == 'f');

   return result;
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
      if(!result.key)
      {
         return result;
      }

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
         if(!result.value)
         {
            result.key = 0;
            return result;
         }

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
   if(table->count < max_hash_count)
   {
      table->count++;

      unsigned long hash_value = hash_key_string(key);
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
   else
   {
      log_message("[WARNING] Failed to insert key/value - table was full.");
   }
}

static char *
get_value(Key_Value_Table *table, char *key)
{
   char *result = 0;

   unsigned long hash_value = hash_key_string(key);
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

   Memory_Arena *arena = &request->arena;

   // Update request data with URL parameters from query string.
   char *query_string = request->QUERY_STRING;
   Key_Value_Pair parameter = consume_key_value_pair(arena, &query_string);
   while(*parameter.key)
   {
      size_t key_size   = string_length(parameter.key) + 1;
      size_t value_size = string_length(parameter.value) + 1;

      char *decoded_key   = PUSH_SIZE(arena, key_size);
      char *decoded_value = PUSH_SIZE(arena, value_size);

      if(!decoded_key || !decoded_value)
      {
         break;
      }

      decode_query_string(decoded_key, parameter.key, key_size);
      decode_query_string(decoded_value, parameter.value, value_size);

      insert_key_value(&request->url, decoded_key, decoded_value);
      parameter = consume_key_value_pair(arena, &query_string);
   }

   // Update request data with form parameters from POST request.
   if(strings_are_equal(request->REQUEST_METHOD, "POST") && request->CONTENT_LENGTH)
   {
      size_t content_length = string_to_integer_decimal(request->CONTENT_LENGTH);
      char *post_data = PUSH_SIZE(arena, content_length + 1);
      if(post_data)
      {
         GET_STRING_FROM_INPUT_STREAM(post_data, content_length + 1);

         Key_Value_Pair parameter = consume_key_value_pair(arena, &post_data);
         while(*parameter.key)
         {
            size_t key_size   = string_length(parameter.key) + 1;
            size_t value_size = string_length(parameter.value) + 1;

            char *decoded_key   = PUSH_SIZE(arena, key_size);
            char *decoded_value = PUSH_SIZE(arena, value_size);

            if(!decoded_key || !decoded_value)
            {
               break;
            }

            decode_query_string(decoded_key, parameter.key, key_size);
            decode_query_string(decoded_value, parameter.value, value_size);

            insert_key_value(&request->form, decoded_key, decoded_value);
            parameter = consume_key_value_pair(arena, &post_data);
         }
      }
   }
}

static void
initialize_application()
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
   import_users_from_database(&global_user_account_table);

   // NOTE(law): Read html tempates into memory.
   char *template_paths[] =
   {
      // TODO(law): New templates need to be manually added to the list here (it
      // doesn't just scan the html directory).

      "html/header.html",
      "html/index.html",
      "html/404.html",
   };

   for(unsigned int index = 0; index < ARRAY_LENGTH(template_paths); ++index)
   {
      // TODO(law): Performing a lot of individually small allocations with
      // read_file() is pretty wasteful. Allocate a big chunk of memory up front
      // just for template data.

      char *path = template_paths[index];
      char *template = read_file(path);
      insert_key_value(&global_html_template_table, path, template);
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
   // NOTE(law): Because of the way this output method works, the contents of
   // the html file is treated as a format string. Therefore, % symbols need to
   // be escaped to work normally (assuming that no additional arguments are
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
   Memory_Arena *arena = &request->arena;
   Key_Value_Table *url = &request->url;
   Key_Value_Table *form = &request->form;

   OUT("<section id=\"debug-information\">");

   // Output url parameters
   OUT("<table>");
   OUT("<tr><th>URL Parameter</th><th>Value</th></tr>");
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
         OUT("<tr>");
         OUT("<td>%s</td>", encode_for_html(arena, parameter->key));
         OUT("<td>%s</td>", encode_for_html(arena, value));
         OUT("</tr>");
      }
   }
   OUT("</table>");

   // Output arena data
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

   OUT("<table>");
   OUT("<tr><th colspan=\"2\">Memory Arena</th></tr>", request->thread_id);
   OUT("<tr><td>Thread ID</td><td>%ld</td></tr>", request->thread_id);
   OUT("<tr><td>Arena Size</td><td>%0.1f%s</td></tr>", arena_size, units_size);
   OUT("<tr><td>Arena Used</td><td>%0.1f%s</td></tr>", arena_used, units_used);
   OUT("</table>");

   // Output user accounts
   OUT("<table>");
   OUT("<tr><th>Username</th><th>Salt</th><th>Password Hash</th></tr>");
   for(unsigned int index = 0; index < global_user_account_table.count; ++index)
   {
      User_Account *user = global_user_account_table.users + index;
      OUT("<tr>");
      OUT("<td>%s</td>", encode_for_html(arena, user->username));
      OUT("<td>");
      print_bytes(request, user->salt, 16);
      OUT("</td>");
      OUT("<td>");
      print_bytes(request, user->password_hash, 32);
      OUT("</td>");
      OUT("</tr>");
   }
   OUT("</table>");

   // Output CGI metavariables
   OUT("<table>");
   OUT("<tr><th>CGI Metavariable</th><th>Value</th></tr>");

#define X(v) OUT("<tr><td>" #v "</td><td>%s</td></tr>",                 \
                 (request->v) ? encode_for_html(arena, request->v) : "");
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

#define PBKDF2_PASSWORD_ITERATION_ACCOUNT 100000

static User_Account
login_user(char *username, char *password)
{
   // NOTE(law): The convention here is that *result.username == 0 means that
   // the user doesn't exists, while *result.password_hash == 0 or *result.salt
   // == 0 means that the supplied password was incorrect.

   // NOTE(law): This and the account registration code are the only areas of
   // the codebase that work with the user's password directly. It only ever
   // exists in working memory - only the salt value and resulting hash are ever
   // saved to disc.

   User_Account result = {0};

   User_Account user = get_user(username);
   if(*user.username)
   {
      // NOTE(law): Save the name to indicate that the account existed.
      memory_copy(result.username, username, sizeof(result.username));

      unsigned char password_hash[sizeof(user.password_hash)];
      unsigned char *password_bytes = (unsigned char *)password;
      size_t password_size = string_length(password);

      pbkdf2_hmac_sha256(password_hash,
                         sizeof(password_hash),
                         password_bytes,
                         password_size,
                         user.salt,
                         sizeof(user.salt),
                         PBKDF2_PASSWORD_ITERATION_ACCOUNT);

      // NOTE(law): If the password hash matches that of the existing account,
      // they can log in (so fill out the rest of the result struct).
      if(bytes_are_equal(password_hash, user.password_hash, sizeof(user.password_hash)))
      {
         result = user;
      }
   }

   return result;
}

static void
register_user(char *username, char *password)
{
   User_Account user = {0};

   // NOTE(law): Generate the random bytes to act as the user's
   // password salt value.
   unsigned char salt[sizeof(user.salt)];
   get_random_bytes(salt, sizeof(salt));

   unsigned char password_hash[sizeof(user.password_hash)];

   pbkdf2_hmac_sha256(password_hash,
                      sizeof(password_hash),
                      (unsigned char *)password,
                      string_length(password),
                      salt,
                      sizeof(salt),
                      PBKDF2_PASSWORD_ITERATION_ACCOUNT);

   // TODO(law): Add to user database.
}

static void
process_request(Request_State *request)
{
   log_message("%s request to \"%s\" received by thread %ld.",
               request->REQUEST_METHOD,
               request->SCRIPT_NAME,
               request->thread_id);

   Memory_Arena *arena = &request->arena;
   Key_Value_Table *form = &request->form;

   if(strings_are_equal(request->SCRIPT_NAME, "/"))
   {
      output_request_header(request, 200);
      OUTPUT_HTML_TEMPLATE("header.html");

      if(get_value(form, "login"))
      {
         // Account login was attempted.
         char *username = get_value(form, "username");
         char *password = get_value(form, "password");

         User_Account user = login_user(username, password);

         if(!*username || !*password)
         {
            OUT("<p class=\"warning\">Please supply both a username and password.</p>");
            OUTPUT_HTML_TEMPLATE("index.html");
         }
         else if(*user.username == 0)
         {
            OUT("<p class=\"warning\">That account does not exist.</p>");
            OUTPUT_HTML_TEMPLATE("index.html");
         }
         else if(*user.password_hash == 0)
         {
            OUT("<p class=\"warning\">The provided username/password was incorrect.</p>");
            OUTPUT_HTML_TEMPLATE("index.html");
         }
         else
         {
            OUT("<p class=\"success\">Success!</p>");
         }
      }
      else if(get_value(form, "register"))
      {
         // Account registration was submitted.
         char *username = get_value(form, "username");
         char *password = get_value(form, "password");

         // TODO(law): Add validation for evil characters.
         if(!*username || !*password)
         {
            OUT("<p class=\"warning\">Please supply both a username and password.</p>");
            OUTPUT_HTML_TEMPLATE("index.html");
         }
         else if(string_length(username) > MAX_USERNAME_LENGTH)
         {
            OUT("<p class=\"warning\">A username cannot exceed %d characters.</p>", MAX_USERNAME_LENGTH);
            OUTPUT_HTML_TEMPLATE("index.html");
         }
         else if(string_length(password) > MAX_PASSWORD_LENGTH)
         {
            OUT("<p class=\"warning\">A password cannot exceed %d characters.</p>", MAX_PASSWORD_LENGTH);
            OUTPUT_HTML_TEMPLATE("index.html");
         }
         else
         {
            User_Account user = get_user(username);
            if(*user.username)
            {
               // Username was already taken.
               OUT("<p class=\"warning\">That username already exists.</p>");
               OUTPUT_HTML_TEMPLATE("index.html");
            }
            else
            {
               register_user(username, password);
               OUT("<p class=\"success\">Your account registration has been submitted.</p>");
            }
         }
      }
      else
      {
         OUTPUT_HTML_TEMPLATE("index.html");
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
