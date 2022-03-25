/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include "bsp.h"

static void
initialize_arena(Memory_Arena *arena, unsigned char *base_address, size_t size)
{
   arena->base_address = base_address;
   arena->size = size;
   arena->used = 0;
}

#define PUSH_SIZE(arena, size)           push_size_((arena), (size))
#define PUSH_STRUCT(arena, Type) (Type *)push_size_((arena), sizeof(Type))

static void *
push_size_(Memory_Arena *arena, size_t size)
{
   // TODO(law): Replace with a growing arena.
   assert(size <= (arena->size - arena->used));

   void *result = arena->base_address + arena->used;
   arena->used += size;

   return result;
}

static bool
strings_are_equal(char *a, char *b)
{
   // TODO(law): Remove dependency on string.h.
   bool result = (strcmp(a, b) == 0);
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
debug_output_request_data(Request_State *request)
{
#if DEVELOPMENT_BUILD
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

         char *username = get_value(&request->form, "username");

         OUT("<main>");
         OUT("  <p style=\"text-align: center;\">The account <kbd>%s</kbd> does not exist.</p>", (username) ? username : "");
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

   debug_output_request_data(request);
}
