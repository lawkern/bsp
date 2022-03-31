/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

#include <stdlib.h>
#include <string.h>

static size_t
string_length(char *string)
{
   // TODO(law): Remove dependency on string.h.
   size_t result = strlen(string);
   return result;
}

static bool
strings_are_equal(char *a, char *b)
{
   // TODO(law): Remove dependency on string.h.
   bool result = (strcmp(a, b) == 0);
   return result;
}

static long
string_to_integer_decimal(char *string)
{
   // TODO(law): Remove dependency on stdlib.h.
   long result = strtol(string, 0, 10);
   return result;
}

static bool
is_whitespace(char c)
{
   bool result = (c == ' '  ||
                  c == '\t' ||
                  c == '\n' ||
                  c == '\f' ||
                  c == '\v' ||
                  c == '\r');

   return result;
}

static size_t
format_string_list(char *destination, size_t size, char *format, va_list arguments)
{
   // TODO(law): Remove dependency on stdio.h.

   // TODO(law); vsnprintf() actually returns an int, not a size_t. This can
   // conceivably generate incorrect values on large enough strings. Handle this
   // properly when implementing from scratch.
   size_t result = vsnprintf(destination, size, format, arguments);
   return result;
}

static size_t
format_string(char *destination, size_t size, char *format, ...)
{
   size_t result = 0;

   va_list arguments;
   va_start(arguments, format);
   {
      result = format_string_list(destination, size, format, arguments);
   }
   va_end(arguments);

   return result;
}

static void
zero_memory(void *destination, size_t size)
{
   // TODO(law): Remove dependency on string.h.
   memset(destination, 0, size);
}

static void
memory_copy(void *destination, void *source, size_t size)
{
   // TODO(law): Remove dependency on string.h.
   memcpy(destination, source, size);
}

static void
memory_set(void *destination, size_t size, unsigned char value)
{
   // TODO(law): Remove dependency on string.h.
   memset(destination, value, size);
}

static void
print_bytes(Request_State *request, void *source, size_t size)
{
   unsigned char *bytes = source;
   for(size_t index = 0; index < size; ++index)
   {
      OUT("%02x", bytes[index]);
   }
}

static void
hexadecimal_string_to_bytes(unsigned char *destination, size_t destination_size,
                            char *source, size_t source_size)
{
   assert((source_size & 1) == 0);
   assert((2 * destination_size) >= source_size);

   while(source_size > 0)
   {
      char hex_byte_string[3];
      hex_byte_string[0] = *source++;
      hex_byte_string[1] = *source++;
      hex_byte_string[2] = 0;

      // TODO(law): Remove dependency on stdlib.h.
      *destination++ = strtol(hex_byte_string, 0, 16);

      destination_size -= 1;
      source_size      -= 2;
   }
}

static bool
bytes_are_equal(void *a, void *b, size_t size)
{
   // TODO(law): Remove dependency on string.h.
   bool result = true;

   unsigned char *a_bytes = (unsigned char *)a;
   unsigned char *b_bytes = (unsigned char *)b;

   for(size_t index = 0; index < size; ++index)
   {
      if(a_bytes[index] != b_bytes[index])
      {
         result = false;
         break;
      }
   }

   return result;
}

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
   void *result = 0;

   if(size <= (arena->size - arena->used))
   {
      result = arena->base_address + arena->used;
      arena->used += size;
   }
   else
   {
      // TODO(law): Replace with a growing arena.
      log_message("[WARNING] Arena is full, failed to allocate memory.");
   }

   return result;
}
