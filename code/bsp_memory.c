/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

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

static void
memory_copy(void *destination, void *source, size_t size)
{
   // TODO(law): Remove dependency on string.h.
   memcpy(destination, source, size);
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
   // TODO(law): Replace with a growing arena.
   assert(size <= (arena->size - arena->used));

   void *result = arena->base_address + arena->used;
   arena->used += size;

   return result;
}
