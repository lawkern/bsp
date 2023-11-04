/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2023 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

static struct
{
   Memory_Arena arena;
   Database_Table users;
} database;

static void
database_initialize_table(Database_Table *result, size_t row_size, char *file_path)
{
   // TODO(law): This structure is mainly for development purposes. I'd like to
   // get away without needing a real database indefinitely.

   zero_memory(result, sizeof(Database_Table));
   result->file_path = file_path;

   result->semaphore = platform_initialize_semaphore();

   result->max_row_count = 10000;
   result->rows = PUSH_SIZE(&database.arena, row_size * result->max_row_count);

   Platform_File disk = platform_read_file(file_path);
   if(disk.memory)
   {
      // TODO(law): Check for file corruption more thoroughly.
      if((disk.size % row_size) == 0)
      {
         size_t database_offset = 0;
         while(database_offset < disk.size)
         {
            unsigned char *source = disk.memory + database_offset;
            unsigned char *destination = (unsigned char *)result->rows + database_offset;
            memory_copy(destination, source, row_size);

            result->row_count++;
            database_offset += row_size;
         }
      }
      else
      {
         platform_log_message("[ERROR] The database table %s was not properly formatted.", file_path);
      }

      platform_free_file(&disk);
   }
   else
   {
      platform_log_message("[WARNING] The database table %s was not found.", file_path);
   }
}

static void
database_initialize(size_t size)
{
   unsigned char *base_address = platform_allocate(size);
   initialize_arena(&database.arena, base_address, size);

   database_initialize_table(&database.users, sizeof(User_Account), "users.dbsp");
}

static void
database_insert_user(char *username,
                     unsigned char *salt,
                     unsigned char *password_hash,
                     unsigned int iteration_count)
{
   // TODO(law): Taking a lock around the entire insertion process for all
   // interactions with the user table is overkill. Determine the best way to
   // handle multiple readers/writers here.

   // TODO(law): Restructure this to use a hash table.

   platform_lock(database.users.semaphore);

   if(database.users.row_count < database.users.max_row_count)
   {
      User_Account *user = (User_Account *)database.users.rows + database.users.row_count++;
      zero_memory(user, sizeof(*user));

      memory_copy(user->username, username, string_length(username));
      memory_copy(user->salt, salt, sizeof(user->salt));
      memory_copy(user->password_hash, password_hash, sizeof(user->password_hash));
      user->iteration_count = iteration_count;

      // Add entry to database.
      platform_append_file(database.users.file_path, user, sizeof(*user));
   }

   platform_unlock(database.users.semaphore);
}

static User_Account
database_get_user_by_username(char *username)
{
   // TODO(law): Taking a lock around the entire lookup process for all
   // interactions with the user table is overkill. Determine the best way to
   // handle multiple readers/writers here.

   // TODO(law): Restructure this to use a hash lookup on the user name.

   User_Account result = {0};

   platform_lock(database.users.semaphore);

   for(unsigned int index = 0; index < database.users.row_count; ++index)
   {
      User_Account *user = (User_Account *)database.users.rows + index;
      if(strings_are_equal(user->username, username))
      {
         result = *user;
         break;
      }
   }

   platform_unlock(database.users.semaphore);

   return result;
}

static User_Account
database_get_user_by_session(char *session_id)
{
   User_Account result = {0};

   // TODO(law): Taking a lock around the entire lookup process for all
   // interactions with the user table is overkill. Determine the best way to
   // handle multiple readers/writers here.

   // TODO(law): Restructure this to use a hash lookup on the username.

   platform_lock(database.users.semaphore);

   for(unsigned int index = 0; index < database.users.row_count; ++index)
   {
      User_Account *user = (User_Account *)database.users.rows + index;
      if(strings_are_equal(user->session_id, session_id))
      {
         result = *user;
         break;
      }
   }

   platform_unlock(database.users.semaphore);

   return result;
}

static void
database_update_user_session_id(char *username, char *session_id)
{
   platform_lock(database.users.semaphore);

   for(unsigned int index = 0; index < database.users.row_count; ++index)
   {
      User_Account *user = (User_Account *)database.users.rows + index;
      if(strings_are_equal(user->username, username))
      {
         memory_copy(user->session_id, session_id, SESSION_ID_LENGTH);
         break;
      }
   }

   platform_unlock(database.users.semaphore);
}
