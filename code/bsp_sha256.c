/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

static uint32_t
rotate_right_32(uint32_t value, uint32_t shift)
{
   ASSERT(shift >= 0);
   ASSERT(shift < 32);

   uint32_t result = value;
   if(shift > 0)
   {
      result = (value >> shift) | (value << (32 - shift));
   }

   return result;
}

static void
consume_sha256_chunk(SHA256_State *state, uint8_t *chunk)
{
   uint32_t w[64] = {0};

   for(unsigned int index = 0; index < 16; ++index)
   {
      w[index] = ((uint32_t)chunk[(sizeof(uint32_t) * index) + 0] << 24 |
                  (uint32_t)chunk[(sizeof(uint32_t) * index) + 1] << 16 |
                  (uint32_t)chunk[(sizeof(uint32_t) * index) + 2] << 8  |
                  (uint32_t)chunk[(sizeof(uint32_t) * index) + 3] << 0);
   }

   for(unsigned int index = 16; index < 64; ++index)
   {
      uint32_t s0 = (rotate_right_32(w[index - 15], 7)  ^
                     rotate_right_32(w[index - 15], 18) ^
                     (w[index - 15] >> 3));

      uint32_t s1 = (rotate_right_32(w[index - 2], 17) ^
                     rotate_right_32(w[index - 2], 19) ^
                     (w[index - 2] >> 10));

      w[index] = w[index - 16] + s0 + w[index - 7] + s1;
   }

   uint32_t a = state->h[0];
   uint32_t b = state->h[1];
   uint32_t c = state->h[2];
   uint32_t d = state->h[3];
   uint32_t e = state->h[4];
   uint32_t f = state->h[5];
   uint32_t g = state->h[6];
   uint32_t h = state->h[7];

   uint32_t k[] =
   {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
   };

   for(unsigned int index = 0; index < 64; ++index)
   {
      uint32_t S1 = (rotate_right_32(e, 6)  ^
                     rotate_right_32(e, 11) ^
                     rotate_right_32(e, 25));

      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t temp1 = h + S1 + ch + k[index] + w[index];

      uint32_t S0 = (rotate_right_32(a, 2)  ^
                     rotate_right_32(a, 13) ^
                     rotate_right_32(a, 22));

      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
   }

   state->h[0] += a;
   state->h[1] += b;
   state->h[2] += c;
   state->h[3] += d;
   state->h[4] += e;
   state->h[5] += f;
   state->h[6] += g;
   state->h[7] += h;
}

static SHA256
hash_sha256(unsigned char *message, size_t message_size)
{
   // This implementation is based on the pseudo-code provided on the SHA-2
   // wikipedia page: https://en.wikipedia.org/wiki/SHA-2

   SHA256 result = {0};

   SHA256_State state = {0};
   state.h[0] = 0x6a09e667;
   state.h[1] = 0xbb67ae85;
   state.h[2] = 0x3c6ef372;
   state.h[3] = 0xa54ff53a;
   state.h[4] = 0x510e527f;
   state.h[5] = 0x9b05688c;
   state.h[6] = 0x1f83d9ab;
   state.h[7] = 0x5be0cd19;

   uint64_t input_bit_count = message_size * 8;
   uint64_t remaining_filled_bits = input_bit_count;
   while(remaining_filled_bits >= 512)
   {
      // Each of these iterations consumes a chunk that contains a full 512 bits
      // of message data.
      consume_sha256_chunk(&state, (uint8_t *)message);

      remaining_filled_bits -= 512;
      message += 64;
   }

   // Assemble and consume final partially-filled chunk(s).
   uint8_t chunk[64] = {0};
   uint64_t byte_index_for_one_bit = message_size % 64;
   if((512 - remaining_filled_bits) < (64 + 1))
   {
      // If there was not at least 65 bits (for the 64-bit size value and the
      // single 1 bit) of unusued space in the first partially-filled chunk,
      // then that chunk is the penultimate chunk. Add the 1 bit to the first
      // unused bit in the penultimate chunk and pad the remaining space
      // (including the final chunk) with 0's.

      // Assemble the penultimate chunk into a local buffer.
      memory_copy(chunk, message, byte_index_for_one_bit);
      chunk[byte_index_for_one_bit] = 0x80; // 0x80 == 0b10000000
      for(uint64_t index = byte_index_for_one_bit + 1; index < 64; ++index)
      {
         chunk[index] = 0;
      }

      // Consume the penultimate chunk.
      consume_sha256_chunk(&state, chunk);

      // Clear the local buffer to zero to process the final chunk.
      zero_memory(chunk, 64);
   }
   else
   {
      // If there was at least 65 bits of unused space in the first
      // partially-filled chunk, then that chunk is the final chunk. Add the 1
      // bit to the first unused bit in the final chunk and pad the remaining
      // space with 0's.

      // Assemble the final chunk into a local buffer.
      memory_copy(chunk, message, byte_index_for_one_bit);
      chunk[byte_index_for_one_bit] = 0x80; // 0x80 == 0b10000000
      for(uint64_t index = (byte_index_for_one_bit + 1); index < 64; ++index)
      {
         chunk[index] = 0;
      }
   }

   // Store the 64 bit value for the initial input size in bits at the end of
   // the final chunk in Big Endian order.
   chunk[56] = (uint8_t)(input_bit_count >> 56);
   chunk[57] = (uint8_t)(input_bit_count >> 48);
   chunk[58] = (uint8_t)(input_bit_count >> 40);
   chunk[59] = (uint8_t)(input_bit_count >> 32);
   chunk[60] = (uint8_t)(input_bit_count >> 24);
   chunk[61] = (uint8_t)(input_bit_count >> 16);
   chunk[62] = (uint8_t)(input_bit_count >> 8);
   chunk[63] = (uint8_t)(input_bit_count >> 0);

   // Consume the final chunk.
   consume_sha256_chunk(&state, chunk);

   // Fill out the output byte array
   for(unsigned int index = 0; index < 8; ++index)
   {
      result.bytes[(4 * index) + 0] = (uint8_t)(state.h[index] >> 24);
      result.bytes[(4 * index) + 1] = (uint8_t)(state.h[index] >> 16);
      result.bytes[(4 * index) + 2] = (uint8_t)(state.h[index] >>  8);
      result.bytes[(4 * index) + 3] = (uint8_t)(state.h[index] >>  0);
   }

   // Format the output bytes into a 65 bit string (including null terminator),
   // using lowercase hexadecimal characters with 0-padding.
   format_string(result.text, 65, "%08x%08x%08x%08x%08x%08x%08x%08x",
                 state.h[0],
                 state.h[1],
                 state.h[2],
                 state.h[3],
                 state.h[4],
                 state.h[5],
                 state.h[6],
                 state.h[7]);

   return result;
}

static SHA256
hash_sha256_string(char *message)
{
   // NOTE(law): This only works on null-terminated C strings. Technically an
   // input message could contain a 0-byte, which would throw off the count of
   // string_length.

   SHA256 result = hash_sha256((unsigned char *)message, string_length(message));
   return result;
}

static SHA256
hmac_sha256(unsigned char *key, size_t key_size,
            unsigned char *message, size_t message_size)
{
   // Implementation based on the description provided by
   // https://datatracker.ietf.org/doc/html/rfc2104

   // Clear to zero to pad out any bytes not supplied by the provided key.
   uint8_t inner_padded_key[64] = {0};
   uint8_t outer_padded_key[64] = {0};

   if(key_size > 64)
   {
      // If the provided key was longer than the block size (64 bytes), then
      // truncate it by using it's hashed value instead.
      SHA256 hash = hash_sha256(key, key_size);

      key = hash.bytes;
      key_size = sizeof(hash.bytes);
   }

   memory_copy(inner_padded_key, key, key_size);
   memory_copy(outer_padded_key, key, key_size);

   for(unsigned int index = 0; index < 64; index++)
   {
      inner_padded_key[index] ^= 0x36;
      outer_padded_key[index] ^= 0x5c;
   }

   // TODO(law): Make this work without requiring an explicit dynamic
   // allocation to hold the inner message.

   // Append message to inner padded key
   size_t inner_message_size = sizeof(inner_padded_key) + message_size;
   unsigned char *inner_message = platform_allocate(inner_message_size);

   memory_copy(inner_message, inner_padded_key, sizeof(inner_padded_key));
   memory_copy(inner_message + sizeof(inner_padded_key), message, message_size);

   SHA256 inner_hash = hash_sha256(inner_message, inner_message_size);
   platform_deallocate(inner_message);

   // Append inner hash to outer padded key
   unsigned char outer_message[sizeof(outer_padded_key) + sizeof(inner_hash.bytes)];

   memory_copy(outer_message, outer_padded_key, sizeof(outer_padded_key));
   memory_copy(outer_message + sizeof(outer_padded_key), inner_hash.bytes, sizeof(inner_hash.bytes));

   SHA256 result = hash_sha256(outer_message, sizeof(outer_message));

   return result;
}

static void
pbkdf2_hmac_sha256(unsigned char *output_key,
                   unsigned int output_key_size,
                   unsigned char *password,
                   size_t password_size,
                   unsigned char *salt,
                   size_t salt_size,
                   unsigned int iteration_count)
{
   // Based on the description of PBKDF2 provided by
   // https://datatracker.ietf.org/doc/html/rfc2898#section-5.2

   // NOTE(law): The block size is assumed to be 32, given that this function is
   // hard-coded to use the 32-bit SHA256 output.
   unsigned int block_count = output_key_size / 32;
   if((output_key_size % 32) != 0)
   {
      block_count++;
   }

   // If the output key size is not evenly divisible by the block size, the
   // final block will not copy the full hash output.
   unsigned int final_block_size = output_key_size - ((block_count - 1) * 32);

   // The iteration starts at one, since the block index is as a part of the
   // initial hash message of each iteration.
   for(unsigned int block_index = 1; block_index <= block_count; ++block_index)
   {
      // The first iteration concatenates the salt with the Big Endian encoding
      // of the 32-bit block index, and then uses that string as the initial
      // hash message.

      // TODO(law): This shouldn't need an allocation given the second part is
      // always 4 bytes. Maybe require the provided salt to include an
      // additional 4 unused bytes at the end?
      size_t u1_size = salt_size + sizeof(unsigned int);
      unsigned char *u1_message = platform_allocate(u1_size);

      memory_copy(u1_message, salt, salt_size);

      // Append the block index in Big Endian order.
      u1_message[salt_size + 0] = (unsigned char)(block_index >> 24);
      u1_message[salt_size + 1] = (unsigned char)(block_index >> 16);
      u1_message[salt_size + 2] = (unsigned char)(block_index >>  8);
      u1_message[salt_size + 3] = (unsigned char)(block_index >>  0);

      // The first hash iteration will be used as an accumulator to xor
      // subsequent hash results.
      SHA256 u1 = hmac_sha256(password, password_size, u1_message, u1_size);

      unsigned char u_message[32] = {0};
      memory_copy(u_message, u1.bytes, sizeof(u1.bytes));

      for(unsigned int index = 2; index <= iteration_count; ++index)
      {
         // Calculate hash using the previous hash result as the message.
         SHA256 u = hmac_sha256(password, password_size, u_message, sizeof(u_message));

         // Accumulate xors into initial hash result.
         for(unsigned int byte_index = 0; byte_index < 32; ++byte_index)
         {
            u1.bytes[byte_index] ^= u.bytes[byte_index];
         }

         // Store the current hash as the message for the next iteration.
         memory_copy(u_message, u.bytes, sizeof(u.bytes));
      }

      // Concatenate the xor'ed result into the output key.
      unsigned char *block_address = output_key + (32 * (block_index - 1));
      if(block_index == block_count)
      {
         memory_copy(block_address, u1.bytes, final_block_size);
      }
      else
      {
         memory_copy(block_address, u1.bytes, 32);
      }

      platform_deallocate(u1_message);
   }
}

static void
test_hash_sha256(unsigned int run_count)
{
   for(unsigned int index = 0; index < run_count; ++index) // Basic stress test
   {
      {
         SHA256 hash;

         unsigned char message_bytes[] = {0};
         unsigned char answer_bytes[] =
         {
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
         };

         char *message_text = "";
         char *answer_text = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

         hash = hash_sha256(message_bytes, 0);
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));

         hash = hash_sha256_string(message_text);
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));
      }
      {
         SHA256 hash;

         unsigned char message_bytes[] = {'a', 'b', 'c'};
         unsigned char answer_bytes[] =
         {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
         };

         char *message_text = "abc";
         char *answer_text = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

         hash = hash_sha256(message_bytes, sizeof(message_bytes));
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));

         hash = hash_sha256_string(message_text);
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));
      }
      {
         SHA256 hash;

         unsigned char message_bytes[] =
         {
            'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e', 'c', 'd',
            'e', 'f', 'd', 'e', 'f', 'g', 'e', 'f', 'g', 'h',
            'f', 'g', 'h', 'i', 'g', 'h', 'i', 'j', 'h', 'i',
            'j', 'k', 'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm',
            'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o', 'm', 'n',
            'o', 'p', 'n', 'o', 'p', 'q',
         };
         unsigned char answer_bytes[] =
         {
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
            0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
            0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
            0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
         };

         char *message_text = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
         char *answer_text = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

         hash = hash_sha256(message_bytes, sizeof(message_bytes));
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));

         hash = hash_sha256_string(message_text);
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));
      }
      {
         SHA256 hash;

         unsigned char message_bytes[] =
         {
            'E', 'v', 'e', 'n', 'i', 'e', 't', ' ', 'a', 'l', 'i', 'a',
            's', ' ', 'a', 'u', 't', ' ', 'e', 't', ' ', 'c', 'o', 'r',
            'r', 'u', 'p', 't', 'i', '.', ' ', 'A', 'c', 'c', 'u', 's',
            'a', 'n', 't', 'i', 'u', 'm', ' ', 'a', 'u', 't', 'e', 'm',
            ' ', 'n', 'o', 's', 't', 'r', 'u', 'm', ' ', 'm', 'a', 'x',
            'i', 'm', 'e', ' ', 'r', 'e', 'p', 'e', 'l', 'l', 'a', 't',
            '.', ' ', 'E', 's', 't', ' ', 'i', 'n', ' ', 'e', 'i', 'u',
            's', ' ', 'q', 'u', 'a', 's', 'i', ' ', 'e', 's', 't', '.',
            ' ', 'E', 'a', ' ', 'a', 's', 'p', 'e', 'r', 'i', 'o', 'r',
            'e', 's', ' ', 'p', 'o', 'r', 'r', 'o', ' ', 'm', 'o', 'l',
            'e', 's', 't', 'i', 'a', 'e', ' ', 'r', 'e', 'p', 'e', 'l',
            'l', 'e', 'n', 'd', 'u', 's', '.', ' ', 'E', 's', 't', ' ',
            'e', 'o', 's', ' ', 'q', 'u', 'i', ' ', 'i', 'l', 'l', 'u',
            'm', '.', ' ', 'A', 's', 'p', 'e', 'r', 'i', 'o', 'r', 'e',
            's', ' ', 'q', 'u', 'o', 'd', ' ', 'd', 'o', 'l', 'o', 'r',
            'e', ' ', 'p', 'l', 'a', 'c', 'e', 'a', 't', ' ', 'e', 'o',
            's', ' ', 'e', 'x', 'p', 'l', 'i', 'c', 'a', 'b', 'o', ' ',
            'e', 'x', 'p', 'e', 'd', 'i', 't', 'a', '.', ' ', 'S', 'o',
            'l', 'u', 't', 'a', ' ', 'n', 'i', 'h', 'i', 'l', ' ', 'v',
            'o', 'l', 'u', 'p', 't', 'a', 't', 'e', 'm', ' ', 's', 'e',
            'd', '.', ' ', 'O', 'm', 'n', 'i', 's', ' ', 'd', 'i', 'c',
            't', 'a', ' ', 'd', 'e', 'l', 'e', 'n', 'i', 't', 'i', ' ',
            'v', 'i', 't', 'a', 'e', ' ', 'p', 'r', 'a', 'e', 's', 'e',
            'n', 't', 'i', 'u', 'm', ' ', 'm', 'o', 'l', 'e', 's', 't',
            'i', 'a', 'e', ' ', 'c', 'o', 'n', 's', 'e', 'q', 'u', 'a',
            't', 'u', 'r', '.', ' ', 'V', 'e', 'l', 'i', 't', ' ', 'e',
            'x', 'p', 'e', 'd', 'i', 't', 'a', ' ', 'c', 'o', 'r', 'p',
            'o', 'r', 'i', 's', ' ', 'e', 'x', '.', ' ', 'P', 'e', 'r',
            'f', 'e', 'r', 'e', 'n', 'd', 'i', 's', ' ', 'e', 'u', 'm',
            ' ', 'n', 'o', 'b', 'i', 's', ' ', 'q', 'u', 'i', ' ', 'a',
            'u', 't', ' ', 'c', 'u', 'm', 'q', 'u', 'e', ' ', 'v', 'o',
            'l', 'u', 'p', 't', 'a', 't', 'e', 's', '.', ' ', 'S', 'i',
            'm', 'i', 'l', 'i', 'q', 'u', 'e', ' ', 'r', 'a', 't', 'i',
            'o', 'n', 'e', ' ', 'p', 'a', 'r', 'i', 'a', 't', 'u', 'r',
            ' ', 'q', 'u', 'i', ' ', 'e', 'x', 'p', 'e', 'd', 'i', 't',
            'a', ' ', 'd', 'e', 'l', 'e', 'n', 'i', 't', 'i', ' ', 'i',
            'l', 'l', 'u', 'm', ' ', 'v', 'o', 'l', 'u', 'p', 't', 'a',
            't', 'e', 'm', '.', ' ', 'Q', 'u', 'i', ' ', 'f', 'a', 'c',
            'i', 'l', 'i', 's', ' ', 'r', 'e', 'r', 'u', 'm', ' ', 'v',
            'o', 'l', 'u', 'p', 't', 'a', 't', 'e', 's', '.', ' ', 'R',
            'e', 'p', 'u', 'd', 'i', 'a', 'n', 'd', 'a', 'e', ' ', 's',
            'u', 's', 'c', 'i', 'p', 'i', 't', ' ', 'a', 'u', 't', ' ',
            'i', 'u', 's', 't', 'o', ' ', 'd', 'e', 'l', 'e', 'n', 'i',
            't', 'i', ' ', 'n', 'o', 'n', ' ', 't', 'o', 't', 'a', 'm',
            '.', ' ', 'S', 'e', 'd', ' ', 'a', ' ', 'a', 'p', 'e', 'r',
            'i', 'a', 'm', ' ', 'f', 'a', 'c', 'e', 'r', 'e', ' ', 'q',
            'u', 'a', 's', 'i', ' ', 'o', 'm', 'n', 'i', 's', ' ', 'f',
            'a', 'c', 'i', 'l', 'i', 's', ' ', 'q', 'u', 'a', 'm', ' ',
            'n', 'o', 'n', '.', ' ', 'Q', 'u', 'i', ' ', 'n', 'e', 'q',
            'u', 'e', ' ', 'q', 'u', 'o', 'd', ' ', 'a', 'u', 't', ' ',
            'o', 'f', 'f', 'i', 'c', 'i', 'i', 's', ' ', 'm', 'i', 'n',
            'i', 'm', 'a', ' ', 'v', 'o', 'l', 'u', 'p', 't', 'a', 's',
            '.', ' ', 'P', 'a', 'r', 'i', 'a', 't', 'u', 'r', ' ', 'o',
            'c', 'c', 'a', 'e', 'c', 'a', 't', 'i', ' ', 'v', 'o', 'l',
            'u', 'p', 't', 'a', 's', ' ', 'e', 's', 's', 'e', ' ', 'v',
            'o', 'l', 'u', 'p', 't', 'a', 's', '.', ' ', 'C', 'o', 'm',
            'm', 'o', 'd', 'i', ' ', 'r', 'e', 'p', 'e', 'l', 'l', 'a',
            't', ' ', 'o', 'p', 't', 'i', 'o', ' ', 'e', 't', ' ', 'v',
            'o', 'l', 'u', 'p', 't', 'a', 't', 'e', 'm', ' ', 'r', 'e',
            'i', 'c', 'i', 'e', 'n', 'd', 'i', 's', ' ', 'd', 'o', 'l',
            'o', 'r', 'u', 'm', '.', ' ', 'Q', 'u', 'a', 'm', ' ', 'd',
            'o', 'l', 'o', 'r', 'u', 'm', ' ', 's', 'i', 'n', 't', ' ',
            'e', 'i', 'u', 's', '.', ' ', 'Q', 'u', 'o', ' ', 'v', 'o',
            'l', 'u', 'p', 't', 'a', 's', ' ', 'a', 'd', ' ', 'e', 'o',
            's', ' ', 'd', 'i', 'g', 'n', 'i', 's', 's', 'i', 'm', 'o',
            's', ' ', 'i', 'n', 'v', 'e', 'n', 't', 'o', 'r', 'e', ' ',
            'q', 'u', 'i', ' ', 'l', 'i', 'b', 'e', 'r', 'o', '.', ' ',
            'N', 'i', 'h', 'i', 'l', ' ', 'r', 'e', 'p', 'e', 'l', 'l',
            'a', 't', ' ', 'o', 'm', 'n', 'i', 's', ' ', 'i', 'l', 'l',
            'u', 'm', '.', ' ', 'E', 'u', 'm', ' ', 'v', 'o', 'l', 'u',
            'p', 't', 'a', 's', ' ', 'v', 'o', 'l', 'u', 'p', 't', 'a',
            's', ' ', 'v', 'e', 'l', ' ', 's', 'e', 'q', 'u', 'i', ' ',
            's', 'e', 'd', ' ', 'r', 'e', 'i', 'c', 'i', 'e', 'n', 'd',
            'i', 's', '.', ' ', 'D', 'o', 'l', 'o', 'r', 'i', 'b', 'u',
            's', ' ', 'e', 's', 't', ' ', 'a', 'm', 'e', 't', ' ', 'a',
            'n', 'i', 'm', 'i', ' ', 'h', 'i', 'c', '.',
         };
         unsigned char answer_bytes[] =
         {
            0x34, 0x0d, 0x3d, 0x2c, 0x6c, 0x19, 0x81, 0x12,
            0x86, 0x0d, 0x0f, 0x6d, 0xda, 0xfe, 0x51, 0xa1,
            0x7e, 0x95, 0xc4, 0x11, 0xa1, 0x18, 0x10, 0xc0,
            0x15, 0x2e, 0xf2, 0x08, 0x08, 0xdd, 0x0e, 0x42,
         };

         char *message_text =
         "Eveniet alias aut et corrupti. Accusantium autem nostrum maxime repellat."
         " Est in eius quasi est. Ea asperiores porro molestiae repellendus. Est "
         "eos qui illum. Asperiores quod dolore placeat eos explicabo expedita. "
         "Soluta nihil voluptatem sed. Omnis dicta deleniti vitae praesentium "
         "molestiae consequatur. Velit expedita corporis ex. Perferendis eum nobis "
         "qui aut cumque voluptates. Similique ratione pariatur qui expedita "
         "deleniti illum voluptatem. Qui facilis rerum voluptates. Repudiandae "
         "suscipit aut iusto deleniti non totam. Sed a aperiam facere quasi omnis "
         "facilis quam non. Qui neque quod aut officiis minima voluptas. Pariatur "
         "occaecati voluptas esse voluptas. Commodi repellat optio et voluptatem "
         "reiciendis dolorum. Quam dolorum sint eius. Quo voluptas ad eos "
         "dignissimos inventore qui libero. Nihil repellat omnis illum. Eum "
         "voluptas voluptas vel sequi sed reiciendis. Doloribus est amet animi hic.";

         char *answer_text = "340d3d2c6c198112860d0f6ddafe51a17e95c411a11810c0152ef20808dd0e42";

         hash = hash_sha256(message_bytes, sizeof(message_bytes));
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));

         hash = hash_sha256_string(message_text);
         ASSERT(bytes_are_equal(hash.bytes, answer_bytes, sizeof(hash.bytes)));
         ASSERT(strings_are_equal(hash.text, answer_text));

      }
   }
}

#define TEST_HMAC_SHA256()                                                    \
   SHA256 hash = hmac_sha256(key, sizeof(key), message, sizeof(message));     \
   ASSERT(bytes_are_equal(hash.bytes, correct_bytes, sizeof(correct_bytes))); \
   ASSERT(bytes_are_equal(hash.text, correct_text, string_length(correct_text)))

static void
test_hmac_sha256(unsigned int run_count)
{
   // Test values taken from https://www.rfc-editor.org/rfc/rfc4231

   for(unsigned int index = 0; index < run_count; ++index) // Basic stress testing
   {
      // Test 1
      {
         unsigned char key[] =
         {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
         };
         unsigned char message[] =
         {
            // "Hi There"
            0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65,
         };
         unsigned char correct_bytes[] =
         {
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
         };
         char *correct_text =
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

         TEST_HMAC_SHA256();
      }

      // Test 2
      {
         unsigned char key[] = {0x4a, 0x65, 0x66, 0x65,}; // "Jefe"
         unsigned char message[] =
         {
            // "what do ya want for nothing?"
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f,
            0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e,
            0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
         };
         unsigned char correct_bytes[] =
         {
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
         };
         char *correct_text =
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

         TEST_HMAC_SHA256();
      }

      // Test 3
      {
         unsigned char key[] =
         {
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
         };
         unsigned char message[] =
         {
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
         };
         unsigned char correct_bytes[] =
         {
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
            0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
            0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
            0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
         };
         char *correct_text =
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

         TEST_HMAC_SHA256();
      }

      // Test 4
      {
         unsigned char key[] =
         {
            0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19,
         };
         unsigned char message[] =
         {
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
         };
         unsigned char correct_bytes[] =
         {
            0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
            0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
            0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
            0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
         };
         char *correct_text =
         "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

         TEST_HMAC_SHA256();
      }

      // Test 5
      {
         unsigned char key[] =
         {
            0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
            0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
         };
         unsigned char message[] =
         {
            // "Test With Truncation"
            0x54, 0x65, 0x73, 0x74, 0x20, 0x57, 0x69, 0x74, 0x68, 0x20,
            0x54, 0x72, 0x75, 0x6e, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
         };
         unsigned char correct_bytes[] =
         {
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0,
            0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b,
         };
         char *correct_text = "a3b6167473100ee06e0c796c2955552b";

         TEST_HMAC_SHA256();
      }

      // Test 6
      {
         unsigned char key[] =
         {
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa,
         };
         unsigned char message[] =
         {
            // "Test Using Larger Than Block-Size Key - Hash Key First"
            0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67,
            0x20, 0x4c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68,
            0x61, 0x6e, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53,
            0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x2d, 0x20,
            0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x46,
            0x69, 0x72, 0x73, 0x74,
         };
         unsigned char correct_bytes[] =
         {
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
            0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
            0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
            0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
         };
         char *correct_text =
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

         TEST_HMAC_SHA256();
      }

      // Test 7
      {
         unsigned char key[] =
         {
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa,
         };
         unsigned char message[] =
         {
            // "This is a test using a larger than block-size key and a larger
            // than block-size data. The key needs to be hashed before being
            // used by the HMAC algorithm."

            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20,
            0x74, 0x65, 0x73, 0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67,
            0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20,
            0x74, 0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
            0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20,
            0x61, 0x6e, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67,
            0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c,
            0x6f, 0x63, 0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64,
            0x61, 0x74, 0x61, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6b,
            0x65, 0x79, 0x20, 0x6e, 0x65, 0x65, 0x64, 0x73, 0x20, 0x74,
            0x6f, 0x20, 0x62, 0x65, 0x20, 0x68, 0x61, 0x73, 0x68, 0x65,
            0x64, 0x20, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62,
            0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20,
            0x62, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x48, 0x4d, 0x41,
            0x43, 0x20, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
            0x6d, 0x2e,
         };
         unsigned char correct_bytes[] =
         {
            0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
            0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
            0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
            0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
         };
         char *correct_text =
         "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

         TEST_HMAC_SHA256();
      }
   }
}

static void
test_pbkdf2_hmac_sha256(unsigned int run_count)
{
   // Test values taken from top rated answer at
   // https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors

   for(unsigned int index = 0; index < run_count; ++index)
   {
      {
         unsigned char key[32];
         unsigned char password[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
         unsigned char salt[] = {'s', 'a', 'l', 't'};
         unsigned char answer1[] =
         {
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
            0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
            0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
            0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
         };

         pbkdf2_hmac_sha256(key, sizeof(key), password, sizeof(password), salt, sizeof(salt), 1);
         ASSERT(bytes_are_equal(key, answer1, sizeof(key)));

         unsigned char answer2[] =
         {
            0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
            0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
            0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
            0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43,
         };

         pbkdf2_hmac_sha256(key, sizeof(key), password, sizeof(password), salt, sizeof(salt), 2);
         ASSERT(bytes_are_equal(key, answer2, sizeof(key)));

         unsigned char answer3[] =
         {
            0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
            0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
            0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
            0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
         };

         pbkdf2_hmac_sha256(key, sizeof(key), password, sizeof(password), salt, sizeof(salt), 4096);
         ASSERT(bytes_are_equal(key, answer3, sizeof(key)));
      }
      {
         unsigned char key[40];
         unsigned char password[] =
         {
            'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
            'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
            'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
         };
         unsigned char salt[] =
         {
            's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
            's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
            's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
            's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
            's', 'a', 'l', 't',
         };
         unsigned char answer[] =
         {
            0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8,
            0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf, 0x2b, 0x17, 0x34, 0x7e,
            0xbc, 0x18, 0x00, 0x18, 0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd,
            0x53, 0xe1, 0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9,
         };

         pbkdf2_hmac_sha256(key, sizeof(key), password, sizeof(password), salt, sizeof(salt), 4096);
         ASSERT(bytes_are_equal(key, answer, sizeof(key)));
      }
      {
         unsigned char key[16];
         unsigned char password[] = {'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd'};
         unsigned char salt[] = {'s', 'a', 0, 'l', 't'};
         unsigned char answer[] =
         {
            0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89,
            0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87,
         };

         pbkdf2_hmac_sha256(key, sizeof(key), password, sizeof(password), salt, sizeof(salt), 4096);
         ASSERT(bytes_are_equal(key, answer, sizeof(key)));
      }
   }
}
