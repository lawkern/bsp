/* /////////////////////////////////////////////////////////////////////////// */
/* (c) copyright 2022 Lawrence D. Kern /////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */

static uint32_t
rotate_right_32(uint32_t value, uint32_t shift)
{
   assert(shift >= 0);
   assert(shift < 32);

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
      for(unsigned int index = byte_index_for_one_bit + 1; index < 64; ++index)
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
      for(unsigned int index = (byte_index_for_one_bit + 1); index < 64; ++index)
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
   unsigned char *inner_message = allocate(inner_message_size);

   memory_copy(inner_message, inner_padded_key, sizeof(inner_padded_key));
   memory_copy(inner_message + sizeof(inner_padded_key), message, message_size);

   SHA256 inner_hash = hash_sha256(inner_message, inner_message_size);
   deallocate(inner_message);

   // Append inner hash to outer padded key
   unsigned char outer_message[sizeof(outer_padded_key) + sizeof(inner_hash.bytes)];

   memory_copy(outer_message, outer_padded_key, sizeof(outer_padded_key));
   memory_copy(outer_message + sizeof(outer_padded_key), inner_hash.bytes, sizeof(inner_hash.bytes));

   SHA256 result = hash_sha256(outer_message, sizeof(outer_message));

   return result;
}

static void
test_hash_sha256(unsigned int run_count)
{
   // TODO(law): Add tests to validate the resulting byte array, not just the
   // string (there are some in test_hmac_sha256(), but this function can be
   // expanded too).

   struct {
      char *input;
      char *output;
   } hashes[] = {
      {
         "",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      {
         "abc",
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      },
      {
         "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
      },
      {
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
         "voluptas voluptas vel sequi sed reiciendis. Doloribus est amet animi hic.",
         "340d3d2c6c198112860d0f6ddafe51a17e95c411a11810c0152ef20808dd0e42"
      },
   };

   for(unsigned int index = 0; index < run_count; ++index) // Basic tress test
   {
      for(unsigned int index = 0; index < ARRAY_LENGTH(hashes); ++index)
      {
         SHA256 hash;

         char *input  = hashes[index].input;
         char *output = hashes[index].output;

         hash = hash_sha256((unsigned char *)input, string_length(input));
         assert(strings_are_equal(hash.text, output));

         hash = hash_sha256_string(input);
         assert(strings_are_equal(hash.text, output));
      }
   }
}

#define TEST_HMAC_SHA256()                                                    \
   SHA256 hash = hmac_sha256(key, sizeof(key), message, sizeof(message));     \
   assert(bytes_are_equal(hash.bytes, correct_bytes, sizeof(correct_bytes))); \
   assert(bytes_are_equal(hash.text, correct_text, string_length(correct_text)))

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
