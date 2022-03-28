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

static SHA256_Hash
hash_sha256(char *input_string, size_t input_size)
{
   // This implementation is based on the pseudo-code provided on the SHA-2
   // wikipedia page: https://en.wikipedia.org/wiki/SHA-2

   SHA256_Hash result = {0};

   SHA256_State state = {0};
   state.h[0] = 0x6a09e667;
   state.h[1] = 0xbb67ae85;
   state.h[2] = 0x3c6ef372;
   state.h[3] = 0xa54ff53a;
   state.h[4] = 0x510e527f;
   state.h[5] = 0x9b05688c;
   state.h[6] = 0x1f83d9ab;
   state.h[7] = 0x5be0cd19;

   uint64_t input_bit_count = input_size * 8;
   uint64_t remaining_filled_bits = input_bit_count;
   while(remaining_filled_bits >= 512)
   {
      // Each of these iterations consumes a chunk that contains a full 512 bits
      // of message data.
      consume_sha256_chunk(&state, (uint8_t *)input_string);

      remaining_filled_bits -= 512;
      input_string += 64;
   }

   // Assemble and consume final partially-filled chunk(s).
   uint8_t chunk[64] = {0};
   uint64_t byte_index_for_one_bit = input_size % 64;
   if((512 - remaining_filled_bits) < (64 + 1))
   {
      // If there was not at least 65 bits (for the 64-bit size value and the
      // single 1 bit) of unusued space in the first partially-filled chunk,
      // then that chunk is the penultimate chunk. Add the 1 bit to the first
      // unused bit in the penultimate chunk and pad the remaining space
      // (including the final chunk) with 0's.

      // Assemble the penultimate chunk into a local buffer.
      memory_copy(chunk, input_string, byte_index_for_one_bit);
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
      memory_copy(chunk, input_string, byte_index_for_one_bit);
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

   // Format the output bytes into a 65 bit string (including null terminator),
   // using lowercase hexadecimal characters with 0-padding.
   format_string(result.bytes, 65, "%08x%08x%08x%08x%08x%08x%08x%08x",
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

static SHA256_Hash
hash_sha256_string(char *input_string)
{
   SHA256_Hash result = hash_sha256(input_string, string_length(input_string));
   return result;
}

static void
test_hash_sha256(unsigned int run_count)
{
   struct {
      char *input;
      char *output;
   } hashes[] = {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
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
         "340d3d2c6c198112860d0f6ddafe51a17e95c411a11810c0152ef20808dd0e42"}
   };

   for(unsigned int index = 0; index < run_count; ++index) // Basic tress test
   {
      for(unsigned int index = 0; index < ARRAY_LENGTH(hashes); ++index)
      {
         SHA256_Hash hash;

         char *input  = hashes[index].input;
         char *output = hashes[index].output;

         hash = hash_sha256(input, string_length(input));
         assert(strings_are_equal(hash.bytes, output));

         hash = hash_sha256_string(input);
         assert(strings_are_equal(hash.bytes, output));
      }
   }
}
