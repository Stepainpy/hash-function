#define HSHFUNC_USE_ROTR64 blake2bi_rotr

#include "blake2b.h"
#include <string.h>
#include "config.h"

typedef hshfunc_u8_t  blake2b_byte_t;
typedef hshfunc_u64_t blake2b_word_t;

static const blake2b_byte_t blake2bi_sigma[10][16];
static const blake2b_word_t blake2bi_IV[8];

static struct {
    blake2b_word_t H[8];
    blake2b_word_t lenlo;
    blake2b_word_t lenup;
    blake2b_byte_t input[128];
    blake2b_byte_t inlen;
} blake2bi_ctx;

#define blake2bi_G(V, a, b, c, d, X, Y) do { \
    V[a] += V[b] + X; V[d] = blake2bi_rotr(V[d] ^ V[a], 32); \
    V[c] += V[d];     V[b] = blake2bi_rotr(V[b] ^ V[c], 24); \
    V[a] += V[b] + Y; V[d] = blake2bi_rotr(V[d] ^ V[a], 16); \
    V[c] += V[d];     V[b] = blake2bi_rotr(V[b] ^ V[c], 63); \
} while (0)

static void blake2bi_round(int islast) {
    blake2b_word_t V[16], M[16];
    blake2b_byte_t s[16]; int i;

    memcpy(M, blake2bi_ctx.input, sizeof blake2bi_ctx.input);
    HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64x16(M));

    memcpy(V + 0, blake2bi_ctx.H, sizeof blake2bi_ctx.H);
    memcpy(V + 8, blake2bi_IV   , sizeof blake2bi_IV   );

    V[12] ^= blake2bi_ctx.lenlo;
    V[13] ^= blake2bi_ctx.lenup;

    if (islast) V[14] = ~V[14];

    for (i = 0; i < 12; i++) {
        memcpy(s, blake2bi_sigma[i % 10], sizeof s);
        blake2bi_G(V, 0, 4,  8, 12, M[s[ 0]], M[s[ 1]]);
        blake2bi_G(V, 1, 5,  9, 13, M[s[ 2]], M[s[ 3]]);
        blake2bi_G(V, 2, 6, 10, 14, M[s[ 4]], M[s[ 5]]);
        blake2bi_G(V, 3, 7, 11, 15, M[s[ 6]], M[s[ 7]]);
        blake2bi_G(V, 0, 5, 10, 15, M[s[ 8]], M[s[ 9]]);
        blake2bi_G(V, 1, 6, 11, 12, M[s[10]], M[s[11]]);
        blake2bi_G(V, 2, 7,  8, 13, M[s[12]], M[s[13]]);
        blake2bi_G(V, 3, 4,  9, 14, M[s[14]], M[s[15]]);
    }

    for (i = 0; i < 8; i++)
        blake2bi_ctx.H[i] ^= V[i] ^ V[i + 8];

    memset(blake2bi_ctx.input, 0, sizeof blake2bi_ctx.input);
    blake2bi_ctx.inlen = 0;
}

int blake2b_launch(const void* salt, size_t size) {
    if (size > BLAKE2B_SALT_BYTE) return 1;

    memset(&blake2bi_ctx, 0, sizeof blake2bi_ctx);
    memcpy(blake2bi_ctx.H, blake2bi_IV, sizeof blake2bi_IV);
    blake2bi_ctx.H[0] ^= 0x01010000 ^ (size << 8) ^ 64;

    if (size > 0) {
        memcpy(blake2bi_ctx.input, salt, size);
        blake2bi_ctx.lenlo += sizeof blake2bi_ctx.input;
        blake2bi_round(0);
    }

    return 0;
}

void blake2b_update(const void* data, size_t count) {
    size_t min, remainder; blake2b_word_t prev;
    while (count > 0) {
        remainder = sizeof blake2bi_ctx.input - blake2bi_ctx.inlen;
        min = count < remainder ? count : remainder;

        memcpy(blake2bi_ctx.input + blake2bi_ctx.inlen, data, min);
        data = (const blake2b_byte_t*)data + min;
        blake2bi_ctx.inlen += min; count -= min;

        prev = blake2bi_ctx.lenlo; blake2bi_ctx.lenlo += min;
        if (blake2bi_ctx.lenlo < prev) ++blake2bi_ctx.lenup;

        if (blake2bi_ctx.inlen == sizeof blake2bi_ctx.input)
            blake2bi_round(0);
    }
}

void blake2b_finish(void* hash) {
    blake2bi_round(1);
    HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64x8(blake2bi_ctx.H));
    memcpy(hash, blake2bi_ctx.H, BLAKE2B_HASH_BYTE);
}

static const blake2b_byte_t blake2bi_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

HSHFUNC_U64_WARN_BEGIN
static const blake2b_word_t blake2bi_IV[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};
HSHFUNC_U64_WARN_END