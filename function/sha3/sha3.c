#define HSHFUNC_USE_ROTL64 sha3i_rotl

#include "sha3.h"
#include <string.h>
#include "config.h"

typedef hshfunc_u8_t  sha3_byte_t;
typedef hshfunc_u64_t sha3_word_t;

static const sha3_word_t sha3i_RC[24];
static const sha3_byte_t sha3i_rotc[24];
static const sha3_byte_t sha3i_piln[24];

static struct {
    sha3_word_t S[25];
    sha3_byte_t inlen;
    sha3_byte_t input[144];
} sha3i_224_ctx;

static struct {
    sha3_word_t S[25];
    sha3_byte_t inlen;
    sha3_byte_t input[136];
} sha3i_256_ctx;

static struct {
    sha3_word_t S[25];
    sha3_byte_t inlen;
    sha3_byte_t input[104];
} sha3i_384_ctx;

static struct {
    sha3_word_t S[25];
    sha3_byte_t inlen;
    sha3_byte_t input[72];
} sha3i_512_ctx;

typedef struct {
    sha3_word_t S[25];
    sha3_byte_t inlen;
    sha3_byte_t input[8];
} sha3_ctx_t;

static void sha3i_round(sha3_ctx_t* ctx, size_t wcount) {
    sha3_word_t T[5]; size_t r, i, j;

    for (i = 0; i < wcount; i++) {
        T[0] = ((const sha3_word_t*)ctx->input)[i];
        HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64_ONE(T[0]));
        ctx->S[i] ^= T[0];
    }
    memset(ctx->input, 0, sizeof(sha3_word_t) * wcount);
    ctx->inlen = 0;

    for (r = 0; r < 24; r++) {
        for (i = 0; i < 5; i++)
            T[i] = ctx->S[i +  0] ^ ctx->S[i +  5] ^ ctx->S[i + 10]
                 ^ ctx->S[i + 15] ^ ctx->S[i + 20];

        for (i = 0; i < 5; i++) {
            sha3_word_t Tw = T[(i + 4) % 5] ^ sha3i_rotl(T[(i + 1) % 5], 1);
            for (j = 0; j < 5; j++)
                ctx->S[5 * j + i] ^= Tw;
        }

        T[0] = ctx->S[1];
        for (i = 0; i < 24; i++) {
            j = sha3i_piln[i];
            T[1] = ctx->S[j];
            ctx->S[j] = sha3i_rotl(T[0], sha3i_rotc[i]);
            T[0] = T[1];
        }

        for (i = 0; i < 5; i++) {
            for (j = 0; j < 5; j++)
                T[j] = ctx->S[5 * i + j];
            for (j = 0; j < 5; j++)
                ctx->S[5 * i + j] ^= ~T[(j + 1) % 5] & T[(j + 2) % 5];
        }

        ctx->S[0] ^= sha3i_RC[r];
    }
}

void sha3_224_launch(void) { memset(&sha3i_224_ctx, 0, sizeof sha3i_224_ctx); }
void sha3_256_launch(void) { memset(&sha3i_256_ctx, 0, sizeof sha3i_256_ctx); }
void sha3_384_launch(void) { memset(&sha3i_384_ctx, 0, sizeof sha3i_384_ctx); }
void sha3_512_launch(void) { memset(&sha3i_512_ctx, 0, sizeof sha3i_512_ctx); }

#define sha3i_update_template(prefix) \
void sha3_##prefix##_update(const void* data, size_t count) {                       \
    size_t min, remainder;                                                          \
    while (count > 0) {                                                             \
        remainder = sizeof sha3i_##prefix##_ctx.input - sha3i_##prefix##_ctx.inlen; \
        min = count < remainder ? count : remainder;                                \
                                                                                    \
        memcpy(sha3i_##prefix##_ctx.input + sha3i_##prefix##_ctx.inlen, data, min); \
        data = (const sha3_byte_t*)data + min;                                      \
        sha3i_##prefix##_ctx.inlen += min; count -= min;                            \
                                                                                    \
        if (sha3i_##prefix##_ctx.inlen == sizeof sha3i_##prefix##_ctx.input)        \
            sha3i_round((void*)&sha3i_##prefix##_ctx,                               \
                sizeof sha3i_##prefix##_ctx.input / sizeof(sha3_word_t));           \
    }                                                                               \
}

sha3i_update_template(224)
sha3i_update_template(256)
sha3i_update_template(384)
sha3i_update_template(512)

#define sha3i_finish_template(prefix, outbytes) \
void sha3_##prefix##_finish(void* hash) {                                      \
    sha3i_##prefix##_ctx.input[sha3i_##prefix##_ctx.inlen] |= 0x06;            \
    sha3i_##prefix##_ctx.input[sizeof sha3i_##prefix##_ctx.input - 1] |= 0x80; \
    sha3i_round((void*)&sha3i_##prefix##_ctx,                                  \
        sizeof sha3i_##prefix##_ctx.input / sizeof(sha3_word_t));              \
                                                                               \
    HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64x5(sha3i_##prefix##_ctx.S +  0));           \
    HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64x5(sha3i_##prefix##_ctx.S +  5));           \
    HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64x5(sha3i_##prefix##_ctx.S + 10));           \
    HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64x5(sha3i_##prefix##_ctx.S + 15));           \
    HSHFUNC_IF_BIG(HSHFUNC_BSWAP_64x5(sha3i_##prefix##_ctx.S + 20));           \
    memcpy(hash, sha3i_##prefix##_ctx.S, outbytes);                            \
}

sha3i_finish_template(224, SHA3_224_HASH_BYTE)
sha3i_finish_template(256, SHA3_256_HASH_BYTE)
sha3i_finish_template(384, SHA3_384_HASH_BYTE)
sha3i_finish_template(512, SHA3_512_HASH_BYTE)

static const sha3_byte_t sha3i_rotc[24] = {
     1,  3,  6, 10, 15, 21, 28, 36,
    45, 55,  2, 14, 27, 41, 56,  8,
    25, 43, 62, 18, 39, 61, 20, 44
};

static const sha3_byte_t sha3i_piln[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,
     8, 21, 24,  4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9,  6,  1
};

HSHFUNC_U64_WARN_BEGIN
static const sha3_word_t sha3i_RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};
HSHFUNC_U64_WARN_END