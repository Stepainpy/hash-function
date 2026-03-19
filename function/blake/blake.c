#define HSHFUNC_USE_ROTR32 blakei_rotr32
#define HSHFUNC_USE_ROTR64 blakei_rotr64

#include "blake.h"
#include <string.h>
#include "config.h"

typedef hshfunc_u8_t  blake_byte_t;
typedef hshfunc_u32_t blake_sword_t;
typedef hshfunc_u64_t blake_dword_t;

static const blake_byte_t blakei_sigma[10][16];
static const blake_sword_t blakei_C_32[16];
static const blake_dword_t blakei_C_64[16];

typedef struct {
    blake_sword_t H[8];
    blake_sword_t S[4];
    blake_sword_t lenlo;
    blake_sword_t lenup;
    blake_byte_t input[64];
    blake_byte_t inlen;
} blake_sctx_t;

typedef struct {
    blake_dword_t H[8];
    blake_dword_t S[4];
    blake_dword_t lenlo;
    blake_dword_t lenup;
    blake_byte_t input[128];
    blake_byte_t inlen;
} blake_dctx_t;

static blake_sctx_t blakei_224_ctx;
static blake_sctx_t blakei_256_ctx;
static blake_dctx_t blakei_384_ctx;
static blake_dctx_t blakei_512_ctx;

#define blakei_G_32(V, M, r, i, a, b, c, d) do { \
    blake_sword_t MC1 = M[blakei_sigma[r%10][2*i+0]] ^ blakei_C_32[blakei_sigma[r%10][2*i+1]]; \
    blake_sword_t MC2 = M[blakei_sigma[r%10][2*i+1]] ^ blakei_C_32[blakei_sigma[r%10][2*i+0]]; \
    V[a] += V[b] + MC1; V[d] = blakei_rotr32(V[d] ^ V[a], 16); \
    V[c] += V[d];       V[b] = blakei_rotr32(V[b] ^ V[c], 12); \
    V[a] += V[b] + MC2; V[d] = blakei_rotr32(V[d] ^ V[a],  8); \
    V[c] += V[d];       V[b] = blakei_rotr32(V[b] ^ V[c],  7); \
} while (0)

static void blakei_sround(blake_sctx_t* ctx) {
    blake_sword_t V[16], M[16]; int i;

    memcpy(M, ctx->input, sizeof ctx->input);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32x16(M));

    memcpy(V + 0, ctx->H, sizeof ctx->H);
    memcpy(V + 8, ctx->S, sizeof ctx->S);
    V[12] = V[13] = ctx->lenlo;
    V[14] = V[15] = ctx->lenup;
    for (i = 0; i < 8; i++) V[i + 8] ^= blakei_C_32[i];

    for (i = 0; i < 14; i++) {
        blakei_G_32(V, M, i, 0, 0, 4,  8, 12);
        blakei_G_32(V, M, i, 1, 1, 5,  9, 13);
        blakei_G_32(V, M, i, 2, 2, 6, 10, 14);
        blakei_G_32(V, M, i, 3, 3, 7, 11, 15);
        blakei_G_32(V, M, i, 4, 0, 5, 10, 15);
        blakei_G_32(V, M, i, 5, 1, 6, 11, 12);
        blakei_G_32(V, M, i, 6, 2, 7,  8, 13);
        blakei_G_32(V, M, i, 7, 3, 4,  9, 14);
    }

    for (i = 0; i < 8; i++)
        ctx->H[i] ^= ctx->S[i & 3] ^ V[i] ^ V[i + 8];

    memset(ctx->input, 0, sizeof ctx->input);
    ctx->inlen = 0;
}

#define blakei_G_64(V, M, r, i, a, b, c, d) do { \
    blake_dword_t MC1 = M[blakei_sigma[r%10][2*i+0]] ^ blakei_C_64[blakei_sigma[r%10][2*i+1]]; \
    blake_dword_t MC2 = M[blakei_sigma[r%10][2*i+1]] ^ blakei_C_64[blakei_sigma[r%10][2*i+0]]; \
    V[a] += V[b] + MC1; V[d] = blakei_rotr64(V[d] ^ V[a], 32); \
    V[c] += V[d];       V[b] = blakei_rotr64(V[b] ^ V[c], 25); \
    V[a] += V[b] + MC2; V[d] = blakei_rotr64(V[d] ^ V[a], 16); \
    V[c] += V[d];       V[b] = blakei_rotr64(V[b] ^ V[c], 11); \
} while (0)

static void blakei_dround(blake_dctx_t* ctx) {
    blake_dword_t V[16], M[16]; int i;

    memcpy(M, ctx->input, sizeof ctx->input);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64x16(M));

    memcpy(V + 0, ctx->H, sizeof ctx->H);
    memcpy(V + 8, ctx->S, sizeof ctx->S);
    V[12] = V[13] = ctx->lenlo;
    V[14] = V[15] = ctx->lenup;
    for (i = 0; i < 8; i++) V[i + 8] ^= blakei_C_64[i];

    for (i = 0; i < 16; i++) {
        blakei_G_64(V, M, i, 0, 0, 4,  8, 12);
        blakei_G_64(V, M, i, 1, 1, 5,  9, 13);
        blakei_G_64(V, M, i, 2, 2, 6, 10, 14);
        blakei_G_64(V, M, i, 3, 3, 7, 11, 15);
        blakei_G_64(V, M, i, 4, 0, 5, 10, 15);
        blakei_G_64(V, M, i, 5, 1, 6, 11, 12);
        blakei_G_64(V, M, i, 6, 2, 7,  8, 13);
        blakei_G_64(V, M, i, 7, 3, 4,  9, 14);
    }

    for (i = 0; i < 8; i++)
        ctx->H[i] ^= ctx->S[i & 3] ^ V[i] ^ V[i + 8];

    memset(ctx->input, 0, sizeof ctx->input);
    ctx->inlen = 0;
}

/* -------------------------------------------------------------------------- */

int blake_224_launch(const void* salt, size_t size) {
    if (size != BLAKE_224_SALT_BYTE) return 1;

    memset(&blakei_224_ctx, 0, sizeof blakei_224_ctx);
    memcpy(blakei_224_ctx.S, salt, BLAKE_224_SALT_BYTE);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32x4(blakei_224_ctx.S));

    blakei_224_ctx.H[0] = 0xc1059ed8; blakei_224_ctx.H[1] = 0x367cd507;
    blakei_224_ctx.H[2] = 0x3070dd17; blakei_224_ctx.H[3] = 0xf70e5939;
    blakei_224_ctx.H[4] = 0xffc00b31; blakei_224_ctx.H[5] = 0x68581511;
    blakei_224_ctx.H[6] = 0x64f98fa7; blakei_224_ctx.H[7] = 0xbefa4fa4;

    return 0;
}

void blake_224_update(const void* data, size_t count) {
    size_t min, remainder; blake_sword_t prev;
    while (count > 0) {
        remainder = sizeof blakei_224_ctx.input - blakei_224_ctx.inlen;
        min = count < remainder ? count : remainder;

        memcpy(blakei_224_ctx.input + blakei_224_ctx.inlen, data, min);
        data = (const blake_byte_t*)data + min;
        blakei_224_ctx.inlen += min; count -= min;

        prev = blakei_224_ctx.lenlo;
        blakei_224_ctx.lenlo += min * 8;
        if (blakei_224_ctx.lenlo < prev) ++blakei_224_ctx.lenup;

        if (blakei_224_ctx.inlen == sizeof blakei_224_ctx.input)
            blakei_sround(&blakei_224_ctx);
    }
}

void blake_224_finish(void* hash) {
    blakei_224_ctx.input[blakei_224_ctx.inlen++] = 0x80;
    if (blakei_224_ctx.inlen > 56) blakei_sround(&blakei_224_ctx);

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32_TWO(blakei_224_ctx.lenlo, blakei_224_ctx.lenup));
    memcpy(blakei_224_ctx.input + 56, &blakei_224_ctx.lenup, sizeof(blake_sword_t));
    memcpy(blakei_224_ctx.input + 60, &blakei_224_ctx.lenlo, sizeof(blake_sword_t));
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32_TWO(blakei_224_ctx.lenlo, blakei_224_ctx.lenup));
    blakei_sround(&blakei_224_ctx);

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32x8(blakei_224_ctx.H));
    memcpy(hash, blakei_224_ctx.H, BLAKE_224_HASH_BYTE);
}

int blake_256_launch(const void* salt, size_t size) {
    if (size != BLAKE_256_SALT_BYTE) return 1;

    memset(&blakei_256_ctx, 0, sizeof blakei_256_ctx);
    memcpy(blakei_256_ctx.S, salt, BLAKE_256_SALT_BYTE);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32x4(blakei_256_ctx.S));

    blakei_256_ctx.H[0] = 0x6a09e667; blakei_256_ctx.H[1] = 0xbb67ae85;
    blakei_256_ctx.H[2] = 0x3c6ef372; blakei_256_ctx.H[3] = 0xa54ff53a;
    blakei_256_ctx.H[4] = 0x510e527f; blakei_256_ctx.H[5] = 0x9b05688c;
    blakei_256_ctx.H[6] = 0x1f83d9ab; blakei_256_ctx.H[7] = 0x5be0cd19;

    return 0;
}

void blake_256_update(const void* data, size_t count) {
    size_t min, remainder; blake_sword_t prev;
    while (count > 0) {
        remainder = sizeof blakei_256_ctx.input - blakei_256_ctx.inlen;
        min = count < remainder ? count : remainder;

        memcpy(blakei_256_ctx.input + blakei_256_ctx.inlen, data, min);
        data = (const blake_byte_t*)data + min;
        blakei_256_ctx.inlen += min; count -= min;

        prev = blakei_256_ctx.lenlo;
        blakei_256_ctx.lenlo += min * 8;
        if (blakei_256_ctx.lenlo < prev) ++blakei_256_ctx.lenup;

        if (blakei_256_ctx.inlen == sizeof blakei_256_ctx.input)
            blakei_sround(&blakei_256_ctx);
    }
}

void blake_256_finish(void* hash) {
    blakei_256_ctx.input[blakei_256_ctx.inlen++] = 0x80;
    if (blakei_256_ctx.inlen > 56) blakei_sround(&blakei_256_ctx);
    blakei_256_ctx.input[55] |= 0x01;

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32_TWO(blakei_256_ctx.lenlo, blakei_256_ctx.lenup));
    memcpy(blakei_256_ctx.input + 56, &blakei_256_ctx.lenup, sizeof(blake_sword_t));
    memcpy(blakei_256_ctx.input + 60, &blakei_256_ctx.lenlo, sizeof(blake_sword_t));
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32_TWO(blakei_256_ctx.lenlo, blakei_256_ctx.lenup));
    blakei_sround(&blakei_256_ctx);

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32x8(blakei_256_ctx.H));
    memcpy(hash, blakei_256_ctx.H, BLAKE_256_HASH_BYTE);
}

/* -------------------------------------------------------------------------- */

int blake_384_launch(const void* salt, size_t size) {
    if (size != BLAKE_384_SALT_BYTE) return 1;

    memset(&blakei_384_ctx, 0, sizeof blakei_384_ctx);
    memcpy(blakei_384_ctx.S, salt, BLAKE_384_SALT_BYTE);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64x4(blakei_384_ctx.S));

    HSHFUNC_U64_WARN_BEGIN
    blakei_384_ctx.H[0] = 0xcbbb9d5dc1059ed8; blakei_384_ctx.H[1] = 0x629a292a367cd507;
    blakei_384_ctx.H[2] = 0x9159015a3070dd17; blakei_384_ctx.H[3] = 0x152fecd8f70e5939;
    blakei_384_ctx.H[4] = 0x67332667ffc00b31; blakei_384_ctx.H[5] = 0x8eb44a8768581511;
    blakei_384_ctx.H[6] = 0xdb0c2e0d64f98fa7; blakei_384_ctx.H[7] = 0x47b5481dbefa4fa4;
    HSHFUNC_U64_WARN_END

    return 0;
}

void blake_384_update(const void* data, size_t count) {
    size_t min, remainder; blake_dword_t prev;
    while (count > 0) {
        remainder = sizeof blakei_384_ctx.input - blakei_384_ctx.inlen;
        min = count < remainder ? count : remainder;

        memcpy(blakei_384_ctx.input + blakei_384_ctx.inlen, data, min);
        data = (const blake_byte_t*)data + min;
        blakei_384_ctx.inlen += min; count -= min;

        prev = blakei_384_ctx.lenlo;
        blakei_384_ctx.lenlo += min * 8;
        if (blakei_384_ctx.lenlo < prev) ++blakei_384_ctx.lenup;

        if (blakei_384_ctx.inlen == sizeof blakei_384_ctx.input)
            blakei_dround(&blakei_384_ctx);
    }
}

void blake_384_finish(void* hash) {
    blakei_384_ctx.input[blakei_384_ctx.inlen++] = 0x80;
    if (blakei_384_ctx.inlen > 112) blakei_dround(&blakei_384_ctx);

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64_TWO(blakei_384_ctx.lenlo, blakei_384_ctx.lenup));
    memcpy(blakei_384_ctx.input + 112, &blakei_384_ctx.lenup, sizeof(blake_dword_t));
    memcpy(blakei_384_ctx.input + 120, &blakei_384_ctx.lenlo, sizeof(blake_dword_t));
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64_TWO(blakei_384_ctx.lenlo, blakei_384_ctx.lenup));
    blakei_dround(&blakei_384_ctx);

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64x8(blakei_384_ctx.H));
    memcpy(hash, blakei_384_ctx.H, BLAKE_384_HASH_BYTE);
}

int blake_512_launch(const void* salt, size_t size) {
    if (size != BLAKE_512_SALT_BYTE) return 1;

    memset(&blakei_512_ctx, 0, sizeof blakei_512_ctx);
    memcpy(blakei_512_ctx.S, salt, BLAKE_512_SALT_BYTE);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64x4(blakei_512_ctx.S));

    HSHFUNC_U64_WARN_BEGIN
    blakei_512_ctx.H[0] = 0x6a09e667f3bcc908; blakei_512_ctx.H[1] = 0xbb67ae8584caa73b;
    blakei_512_ctx.H[2] = 0x3c6ef372fe94f82b; blakei_512_ctx.H[3] = 0xa54ff53a5f1d36f1;
    blakei_512_ctx.H[4] = 0x510e527fade682d1; blakei_512_ctx.H[5] = 0x9b05688c2b3e6c1f;
    blakei_512_ctx.H[6] = 0x1f83d9abfb41bd6b; blakei_512_ctx.H[7] = 0x5be0cd19137e2179;
    HSHFUNC_U64_WARN_END

    return 0;
}

void blake_512_update(const void* data, size_t count) {
    size_t min, remainder; blake_dword_t prev;
    while (count > 0) {
        remainder = sizeof blakei_512_ctx.input - blakei_512_ctx.inlen;
        min = count < remainder ? count : remainder;

        memcpy(blakei_512_ctx.input + blakei_512_ctx.inlen, data, min);
        data = (const blake_byte_t*)data + min;
        blakei_512_ctx.inlen += min; count -= min;

        prev = blakei_512_ctx.lenlo;
        blakei_512_ctx.lenlo += min * 8;
        if (blakei_512_ctx.lenlo < prev) ++blakei_512_ctx.lenup;

        if (blakei_512_ctx.inlen == sizeof blakei_512_ctx.input)
            blakei_dround(&blakei_512_ctx);
    }
}

void blake_512_finish(void* hash) {
    blakei_512_ctx.input[blakei_512_ctx.inlen++] = 0x80;
    if (blakei_512_ctx.inlen > 112) blakei_dround(&blakei_512_ctx);
    blakei_512_ctx.input[111] |= 0x01;

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64_TWO(blakei_512_ctx.lenlo, blakei_512_ctx.lenup));
    memcpy(blakei_512_ctx.input + 112, &blakei_512_ctx.lenup, sizeof(blake_dword_t));
    memcpy(blakei_512_ctx.input + 120, &blakei_512_ctx.lenlo, sizeof(blake_dword_t));
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64_TWO(blakei_512_ctx.lenlo, blakei_512_ctx.lenup));
    blakei_dround(&blakei_512_ctx);

    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64x8(blakei_512_ctx.H));
    memcpy(hash, blakei_512_ctx.H, BLAKE_512_HASH_BYTE);
}

static const blake_byte_t blakei_sigma[10][16] = {
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

static const blake_sword_t blakei_C_32[16] = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

HSHFUNC_U64_WARN_BEGIN
static const blake_dword_t blakei_C_64[16] = {
    0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
    0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
    0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69
};
HSHFUNC_U64_WARN_END