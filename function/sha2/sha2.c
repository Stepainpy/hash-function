#define HSHFUNC_USE_ROTR32 sha2i_rotr32
#define HSHFUNC_USE_ROTR64 sha2i_rotr64

#include "sha2.h"
#include <string.h>
#include "config.h"

typedef hshfunc_u8_t  sha2_byte_t;
typedef hshfunc_u32_t sha2_sword_t;
typedef hshfunc_u64_t sha2_dword_t;

static const sha2_sword_t sha2i_K_32[64];
static const sha2_dword_t sha2i_K_64[80];

typedef struct {
    sha2_sword_t H[8];
    sha2_sword_t lenlo;
    sha2_sword_t lenup;
    sha2_byte_t input[64];
    sha2_byte_t inlen;
} sha2i_sctx_t;

typedef struct {
    sha2_dword_t H[8];
    sha2_dword_t lenlo;
    sha2_dword_t lenup;
    sha2_byte_t input[128];
    sha2_byte_t inlen;
} sha2i_dctx_t;

static sha2i_sctx_t sha2i_224_ctx;
static sha2i_sctx_t sha2i_256_ctx;
static sha2i_dctx_t sha2i_384_ctx;
static sha2i_dctx_t sha2i_512_ctx;
static sha2i_dctx_t sha2i_512_224_ctx;
static sha2i_dctx_t sha2i_512_256_ctx;

static void sha2i_sround(sha2i_sctx_t* ctx) {
    sha2_sword_t A, B, C, D, E, F, G, H;
    sha2_sword_t S0, S1, Ch, Ma, T1, T2;
    sha2_sword_t W[64]; int i;

    memcpy(W, ctx->input, sizeof ctx->input);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_32x16(W));
/* #if HSHFUNC_IS_LITTLE
    for (i =  0; i < 16; i++) W[i] = hshfunc_bswap32(W[i]);
#endif */
    for (i = 16; i < 64; i++) {
        S0 = sha2i_rotr32(W[i - 15],  7) ^ sha2i_rotr32(W[i - 15], 18) ^ (W[i - 15] >>  3);
        S1 = sha2i_rotr32(W[i -  2], 17) ^ sha2i_rotr32(W[i -  2], 19) ^ (W[i -  2] >> 10);
        W[i] = W[i - 16] + S0 + W[i - 7] + S1;
    }

    A = ctx->H[0]; B = ctx->H[1]; C = ctx->H[2]; D = ctx->H[3];
    E = ctx->H[4]; F = ctx->H[5]; G = ctx->H[6]; H = ctx->H[7];

    for (i = 0; i < 64; i++) {
        S0 = sha2i_rotr32(A, 2) ^ sha2i_rotr32(A, 13) ^ sha2i_rotr32(A, 22);
        S1 = sha2i_rotr32(E, 6) ^ sha2i_rotr32(E, 11) ^ sha2i_rotr32(E, 25);
        Ch = (E & F) ^ (~E & G);
        Ma = (A & B) ^ (A & C) ^ (B & C);
        T1 = H + S1 + Ch + sha2i_K_32[i] + W[i];
        T2 = S0 + Ma;

        H = G; G = F; F = E; E = T1 + D;
        D = C; C = B; B = A; A = T1 + T2;
    }

    ctx->H[0] += A; ctx->H[1] += B; ctx->H[2] += C; ctx->H[3] += D;
    ctx->H[4] += E; ctx->H[5] += F; ctx->H[6] += G; ctx->H[7] += H;

    memset(ctx->input, 0, sizeof ctx->input);
    ctx->inlen = 0;
}

static void sha2i_dround(sha2i_dctx_t* ctx) {
    sha2_dword_t A, B, C, D, E, F, G, H;
    sha2_dword_t S0, S1, Ch, Ma, T1, T2;
    sha2_dword_t W[80]; int i;

    memcpy(W, ctx->input, sizeof ctx->input);
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_64x16(W));
/* #if HSHFUNC_IS_LITTLE
    for (i =  0; i < 16; i++) W[i] = hshfunc_bswap64(W[i]);
#endif */
    for (i = 16; i < 80; i++) {
        S0 = sha2i_rotr64(W[i - 15],  1) ^ sha2i_rotr64(W[i - 15],  8) ^ (W[i - 15] >> 7);
        S1 = sha2i_rotr64(W[i -  2], 19) ^ sha2i_rotr64(W[i -  2], 61) ^ (W[i -  2] >> 6);
        W[i] = W[i - 16] + S0 + W[i - 7] + S1;
    }

    A = ctx->H[0]; B = ctx->H[1]; C = ctx->H[2]; D = ctx->H[3];
    E = ctx->H[4]; F = ctx->H[5]; G = ctx->H[6]; H = ctx->H[7];

    for (i = 0; i < 80; i++) {
        S0 = sha2i_rotr64(A, 28) ^ sha2i_rotr64(A, 34) ^ sha2i_rotr64(A, 39);
        S1 = sha2i_rotr64(E, 14) ^ sha2i_rotr64(E, 18) ^ sha2i_rotr64(E, 41);
        Ch = (E & F) ^ (~E & G);
        Ma = (A & B) ^ (A & C) ^ (B & C);
        T1 = H + S1 + Ch + sha2i_K_64[i] + W[i];
        T2 = S0 + Ma;

        H = G; G = F; F = E; E = T1 + D;
        D = C; C = B; B = A; A = T1 + T2;
    }

    ctx->H[0] += A; ctx->H[1] += B; ctx->H[2] += C; ctx->H[3] += D;
    ctx->H[4] += E; ctx->H[5] += F; ctx->H[6] += G; ctx->H[7] += H;

    memset(ctx->input, 0, sizeof ctx->input);
    ctx->inlen = 0;
}

void sha2_224_launch(void) {
    memset(&sha2i_224_ctx, 0, sizeof sha2i_224_ctx);

    sha2i_224_ctx.H[0] = 0xc1059ed8; sha2i_224_ctx.H[1] = 0x367cd507;
    sha2i_224_ctx.H[2] = 0x3070dd17; sha2i_224_ctx.H[3] = 0xf70e5939;
    sha2i_224_ctx.H[4] = 0xffc00b31; sha2i_224_ctx.H[5] = 0x68581511;
    sha2i_224_ctx.H[6] = 0x64f98fa7; sha2i_224_ctx.H[7] = 0xbefa4fa4;
}

void sha2_256_launch(void) {
    memset(&sha2i_256_ctx, 0, sizeof sha2i_256_ctx);

    sha2i_256_ctx.H[0] = 0x6a09e667; sha2i_256_ctx.H[1] = 0xbb67ae85;
    sha2i_256_ctx.H[2] = 0x3c6ef372; sha2i_256_ctx.H[3] = 0xa54ff53a;
    sha2i_256_ctx.H[4] = 0x510e527f; sha2i_256_ctx.H[5] = 0x9b05688c;
    sha2i_256_ctx.H[6] = 0x1f83d9ab; sha2i_256_ctx.H[7] = 0x5be0cd19;
}

void sha2_384_launch(void) {
    memset(&sha2i_384_ctx, 0, sizeof sha2i_384_ctx);

    HSHFUNC_U64_WARN_BEGIN
    sha2i_384_ctx.H[0] = 0xcbbb9d5dc1059ed8; sha2i_384_ctx.H[1] = 0x629a292a367cd507;
    sha2i_384_ctx.H[2] = 0x9159015a3070dd17; sha2i_384_ctx.H[3] = 0x152fecd8f70e5939;
    sha2i_384_ctx.H[4] = 0x67332667ffc00b31; sha2i_384_ctx.H[5] = 0x8eb44a8768581511;
    sha2i_384_ctx.H[6] = 0xdb0c2e0d64f98fa7; sha2i_384_ctx.H[7] = 0x47b5481dbefa4fa4;
    HSHFUNC_U64_WARN_END
}

void sha2_512_launch(void) {
    memset(&sha2i_512_ctx, 0, sizeof sha2i_512_ctx);

    HSHFUNC_U64_WARN_BEGIN
    sha2i_512_ctx.H[0] = 0x6a09e667f3bcc908; sha2i_512_ctx.H[1] = 0xbb67ae8584caa73b;
    sha2i_512_ctx.H[2] = 0x3c6ef372fe94f82b; sha2i_512_ctx.H[3] = 0xa54ff53a5f1d36f1;
    sha2i_512_ctx.H[4] = 0x510e527fade682d1; sha2i_512_ctx.H[5] = 0x9b05688c2b3e6c1f;
    sha2i_512_ctx.H[6] = 0x1f83d9abfb41bd6b; sha2i_512_ctx.H[7] = 0x5be0cd19137e2179;
    HSHFUNC_U64_WARN_END
}

void sha2_512_224_launch(void) {
    memset(&sha2i_512_224_ctx, 0, sizeof sha2i_512_224_ctx);

    HSHFUNC_U64_WARN_BEGIN
    sha2i_512_224_ctx.H[0] = 0x8c3d37c819544da2; sha2i_512_224_ctx.H[1] = 0x73e1996689dcd4d6;
    sha2i_512_224_ctx.H[2] = 0x1dfab7ae32ff9c82; sha2i_512_224_ctx.H[3] = 0x679dd514582f9fcf;
    sha2i_512_224_ctx.H[4] = 0x0f6d2b697bd44da8; sha2i_512_224_ctx.H[5] = 0x77e36f7304C48942;
    sha2i_512_224_ctx.H[6] = 0x3f9d85a86a1d36C8; sha2i_512_224_ctx.H[7] = 0x1112e6ad91d692a1;
    HSHFUNC_U64_WARN_END
}

void sha2_512_256_launch(void) {
    memset(&sha2i_512_256_ctx, 0, sizeof sha2i_512_256_ctx);

    HSHFUNC_U64_WARN_BEGIN
    sha2i_512_256_ctx.H[0] = 0x22312194fc2bf72c; sha2i_512_256_ctx.H[1] = 0x9f555fa3c84c64c2;
    sha2i_512_256_ctx.H[2] = 0x2393b86b6f53b151; sha2i_512_256_ctx.H[3] = 0x963877195940eabd;
    sha2i_512_256_ctx.H[4] = 0x96283ee2a88effe3; sha2i_512_256_ctx.H[5] = 0xbe5e1e2553863992;
    sha2i_512_256_ctx.H[6] = 0x2b0199fc2c85b8aa; sha2i_512_256_ctx.H[7] = 0x0eb72ddC81c52ca2;
    HSHFUNC_U64_WARN_END
}

#define sha2i_update_template(prefix, word_t, roundfn) \
void sha2_##prefix##_update(const void* data, size_t count) {                       \
    size_t min, remainder; word_t prev;                                             \
    while (count > 0) {                                                             \
        remainder = sizeof sha2i_##prefix##_ctx.input - sha2i_##prefix##_ctx.inlen; \
        min = count < remainder ? count : remainder;                                \
                                                                                    \
        memcpy(sha2i_##prefix##_ctx.input + sha2i_##prefix##_ctx.inlen, data, min); \
        data = (const sha2_byte_t*)data + min;                                      \
        sha2i_##prefix##_ctx.inlen += min; count -= min;                            \
                                                                                    \
        prev = sha2i_##prefix##_ctx.lenlo;                                          \
        sha2i_##prefix##_ctx.lenlo += min * 8;                                      \
        if (sha2i_##prefix##_ctx.lenlo < prev) ++sha2i_##prefix##_ctx.lenup;        \
                                                                                    \
        if (sha2i_##prefix##_ctx.inlen == sizeof sha2i_##prefix##_ctx.input)        \
            sha2i_##roundfn(&sha2i_##prefix##_ctx);                                 \
    }                                                                               \
}

sha2i_update_template(224, sha2_sword_t, sround)
sha2i_update_template(256, sha2_sword_t, sround)
sha2i_update_template(384, sha2_dword_t, dround)
sha2i_update_template(512, sha2_dword_t, dround)

sha2i_update_template(512_224, sha2_dword_t, dround)
sha2i_update_template(512_256, sha2_dword_t, dround)

/* #if HSHFUNC_IS_LITTLE
#  define sha2i_bswap_u32x2(A0, A1) do { \
    A0 = hshfunc_bswap32(A0); \
    A1 = hshfunc_bswap32(A1); \
} while (0)
#else
#  define sha2i_bswap_u32x2(A0, A1)
#endif

#if HSHFUNC_IS_LITTLE
#  define sha2i_bswap_u64x2(A0, A1) do { \
    A0 = hshfunc_bswap64(A0); \
    A1 = hshfunc_bswap64(A1); \
} while (0)
#else
#  define sha2i_bswap_u64x2(A0, A1)
#endif

#if HSHFUNC_IS_LITTLE
#  define sha2i_bswap_u32x8(array) do {   \
    array[0] = hshfunc_bswap32(array[0]); \
    array[1] = hshfunc_bswap32(array[1]); \
    array[2] = hshfunc_bswap32(array[2]); \
    array[3] = hshfunc_bswap32(array[3]); \
    array[4] = hshfunc_bswap32(array[4]); \
    array[5] = hshfunc_bswap32(array[5]); \
    array[6] = hshfunc_bswap32(array[6]); \
    array[7] = hshfunc_bswap32(array[7]); \
} while (0)
#else
#  define sha2i_bswap_u32x8(array)
#endif

#if HSHFUNC_IS_LITTLE
#  define sha2i_bswap_u64x8(array) do {   \
    array[0] = hshfunc_bswap64(array[0]); \
    array[1] = hshfunc_bswap64(array[1]); \
    array[2] = hshfunc_bswap64(array[2]); \
    array[3] = hshfunc_bswap64(array[3]); \
    array[4] = hshfunc_bswap64(array[4]); \
    array[5] = hshfunc_bswap64(array[5]); \
    array[6] = hshfunc_bswap64(array[6]); \
    array[7] = hshfunc_bswap64(array[7]); \
} while (0)
#else
#  define sha2i_bswap_u64x8(array)
#endif */

#define sha2i_finish_template(prefix, word_t, roundfn, outbytes, bits) \
void sha2_##prefix##_finish(void* hash) {                                                       \
    sha2i_##prefix##_ctx.input[sha2i_##prefix##_ctx.inlen++] = 0x80;                            \
    if (sha2i_##prefix##_ctx.inlen > sizeof sha2i_##prefix##_ctx.input - sizeof(word_t) * 2)    \
        sha2i_##roundfn(&sha2i_##prefix##_ctx);                                                 \
                                                                                                \
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_##bits##_TWO(                                               \
        sha2i_##prefix##_ctx.lenlo, sha2i_##prefix##_ctx.lenup));                               \
    memcpy(sha2i_##prefix##_ctx.input + sizeof sha2i_##prefix##_ctx.input - sizeof(word_t) * 2, \
        &sha2i_##prefix##_ctx.lenup, sizeof sha2i_##prefix##_ctx.lenup);                        \
    memcpy(sha2i_##prefix##_ctx.input + sizeof sha2i_##prefix##_ctx.input - sizeof(word_t) * 1, \
        &sha2i_##prefix##_ctx.lenlo, sizeof sha2i_##prefix##_ctx.lenlo);                        \
    sha2i_##roundfn(&sha2i_##prefix##_ctx);                                                     \
                                                                                                \
    HSHFUNC_IF_LITTLE(HSHFUNC_BSWAP_##bits##x8(sha2i_##prefix##_ctx.H));                        \
    memcpy(hash, sha2i_##prefix##_ctx.H, outbytes);                                             \
}

sha2i_finish_template(224, sha2_sword_t, sround, SHA2_224_HASH_BYTE, 32)
sha2i_finish_template(256, sha2_sword_t, sround, SHA2_256_HASH_BYTE, 32)
sha2i_finish_template(384, sha2_dword_t, dround, SHA2_384_HASH_BYTE, 64)
sha2i_finish_template(512, sha2_dword_t, dround, SHA2_512_HASH_BYTE, 64)

sha2i_finish_template(512_224, sha2_dword_t, dround, SHA2_512_224_HASH_BYTE, 64)
sha2i_finish_template(512_256, sha2_dword_t, dround, SHA2_512_256_HASH_BYTE, 64)

static const sha2_sword_t sha2i_K_32[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

HSHFUNC_U64_WARN_BEGIN
static const sha2_dword_t sha2i_K_64[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};
HSHFUNC_U64_WARN_END