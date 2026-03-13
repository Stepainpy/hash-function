#define HSHFUNC_USE_ROTL32 md5i_rotl

#include "md5.h"
#include <string.h>
#include "config.h"

typedef hshfunc_u8_t  md5_byte_t;
typedef hshfunc_u32_t md5_word_t;

static const md5_word_t md5i_K[64];
static const md5_byte_t md5i_S[16];

static struct {
    md5_word_t H[4];
    md5_word_t lenlo;
    md5_word_t lenup;
    md5_byte_t input[64];
    md5_byte_t inlen;
} md5i_ctx;

static void md5i_round(void) {
    md5_word_t A, B, C, D, temp;
    md5_word_t W[16]; int i;

    memcpy(W, md5i_ctx.input, sizeof md5i_ctx.input);
#if HSHFUNC_IS_BIG
    for (i = 0; i < 16; i++) W[i] = hshfunc_bswap32(W[i]);
#endif

    A = md5i_ctx.H[0]; B = md5i_ctx.H[1];
    C = md5i_ctx.H[2]; D = md5i_ctx.H[3];

    for (i = 0; i < 64; i++) {
        /**/ if ( 0 <= i && i < 16) temp = ((B & C) | (~B & D)) + W[   i        ];
        else if (16 <= i && i < 32) temp = ((D & B) | (~D & C)) + W[(5*i+1) & 15];
        else if (32 <= i && i < 48) temp = (B ^ C ^ D         ) + W[(3*i+5) & 15];
        else if (48 <= i && i < 64) temp = (C ^ (B | ~D)      ) + W[(7*i  ) & 15];

        temp += A + md5i_K[i];
        A = D; D = C; C = B;
        B += md5i_rotl(temp, md5i_S[i / 16 * 4 + (i & 3)]);
    }

    md5i_ctx.H[0] += A; md5i_ctx.H[1] += B;
    md5i_ctx.H[2] += C; md5i_ctx.H[3] += D;

    memset(md5i_ctx.input, 0, sizeof md5i_ctx.input);
    md5i_ctx.inlen = 0;
}

void md5_launch(void) {
    memset(&md5i_ctx, 0, sizeof md5i_ctx);

    md5i_ctx.H[0] = 0x67452301;
    md5i_ctx.H[1] = 0xefcdab89;
    md5i_ctx.H[2] = 0x98badcfe;
    md5i_ctx.H[3] = 0x10325476;
}

void md5_update(const void* data, size_t count) {
    size_t min, remainder, prev;
    while (count > 0) {
        remainder = sizeof md5i_ctx.input - md5i_ctx.inlen;
        min = count < remainder ? count : remainder;

        memcpy(md5i_ctx.input + md5i_ctx.inlen, data, min);
        data = (const md5_byte_t*)data + min;
        md5i_ctx.inlen += min; count -= min;

        prev = md5i_ctx.lenlo;
        md5i_ctx.lenlo += min * 8;
        if (md5i_ctx.lenlo < prev) ++md5i_ctx.lenup;

        if (md5i_ctx.inlen == sizeof md5i_ctx.input)
            md5i_round();
    }
}

void md5_finish(void* hash) {
    md5i_ctx.input[md5i_ctx.inlen++] = 0x80;
    if (md5i_ctx.inlen > 56) md5i_round();

#if HSHFUNC_IS_BIG
    md5i_ctx.lenup = hshfunc_bswap32(md5i_ctx.lenup);
    md5i_ctx.lenlo = hshfunc_bswap32(md5i_ctx.lenlo);
#endif
    memcpy(md5i_ctx.input + 56, &md5i_ctx.lenlo, sizeof md5i_ctx.lenlo);
    memcpy(md5i_ctx.input + 60, &md5i_ctx.lenup, sizeof md5i_ctx.lenup);
    md5i_round();

#if HSHFUNC_IS_BIG
    md5i_ctx.H[0] = hshfunc_bswap32(md5i_ctx.H[0]);
    md5i_ctx.H[1] = hshfunc_bswap32(md5i_ctx.H[1]);
    md5i_ctx.H[2] = hshfunc_bswap32(md5i_ctx.H[2]);
    md5i_ctx.H[3] = hshfunc_bswap32(md5i_ctx.H[3]);
#endif
    memcpy(hash, md5i_ctx.H, sizeof md5i_ctx.H);
}

static const md5_word_t md5i_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const md5_byte_t md5i_S[16] = {
    7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21
};