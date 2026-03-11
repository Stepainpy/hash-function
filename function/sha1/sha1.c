#define HSHFUNC_USE_ROTL32 sha1i_rotl

#include "sha1.h"
#include <string.h>
#include "config.h"

typedef hshfunc_u8_t  sha1_byte_t;
typedef hshfunc_u32_t sha1_word_t;

static struct {
    sha1_word_t H[5];
    sha1_word_t lenlo;
    sha1_word_t lenup;
    sha1_byte_t input[64];
    sha1_byte_t inlen;
} sha1i_ctx;

static void sha1i_round(void) {
    sha1_word_t A, B, C, D, E, temp;
    sha1_word_t W[80]; int i;

    memcpy(W, sha1i_ctx.input, sizeof sha1i_ctx.input);
#if HSHFUNC_IS_LITTLE
    for (i =  0; i < 16; i++) W[i] = hshfunc_bswap32(W[i]);
#endif
    for (i = 16; i < 80; i++)
        W[i] = sha1i_rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

    A = sha1i_ctx.H[0]; B = sha1i_ctx.H[1];
    C = sha1i_ctx.H[2]; D = sha1i_ctx.H[3];
    E = sha1i_ctx.H[4];

    for (i = 0; i < 80; i++) {
        /**/ if ( 0 <= i && i < 20) temp = 0x5a827999 + ((B & C) | (~B & D));
        else if (20 <= i && i < 40) temp = 0x6ed9eba1 + (B ^ C ^ D);
        else if (40 <= i && i < 60) temp = 0x8f1bbcdc + ((B & C) | (B & D) | (C & D));
        else if (60 <= i && i < 80) temp = 0xca62c1d6 + (B ^ C ^ D);

        temp += sha1i_rotl(A, 5) + E + W[i];
        E = D; D = C; C = sha1i_rotl(B, 30); B = A; A = temp;
    }

    sha1i_ctx.H[0] += A; sha1i_ctx.H[1] += B;
    sha1i_ctx.H[2] += C; sha1i_ctx.H[3] += D;
    sha1i_ctx.H[4] += E;

    memset(sha1i_ctx.input, 0, sizeof sha1i_ctx.input);
    sha1i_ctx.inlen = 0;
}

void sha1_launch(void) {
    memset(&sha1i_ctx, 0, sizeof sha1i_ctx);

    sha1i_ctx.H[0] = 0x67452301;
    sha1i_ctx.H[1] = 0xefcdab89;
    sha1i_ctx.H[2] = 0x98badcfe;
    sha1i_ctx.H[3] = 0x10325476;
    sha1i_ctx.H[4] = 0xc3d2e1f0;
}

void sha1_update(const void* data, size_t count) {
    size_t min, remainder, prev;
    while (count > 0) {
        remainder = sizeof sha1i_ctx.input - sha1i_ctx.inlen;
        min = count < remainder ? count : remainder;

        memcpy(sha1i_ctx.input + sha1i_ctx.inlen, data, min);
        data = (const sha1_byte_t*)data + min;
        sha1i_ctx.inlen += min; count -= min;

        prev = (sha1i_ctx.lenlo += min);
        if (sha1i_ctx.lenlo < prev) ++sha1i_ctx.lenup;

        if (sha1i_ctx.inlen == sizeof sha1i_ctx.input)
            sha1i_round();
    }
}

void sha1_finish(void* hash) {
    sha1i_ctx.input[sha1i_ctx.inlen++] = 0x80;
    if (sha1i_ctx.inlen > 56) sha1i_round();

    sha1i_ctx.lenup = sha1i_ctx.lenup << 3 | sha1i_ctx.lenlo >> 29;
    sha1i_ctx.lenlo = sha1i_ctx.lenlo << 3;
#if HSHFUNC_IS_LITTLE
    sha1i_ctx.lenup = hshfunc_bswap32(sha1i_ctx.lenup);
    sha1i_ctx.lenlo = hshfunc_bswap32(sha1i_ctx.lenlo);
#endif
    memcpy(sha1i_ctx.input + 56, &sha1i_ctx.lenup, sizeof sha1i_ctx.lenup);
    memcpy(sha1i_ctx.input + 60, &sha1i_ctx.lenlo, sizeof sha1i_ctx.lenlo);
    sha1i_round();

#if HSHFUNC_IS_LITTLE
    sha1i_ctx.H[0] = hshfunc_bswap32(sha1i_ctx.H[0]);
    sha1i_ctx.H[1] = hshfunc_bswap32(sha1i_ctx.H[1]);
    sha1i_ctx.H[2] = hshfunc_bswap32(sha1i_ctx.H[2]);
    sha1i_ctx.H[3] = hshfunc_bswap32(sha1i_ctx.H[3]);
    sha1i_ctx.H[4] = hshfunc_bswap32(sha1i_ctx.H[4]);
#endif
    memcpy(hash, sha1i_ctx.H, sizeof sha1i_ctx.H);
}