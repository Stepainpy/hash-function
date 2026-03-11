#include <stdio.h>
#include <string.h>

#include "sha1/sha1.h"

/* use ANSI coloring */
#if 1
#  define OK   "\x1b[32mOK\x1b[0m"
#  define FAIL "\x1b[31mFAIL\x1b[0m"
#else
#  define OK   "OK"
#  define FAIL "FAIL"
#endif

#define test_function(name, hashsz, msgsz, msg, hash)    \
do {                                                     \
    unsigned char H[hashsz]; int i;                      \
                                                         \
    name##_launch();                                     \
    name##_update(msg, msgsz);                           \
    name##_finish(H);                                    \
                                                         \
    printf("- Check hash (load %2i bytes) ... ", msgsz); \
    if (memcmp(H, hash, hashsz) == 0) puts(OK);          \
    else {                                               \
        puts(FAIL);                                      \
        printf("  > expected: ");                        \
        for (i = 0; i < hashsz; i++)                     \
            printf("%02x", hash[i] & 0xFF);              \
        putchar('\n');                                   \
        printf("  > received: ");                        \
        for (i = 0; i < hashsz; i++)                     \
            printf("%02x", H[i]);                        \
        putchar('\n');                                   \
    }                                                    \
} while (0)

int main(void) {
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Tesing Secure Hash Algorithm 1 (SHA-1):");
    test_function(
        sha1, SHA1_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\x2f\xd4\xe1\xc6\x7a\x2d\x28\xfc\xed\x84\x9e\xe1\xbb\x76\xe7\x39"
                "\x1b\x93\xeb\x12"
    );
    test_function(
        sha1, SHA1_HASH_BYTE, 3,
        /* M */ "abc",
        /* H */ "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c"
                "\x9c\xd0\xd8\x9d"
    );
    test_function(
        sha1, SHA1_HASH_BYTE, 56,
        /* M */ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        /* H */ "\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5"
                "\xe5\x46\x70\xf1"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    return 0;
}