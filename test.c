#include <stdio.h>
#include <string.h>

#include "sha1/sha1.h"
#include "md5/md5.h"

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

    puts("Testing Message Digest 5 (MD5):");
    test_function(
        md5, MD5_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\x9e\x10\x7d\x9d\x37\x2b\xb6\x82\x6b\xd8\x1d\x35\x42\xa4\x19\xd6"
    );
    test_function(
        md5, MD5_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
    );
    test_function(
        md5, MD5_HASH_BYTE, 1,
        /* M */ "a",
        /* H */ "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61"
    );
    test_function(
        md5, MD5_HASH_BYTE, 3,
        /* M */ "abc",
        /* H */ "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72"
    );
    test_function(
        md5, MD5_HASH_BYTE, 14,
        /* M */ "message digest",
        /* H */ "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0"
    );
    test_function(
        md5, MD5_HASH_BYTE, 26,
        /* M */ "abcdefghijklmnopqrstuvwxyz",
        /* H */ "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b"
    );
    test_function(
        md5, MD5_HASH_BYTE, 62,
        /* M */ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        /* H */ "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f"
    );
    test_function(
        md5, MD5_HASH_BYTE, 80,
        /* M */ "1234567890123456789012345678901234567890123456789012345678901234"
                "5678901234567890",
        /* H */ "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6\x7a"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    return 0;
}