#include <stdio.h>
#include <string.h>

#include "whirlpool/whirlpool.h"
#include "sha1/sha1.h"
#include "sha2/sha2.h"
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

/* Testing cases
 * 1. "" (empty message)
 * 2. "The quick brown fox jumps over the lazy dog" (pangram)
 * 3. other from spec or online tools
 */

int main(void) {
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Tesing Secure Hash Algorithm 1 (SHA-1):");
    test_function(
        sha1, SHA1_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90"
                "\xaf\xd8\x07\x09"
    );
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

    puts("Testing Secure Hash Algorithm 2 (SHA-2):");
    test_function(
        sha2_224, SHA2_224_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9\x47\x61\x02\xbb\x28\x82\x34\xc4"
                "\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a\xc5\xb3\xe4\x2f"
    );
    test_function(
        sha2_224, SHA2_224_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\x73\x0e\x10\x9b\xd7\xa8\xa3\x2b\x1c\xb9\xd9\xa0\x9a\xa2\x32\x5d"
                "\x24\x30\x58\x7d\xdb\xc0\xc3\x8b\xad\x91\x15\x25"
    );

    test_function(
        sha2_256, SHA2_256_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
                "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"
    );
    test_function(
        sha2_256, SHA2_256_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\xd7\xa8\xfb\xb3\x07\xd7\x80\x94\x69\xca\x9a\xbc\xb0\x08\x2e\x4f"
                "\x8d\x56\x51\xe4\x6d\x3c\xdb\x76\x2d\x02\xd0\xbf\x37\xc9\xe5\x92"
    );

    test_function(
        sha2_384, SHA2_384_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a"
                "\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda"
                "\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b"
    );
    test_function(
        sha2_384, SHA2_384_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\xca\x73\x7f\x10\x14\xa4\x8f\x4c\x0b\x6d\xd4\x3c\xb1\x77\xb0\xaf"
                "\xd9\xe5\x16\x93\x67\x54\x4c\x49\x40\x11\xe3\x31\x7d\xbf\x9a\x50"
                "\x9c\xb1\xe5\xdc\x1e\x85\xa9\x41\xbb\xee\x3d\x7f\x2a\xfb\xc9\xb1"
    );

    test_function(
        sha2_512, SHA2_512_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07"
                "\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
                "\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f"
                "\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e"
    );
    test_function(
        sha2_512, SHA2_512_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\x07\xe5\x47\xd9\x58\x6f\x6a\x73\xf7\x3f\xba\xc0\x43\x5e\xd7\x69"
                "\x51\x21\x8f\xb7\xd0\xc8\xd7\x88\xa3\x09\xd7\x85\x43\x6b\xbb\x64"
                "\x2e\x93\xa2\x52\xa9\x54\xf2\x39\x12\x54\x7d\x1e\x8a\x3b\x5e\xd6"
                "\xe1\xbf\xd7\x09\x78\x21\x23\x3f\xa0\x53\x8f\x3d\xb8\x54\xfe\xe6"
    );

    test_function(
        sha2_512_224, SHA2_512_224_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\x6e\xd0\xdd\x02\x80\x6f\xa8\x9e\x25\xde\x06\x0c\x19\xd3\xac\x86"
                "\xca\xbb\x87\xd6\xa0\xdd\xd0\x5c\x33\x3b\x84\xf4"
    );
    test_function(
        sha2_512_224, SHA2_512_224_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\x94\x4c\xd2\x84\x7f\xb5\x45\x58\xd4\x77\x5d\xb0\x48\x5a\x50\x00"
                "\x31\x11\xc8\xe5\xda\xa6\x3f\xe7\x22\xc6\xaa\x37"
    );

    test_function(
        sha2_512_256, SHA2_512_256_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\xc6\x72\xb8\xd1\xef\x56\xed\x28\xab\x87\xc3\x62\x2c\x51\x14\x06"
                "\x9b\xdd\x3a\xd7\xb8\xf9\x73\x74\x98\xd0\xc0\x1e\xce\xf0\x96\x7a"
    );
    test_function(
        sha2_512_256, SHA2_512_256_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\xdd\x9d\x67\xb3\x71\x51\x9c\x33\x9e\xd8\xdb\xd2\x5a\xf9\x0e\x97"
                "\x6a\x1e\xee\xfd\x4a\xd3\xd8\x89\x00\x5e\x53\x2f\xc5\xbe\xf0\x4d"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Message Digest 5 (MD5):");
    test_function(
        md5, MD5_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
    );
    test_function(
        md5, MD5_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\x9e\x10\x7d\x9d\x37\x2b\xb6\x82\x6b\xd8\x1d\x35\x42\xa4\x19\xd6"
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

    puts("Testing Whirlpool:");
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 0,
        /* M */ "",
        /* H */ "\x19\xfa\x61\xd7\x55\x22\xa4\x66\x9b\x44\xe3\x9c\x1d\x2e\x17\x26"
                "\xc5\x30\x23\x21\x30\xd4\x07\xf8\x9a\xfe\xe0\x96\x49\x97\xf7\xa7"
                "\x3e\x83\xbe\x69\x8b\x28\x8f\xeb\xcf\x88\xe3\xe0\x3c\x4f\x07\x57"
                "\xea\x89\x64\xe5\x9b\x63\xd9\x37\x08\xb1\x38\xcc\x42\xa6\x6e\xb3"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy dog",
        /* H */ "\xb9\x7d\xe5\x12\xe9\x1e\x38\x28\xb4\x0d\x2b\x0f\xdc\xe9\xce\xb3"
                "\xc4\xa7\x1f\x9b\xea\x8d\x88\xe7\x5c\x4f\xa8\x54\xdf\x36\x72\x5f"
                "\xd2\xb5\x2e\xb6\x54\x4e\xdc\xac\xd6\xf8\xbe\xdd\xfe\xa4\x03\xcb"
                "\x55\xae\x31\xf0\x3a\xd6\x2a\x5e\xf5\x4e\x42\xee\x82\xc3\xfb\x35"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 1,
        /* M */ "a",
        /* H */ "\x8a\xca\x26\x02\x79\x2a\xec\x6f\x11\xa6\x72\x06\x53\x1f\xb7\xd7"
                "\xf0\xdf\xf5\x94\x13\x14\x5e\x69\x73\xc4\x50\x01\xd0\x08\x7b\x42"
                "\xd1\x1b\xc6\x45\x41\x3a\xef\xf6\x3a\x42\x39\x1a\x39\x14\x5a\x59"
                "\x1a\x92\x20\x0d\x56\x01\x95\xe5\x3b\x47\x85\x84\xfd\xae\x23\x1a"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 3,
        /* M */ "abc",
        /* H */ "\x4e\x24\x48\xa4\xc6\xf4\x86\xbb\x16\xb6\x56\x2c\x73\xb4\x02\x0b"
                "\xf3\x04\x3e\x3a\x73\x1b\xce\x72\x1a\xe1\xb3\x03\xd9\x7e\x6d\x4c"
                "\x71\x81\xee\xbd\xb6\xc5\x7e\x27\x7d\x0e\x34\x95\x71\x14\xcb\xd6"
                "\xc7\x97\xfc\x9d\x95\xd8\xb5\x82\xd2\x25\x29\x20\x76\xd4\xee\xf5"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 4,
        /* M */ "test",
        /* H */ "\xb9\x13\xd5\xbb\xb8\xe4\x61\xc2\xc5\x96\x1c\xbe\x0e\xdc\xda\xdf"
                "\xd2\x9f\x06\x82\x25\xce\xb3\x7d\xa6\xde\xfc\xf8\x98\x49\x36\x8f"
                "\x8c\x6c\x2e\xb6\xa4\xc4\xac\x75\x77\x5d\x03\x2a\x0e\xcf\xdf\xe8"
                "\x55\x05\x73\x06\x2b\x65\x3f\xe9\x2f\xc7\xb8\xfb\x3b\x7b\xe8\xd6"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 14,
        /* M */ "message digest",
        /* H */ "\x37\x8c\x84\xa4\x12\x6e\x2d\xc6\xe5\x6d\xcc\x74\x58\x37\x7a\xac"
                "\x83\x8d\x00\x03\x22\x30\xf5\x3c\xe1\xf5\x70\x0c\x0f\xfb\x4d\x3b"
                "\x84\x21\x55\x76\x59\xef\x55\xc1\x06\xb4\xb5\x2a\xc5\xa4\xaa\xa6"
                "\x92\xed\x92\x00\x52\x83\x8f\x33\x62\xe8\x6d\xbd\x37\xa8\x90\x3e"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 26,
        /* M */ "abcdefghijklmnopqrstuvwxyz",
        /* H */ "\xf1\xd7\x54\x66\x26\x36\xff\xe9\x2c\x82\xeb\xb9\x21\x2a\x48\x4a"
                "\x8d\x38\x63\x1e\xad\x42\x38\xf5\x44\x2e\xe1\x3b\x80\x54\xe4\x1b"
                "\x08\xbf\x2a\x92\x51\xc3\x0b\x6a\x0b\x8a\xae\x86\x17\x7a\xb4\xa6"
                "\xf6\x8f\x67\x3e\x72\x07\x86\x5d\x5d\x98\x19\xa3\xdb\xa4\xeb\x3b"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 32,
        /* M */ "abcdbcdecdefdefgefghfghighijhijk",
        /* H */ "\x2a\x98\x7e\xa4\x0f\x91\x70\x61\xf5\xd6\xf0\xa0\xe4\x64\x4f\x48"
                "\x8a\x7a\x5a\x52\xde\xee\x65\x62\x07\xc5\x62\xf9\x88\xe9\x5c\x69"
                "\x16\xbd\xc8\x03\x1b\xc5\xbe\x1b\x7b\x94\x76\x39\xfe\x05\x0b\x56"
                "\x93\x9b\xaa\xa0\xad\xff\x9a\xe6\x74\x5b\x7b\x18\x1c\x3b\xe3\xfd"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 43,
        /* M */ "The quick brown fox jumps over the lazy eog",
        /* H */ "\xc2\x7b\xa1\x24\x20\x5f\x72\xe6\x84\x7f\x3e\x19\x83\x4f\x92\x5c"
                "\xc6\x66\xd0\x97\x41\x67\xaf\x91\x5b\xb4\x62\x42\x0e\xd4\x0c\xc5"
                "\x09\x00\xd8\x5a\x1f\x92\x32\x19\xd8\x32\x35\x77\x50\x49\x2d\x5c"
                "\x14\x30\x11\xa7\x69\x88\x34\x4c\x26\x35\xe6\x9d\x06\xf2\xd3\x8c"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 62,
        /* M */ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        /* H */ "\xdc\x37\xe0\x08\xcf\x9e\xe6\x9b\xf1\x1f\x00\xed\x9a\xba\x26\x90"
                "\x1d\xd7\xc2\x8c\xde\xc0\x66\xcc\x6a\xf4\x2e\x40\xf8\x2f\x3a\x1e"
                "\x08\xeb\xa2\x66\x29\x12\x9d\x8f\xb7\xcb\x57\x21\x1b\x92\x81\xa6"
                "\x55\x17\xcc\x87\x9d\x7b\x96\x21\x42\xc6\x5f\x5a\x7a\xf0\x14\x67"
    );
    test_function(
        whirlpool, WHIRLPOOL_HASH_BYTE, 80,
        /* M */ "1234567890123456789012345678901234567890123456789012345678901234"
                "5678901234567890",
        /* H */ "\x46\x6e\xf1\x8b\xab\xb0\x15\x4d\x25\xb9\xd3\x8a\x64\x14\xf5\xc0"
                "\x87\x84\x37\x2b\xcc\xb2\x04\xd6\x54\x9c\x4a\xfa\xdb\x60\x14\x29"
                "\x4d\x5b\xd8\xdf\x2a\x6c\x44\xe5\x38\xcd\x04\x7b\x26\x81\xa5\x1a"
                "\x2c\x60\x48\x1e\x88\xc5\xa2\x0b\x2c\x2a\x80\xcf\x3a\x9a\x08\x3b"
    );
#if 0 /* Whirlpool test case with 'a' repeated 10^6 times, default disable */
    do {
        const char* hash =
            "\x0c\x99\x00\x5b\xeb\x57\xef\xf5\x0a\x7c\xf0\x05\x56\x0d\xdf\x5d"
            "\x29\x05\x7f\xd8\x6b\x20\xbf\xd6\x2d\xec\xa0\xf1\xcc\xea\x4a\xf5"
            "\x1f\xc1\x54\x90\xed\xdc\x47\xaf\x32\xbb\x2b\x66\xc3\x4f\xf9\xad"
            "\x8c\x60\x08\xad\x67\x7f\x77\x12\x69\x53\xb2\x26\xe4\xed\x8b\x01";
        unsigned char H[WHIRLPOOL_HASH_BYTE]; int i;

        whirlpool_launch();
        for (i = 0; i < 20000; i++)
            whirlpool_update("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50);
        whirlpool_finish(H);

        printf("- Check hash (load 1000000 bytes) ... ");
        if (memcmp(H, hash, WHIRLPOOL_HASH_BYTE) == 0) puts(OK);
        else {
            puts(FAIL);
            printf("  > expected: ");
            for (i = 0; i < WHIRLPOOL_HASH_BYTE; i++)
                printf("%02x", hash[i] & 0xFF);
            putchar('\n');
            printf("  > received: ");
            for (i = 0; i < WHIRLPOOL_HASH_BYTE; i++)
                printf("%02x", H[i]);
            putchar('\n');
        }
    } while (0);
#endif
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    return 0;
}