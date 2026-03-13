/* Secure Hash Algorithm 3 (SHA-3)
 *
 * Length of hash - 224, 256, 384 or 512 bit
 * Sources:
 *   https://en.wikipedia.org/wiki/SHA-3
 *   https://github.com/brainhub/SHA3IUF/blob/master/sha3.c#L82
 */

#ifndef SHA3_HASH_FUNCTION_H
#define SHA3_HASH_FUNCTION_H

#include <stddef.h>

#define SHA3_224_HASH_BITS 224
#define SHA3_224_HASH_BYTE 28

void sha3_224_launch(void);
void sha3_224_update(const void* data, size_t count);
void sha3_224_finish(void* hash);

#define SHA3_256_HASH_BITS 256
#define SHA3_256_HASH_BYTE 32

void sha3_256_launch(void);
void sha3_256_update(const void* data, size_t count);
void sha3_256_finish(void* hash);

#define SHA3_384_HASH_BITS 384
#define SHA3_384_HASH_BYTE 48

void sha3_384_launch(void);
void sha3_384_update(const void* data, size_t count);
void sha3_384_finish(void* hash);

#define SHA3_512_HASH_BITS 512
#define SHA3_512_HASH_BYTE 64

void sha3_512_launch(void);
void sha3_512_update(const void* data, size_t count);
void sha3_512_finish(void* hash);

#endif /* SHA3_HASH_FUNCTION_H */