/* Secure Hash Algorithm 2 (SHA-2)
 *
 * Length of hash - 224, 256, 384 or 512 bit
 * Sources:
 *   https://ru.wikipedia.org/wiki/SHA-2
 */

#ifndef SHA2_HASH_FUNCTION_H
#define SHA2_HASH_FUNCTION_H

#include <stddef.h>

#define SHA2_224_HASH_BITS 224
#define SHA2_224_HASH_BYTE 28

void sha2_224_launch(void);
void sha2_224_update(const void* data, size_t count);
void sha2_224_finish(void* hash);

#define SHA2_256_HASH_BITS 256
#define SHA2_256_HASH_BYTE 32

void sha2_256_launch(void);
void sha2_256_update(const void* data, size_t count);
void sha2_256_finish(void* hash);

#define SHA2_384_HASH_BITS 384
#define SHA2_384_HASH_BYTE 48

void sha2_384_launch(void);
void sha2_384_update(const void* data, size_t count);
void sha2_384_finish(void* hash);

#define SHA2_512_HASH_BITS 512
#define SHA2_512_HASH_BYTE 64

void sha2_512_launch(void);
void sha2_512_update(const void* data, size_t count);
void sha2_512_finish(void* hash);

#define SHA2_512_224_HASH_BITS 224
#define SHA2_512_224_HASH_BYTE 28

void sha2_512_224_launch(void);
void sha2_512_224_update(const void* data, size_t count);
void sha2_512_224_finish(void* hash);

#define SHA2_512_256_HASH_BITS 256
#define SHA2_512_256_HASH_BYTE 32

void sha2_512_256_launch(void);
void sha2_512_256_update(const void* data, size_t count);
void sha2_512_256_finish(void* hash);

#endif /* SHA2_HASH_FUNCTION_H */