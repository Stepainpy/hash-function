/* BLAKE
 *
 * Length of hash - 224, 256, 384 or 512 bit
 * Length of salt - 128 or 256 bit
 * Sources:
 *   https://www.aumasson.jp/blake/blake.pdf
 */

#ifndef BLAKE_HASH_FUNCTION_H
#define BLAKE_HASH_FUNCTION_H

#include <stddef.h>

#define BLAKE_224_HASH_BITS 224
#define BLAKE_224_HASH_BYTE 28
#define BLAKE_224_SALT_BITS 128
#define BLAKE_224_SALT_BYTE 16

void blake_224_launch(const void* salt);
void blake_224_update(const void* data, size_t count);
void blake_224_finish(void* hash);

#define BLAKE_256_HASH_BITS 256
#define BLAKE_256_HASH_BYTE 32
#define BLAKE_256_SALT_BITS 128
#define BLAKE_256_SALT_BYTE 16

void blake_256_launch(const void* salt);
void blake_256_update(const void* data, size_t count);
void blake_256_finish(void* hash);

#define BLAKE_384_HASH_BITS 384
#define BLAKE_384_HASH_BYTE 48
#define BLAKE_384_SALT_BITS 256
#define BLAKE_384_SALT_BYTE 32

void blake_384_launch(const void* salt);
void blake_384_update(const void* data, size_t count);
void blake_384_finish(void* hash);

#define BLAKE_512_HASH_BITS 512
#define BLAKE_512_HASH_BYTE 64
#define BLAKE_512_SALT_BITS 256
#define BLAKE_512_SALT_BYTE 32

void blake_512_launch(const void* salt);
void blake_512_update(const void* data, size_t count);
void blake_512_finish(void* hash);

#endif /* BLAKE_HASH_FUNCTION_H */