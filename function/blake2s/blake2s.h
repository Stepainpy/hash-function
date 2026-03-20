/* BLAKE2s
 *
 * Length of hash - 256 bit
 * Length of salt - from 0 to 256 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc7693
 */

#ifndef BLAKE2S_HASH_FUNCTION_H
#define BLAKE2S_HASH_FUNCTION_H

#include <stddef.h>

#define BLAKE2S_HASH_BITS 256
#define BLAKE2S_HASH_BYTE 32
#define BLAKE2S_SALT_BITS 256
#define BLAKE2S_SALT_BYTE 32

int  blake2s_launch(const void* salt, size_t size);
void blake2s_update(const void* data, size_t count);
void blake2s_finish(void* hash);

#endif /* BLAKE2S_HASH_FUNCTION_H */