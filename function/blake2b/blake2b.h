/* BLAKE2b
 *
 * Length of hash - 512 bit
 * Length of salt - from 0 to 512 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc7693
 */

#ifndef BLAKE2B_HASH_FUNCTION_H
#define BLAKE2B_HASH_FUNCTION_H

#include <stddef.h>

#define BLAKE2B_HASH_BITS 512
#define BLAKE2B_HASH_BYTE 64
#define BLAKE2B_SALT_BITS 512
#define BLAKE2B_SALT_BYTE 64

int  blake2b_launch(const void* salt, size_t size);
void blake2b_update(const void* data, size_t count);
void blake2b_finish(void* hash);

#endif /* BLAKE2B_HASH_FUNCTION_H */