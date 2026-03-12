/* Message Digest 5 (MD5)
 *
 * Length of hash - 128 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc1321
 */

#ifndef MD5_HASH_FUNCTION_H
#define MD5_HASH_FUNCTION_H

#include <stddef.h>

#define MD5_HASH_BITS 128
#define MD5_HASH_BYTE 16

void md5_launch(void);
void md5_update(const void* data, size_t count);
void md5_finish(void* hash);

#endif /* MD5_HASH_FUNCTION_H */