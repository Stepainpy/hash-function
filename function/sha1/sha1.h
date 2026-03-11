/* Secure Hash Algorithm 1 (SHA-1)
 *
 * Length of hash - 160 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc3174
 */

#ifndef SHA1_HASH_FUNCTION_H
#define SHA1_HASH_FUNCTION_H

#include <stddef.h>

#define SHA1_HASH_BITS 160
#define SHA1_HASH_BYTE 20

void sha1_launch(void);
void sha1_update(const void* data, size_t count);
void sha1_finish(void* hash);

#endif /* SHA1_HASH_FUNCTION_H */