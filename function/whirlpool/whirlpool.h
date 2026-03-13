/* Whirlpool
 *
 * Length of hash - 512 bit
 * Sources:
 *   https://ru.wikipedia.org/wiki/Whirlpool_(хеш-функция)
 *   http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html
 */

#ifndef WHIRLPOOL_HASH_FUNCTION_H
#define WHIRLPOOL_HASH_FUNCTION_H

#include <stddef.h>

#define WHIRLPOOL_HASH_BITS 512
#define WHIRLPOOL_HASH_BYTE 64

void whirlpool_launch(void);
void whirlpool_update(const void* data, size_t count);
void whirlpool_finish(void* hash);

#endif /* WHIRLPOOL_HASH_FUNCTION_H */