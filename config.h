#ifndef HASH_FUNCTION_CONFIG_H
#define HASH_FUNCTION_CONFIG_H

/* Detecting compiler */

#if defined(__GNUC__)
#  define HSHFUNC_ON_GNUC 1
#  if defined(__clang__)
#    define HSHFUNC_ON_CLANG 1
#  else
#    define HSHFUNC_ON_GCC 1
#  endif
#elif defined(_MSC_VER)
#  define HSHFUNC_ON_MSVC 1
#else
#  error Unsupported compiler
#endif

/* Detecting endianness */

#if HSHFUNC_ON_GNUC
#  if defined(__BYTE_ORDER__)
#    if   __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#      define HSHFUNC_IS_LITTLE 1
#      define HSHFUNC_IS_BIG    0
#    elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#      define HSHFUNC_IS_LITTLE 0
#      define HSHFUNC_IS_BIG    1
#    else
#      error Unknown endianness
#    endif
#  else
#    error Not defined __BYTE_ORDER__
#  endif
#elif HSHFUNC_ON_MSVC
#  define HSHFUNC_IS_LITTLE 1
#  define HSHFUNC_IS_BIG    0
#else
#  error Unsupported compiler
#endif

/* Turning off warning "-Wlong-long" on GNUC */

#if HSHFUNC_ON_GNUC && __STDC_VERSION__ < 199901L
#  define HSHFUNC_U64_WARN_BEGIN \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wlong-long\"")
#  define HSHFUNC_U64_WARN_END \
    _Pragma("GCC diagnostic pop")
#else
#  define HSHFUNC_U64_WARN_BEGIN
#  define HSHFUNC_U64_WARN_END
#endif

/* Define fixed width integer types */

#if __STDC_VERSION__ >= 199901L

#include <stdint.h>

typedef uint8_t hshfunc_u8_t;
typedef uint16_t hshfunc_u16_t;
typedef uint32_t hshfunc_u32_t;
typedef uint64_t hshfunc_u64_t;

#else /* C89 */

#include <limits.h>

typedef unsigned char hshfunc_u8_t;
typedef unsigned short hshfunc_u16_t;

#if ULONG_MAX == 0xFFFFFFFFul
typedef unsigned long hshfunc_u32_t;
#else
typedef unsigned int  hshfunc_u32_t;
#endif

#if HSHFUNC_ON_GNUC
HSHFUNC_U64_WARN_BEGIN
typedef unsigned long long hshfunc_u64_t;
HSHFUNC_U64_WARN_END
#elif HSHFUNC_ON_MSVC
typedef unsigned __int64 hshfunc_u64_t;
#else
#  error Unsupported copmiler
#endif

#endif /* __STDC_VERSION__ >= 199901L */

/* Integer byte swap functions */

#if HSHFUNC_ON_GNUC
#  define hshfunc_bswap16 __builtin_bswap16
#  define hshfunc_bswap32 __builtin_bswap32
#  define hshfunc_bswap64 __builtin_bswap64
#elif HSHFUNC_ON_MSVC
#  include <stdlib.h>
#  define hshfunc_bswap16 _byteswap_ushort
#  define hshfunc_bswap32 _byteswap_ulong
#  define hshfunc_bswap64 _byteswap_uint64
#else
#  error Unsupported compiler
#endif

/* If condition for preprocessor */

#define HSHFUNC_CONCAT_(left, right) left ## right
#define HSHFUNC_CONCAT(left, right) HSHFUNC_CONCAT_(left, right)

#define HSHFUNC_IF_0(stmt)
#define HSHFUNC_IF_1(stmt) stmt
#define HSHFUNC_IF(cond, stmt) HSHFUNC_CONCAT(HSHFUNC_IF_, cond)(stmt)

#define HSHFUNC_IF_LITTLE(stmt) HSHFUNC_IF(HSHFUNC_IS_LITTLE, stmt)
#define HSHFUNC_IF_BIG(stmt) HSHFUNC_IF(HSHFUNC_IS_BIG, stmt)

/* Byte swapping one, pair and blocks */

#define HSHFUNC_BSWAP_B_STMT_1(bits, array) \
    (array)[0] = hshfunc_bswap##bits((array)[0]);
#define HSHFUNC_BSWAP_B_STMT_2(bits, array) \
    HSHFUNC_BSWAP_B_STMT_1(bits, array)     \
    (array)[1] = hshfunc_bswap##bits((array)[1]);
#define HSHFUNC_BSWAP_B_STMT_3(bits, array) \
    HSHFUNC_BSWAP_B_STMT_2(bits, array)     \
    (array)[2] = hshfunc_bswap##bits((array)[2]);
#define HSHFUNC_BSWAP_B_STMT_4(bits, array) \
    HSHFUNC_BSWAP_B_STMT_3(bits, array)     \
    (array)[3] = hshfunc_bswap##bits((array)[3]);
#define HSHFUNC_BSWAP_B_STMT_5(bits, array) \
    HSHFUNC_BSWAP_B_STMT_4(bits, array)     \
    (array)[4] = hshfunc_bswap##bits((array)[4]);
#define HSHFUNC_BSWAP_B_STMT_6(bits, array) \
    HSHFUNC_BSWAP_B_STMT_5(bits, array)     \
    (array)[5] = hshfunc_bswap##bits((array)[5]);
#define HSHFUNC_BSWAP_B_STMT_7(bits, array) \
    HSHFUNC_BSWAP_B_STMT_6(bits, array)     \
    (array)[6] = hshfunc_bswap##bits((array)[6]);
#define HSHFUNC_BSWAP_B_STMT_8(bits, array) \
    HSHFUNC_BSWAP_B_STMT_7(bits, array)     \
    (array)[7] = hshfunc_bswap##bits((array)[7]);
#define HSHFUNC_BSWAP_B_STMT_9(bits, array) \
    HSHFUNC_BSWAP_B_STMT_8(bits, array)     \
    (array)[8] = hshfunc_bswap##bits((array)[8]);
#define HSHFUNC_BSWAP_B_STMT_10(bits, array) \
    HSHFUNC_BSWAP_B_STMT_9(bits, array)     \
    (array)[9] = hshfunc_bswap##bits((array)[9]);
#define HSHFUNC_BSWAP_B_STMT_11(bits, array) \
    HSHFUNC_BSWAP_B_STMT_10(bits, array)     \
    (array)[10] = hshfunc_bswap##bits((array)[10]);
#define HSHFUNC_BSWAP_B_STMT_12(bits, array) \
    HSHFUNC_BSWAP_B_STMT_11(bits, array)     \
    (array)[11] = hshfunc_bswap##bits((array)[11]);
#define HSHFUNC_BSWAP_B_STMT_13(bits, array) \
    HSHFUNC_BSWAP_B_STMT_12(bits, array)     \
    (array)[12] = hshfunc_bswap##bits((array)[12]);
#define HSHFUNC_BSWAP_B_STMT_14(bits, array) \
    HSHFUNC_BSWAP_B_STMT_13(bits, array)     \
    (array)[13] = hshfunc_bswap##bits((array)[13]);
#define HSHFUNC_BSWAP_B_STMT_15(bits, array) \
    HSHFUNC_BSWAP_B_STMT_14(bits, array)     \
    (array)[14] = hshfunc_bswap##bits((array)[14]);
#define HSHFUNC_BSWAP_B_STMT_16(bits, array) \
    HSHFUNC_BSWAP_B_STMT_15(bits, array)     \
    (array)[15] = hshfunc_bswap##bits((array)[15]);

#define HSHFUNC_BSWAP_B_ONE(bits, value) do { \
    (value) = hshfunc_bswap##bits(value); \
} while (0)

#define HSHFUNC_BSWAP_BxN(number, bits, array) do { \
    HSHFUNC_BSWAP_B_STMT_##number(bits, array) \
} while (0)

/* Bit rotation functions */

#ifdef HSHFUNC_USE_ROTL32
static hshfunc_u32_t HSHFUNC_USE_ROTL32(hshfunc_u32_t n, hshfunc_u32_t s)
    { s &= 31; return n << s | n >> (-s & 31); }
#endif

#ifdef HSHFUNC_USE_ROTR32
static hshfunc_u32_t HSHFUNC_USE_ROTR32(hshfunc_u32_t n, hshfunc_u32_t s)
    { s &= 31; return n >> s | n << (-s & 31); }
#endif

#ifdef HSHFUNC_USE_ROTL64
static hshfunc_u64_t HSHFUNC_USE_ROTL64(hshfunc_u64_t n, hshfunc_u64_t s)
    { s &= 63; return n << s | n >> (-s & 63); }
#endif

#ifdef HSHFUNC_USE_ROTR64
static hshfunc_u64_t HSHFUNC_USE_ROTR64(hshfunc_u64_t n, hshfunc_u64_t s)
    { s &= 63; return n >> s | n << (-s & 63); }
#endif

#endif /* HASH_FUNCTION_CONFIG_H */