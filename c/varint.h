#ifndef VARINT_H
#define VARINT_H

#include <linux/types.h>

#include "common.h"

/*
 * Bounded reader for Minecraft VarInts.
 *
 * VarInts encode 7 bits per byte, least significant group first; the high
 * bit of each byte marks continuation. A 32-bit value therefore occupies at
 * most 5 bytes.
 */

#define MIN_VARINT_BYTES 1
#define MAX_VARINT_BYTES 5

// number of bytes a compile-time constant occupies when varint-encoded
#define VARINT_SIZE(n)                     \
    (((__u32)(n) <= 0x7F)      ? 1 :       \
     ((__u32)(n) <= 0x3FFF)    ? 2 :       \
     ((__u32)(n) <= 0x1FFFFF)  ? 3 :       \
     ((__u32)(n) <= 0xFFFFFFF) ? 4 : 5)

struct varint_value
{
    __s32 value;
    __u32 bytes; // bytes consumed (1 to 5), 0 on parse failure
};
_Static_assert(sizeof(struct varint_value) == 8, "varint_value size mismatch!");

static __always_inline struct varint_value varint(__s32 value, __u32 bytes)
{
    return (struct varint_value){value, bytes};
}

// One unrolled step of read_varint_sized(): bounds-check one byte, fold it
// into result, and return from the enclosing function once the continuation
// bit ends. Must be a macro because it returns/jumps on behalf of its caller;
// the manual unrolling keeps the parse loop verifier-friendly.
#define VARINT_BYTE(ptr, pend, dend, max, idx, shift, result)    \
    do                                                           \
    {                                                            \
        if ((max) < (idx))                                       \
            goto error;                                          \
        if ((const void *)(ptr) + 1 > (const void *)(dend))      \
            goto error;                                          \
        barrier_var(ptr);                                        \
        if ((const void *)(ptr) + 1 > (const void *)(pend))      \
            goto error;                                          \
        barrier_var(ptr);                                        \
        __u8 _b = *(ptr)++;                                      \
        (result) |= ((__s32)(_b & 0x7F) << (shift));             \
        if (!(_b & 0x80))                                        \
            return varint((result), (idx));                      \
    } while (0)

// reads a varint of at most max_size bytes, never touching memory beyond
// payload_end/data_end; returns {0, 0} on any violation
static __always_inline struct varint_value read_varint_sized(const __u8 *cursor, const __u8 *payload_end, const __u8 max_size, const void *data_end)
{
    __s32 result = 0;

    VARINT_BYTE(cursor, payload_end, data_end, max_size, 1, 0, result);
    VARINT_BYTE(cursor, payload_end, data_end, max_size, 2, 7, result);
    VARINT_BYTE(cursor, payload_end, data_end, max_size, 3, 14, result);
    VARINT_BYTE(cursor, payload_end, data_end, max_size, 4, 21, result);
    VARINT_BYTE(cursor, payload_end, data_end, max_size, 5, 28, result);

error:
    return varint(0, 0);
}

// reads a varint of at most max bytes into dest and advances ptr past it,
// or returns 0 from the calling function on failure
#define READ_VARINT_OR_RETURN(dest, ptr, pend, dend, max)        \
    do                                                           \
    {                                                            \
        dest = read_varint_sized(ptr, pend, max, dend);          \
        if (!(dest).bytes)                                       \
            return 0;                                            \
        (ptr) += (dest).bytes;                                   \
        barrier_var(ptr);                                        \
    } while (0)

#endif
