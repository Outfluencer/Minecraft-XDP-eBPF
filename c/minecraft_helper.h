#ifndef MINECRAFT_HELPER_H
#define MINECRAFT_HELPER_H

#include <linux/types.h>
#include "common.h"

// if you are running a premium server, you can enable this, it drops weird usernames
#ifndef ONLY_ASCII_NAMES
#define ONLY_ASCII_NAMES 0
#endif

// general varint limits
#define UTF8_MAX_BYTES 3
#define UUID_LEN 16
#define MIN_VARINT_BYTES 1
#define MAX_VARINT_BYTES 5

#define PACKET_ID_MIN MIN_VARINT_BYTES
#define PACKET_ID_MAX MAX_VARINT_BYTES

// handshake packet
#define HANDSHAKE_VERSION_MIN MIN_VARINT_BYTES
#define HANDSHAKE_VERSION_MAX MAX_VARINT_BYTES

#define HANDSHAKE_HOSTLEN_MIN MIN_VARINT_BYTES
#define HANDSHAKE_HOSTLEN_MAX MAX_VARINT_BYTES

#define HANDSHAKE_HOST_DATA_MIN (0)
#define HANDSHAKE_HOST_DATA_MAX (255 * 3)

#define HANDSHAKE_PORT_LEN (2)

#define HANDSHAKE_INTENTION_MIN MIN_VARINT_BYTES
#define HANDSHAKE_INTENTION_MAX MAX_VARINT_BYTES

#define HANDSHAKE_DATA_MIN (HANDSHAKE_VERSION_MIN + HANDSHAKE_HOSTLEN_MIN + HANDSHAKE_HOST_DATA_MIN + HANDSHAKE_PORT_LEN + HANDSHAKE_INTENTION_MIN)
#define HANDSHAKE_DATA_MAX (HANDSHAKE_VERSION_MAX + HANDSHAKE_HOSTLEN_MAX + HANDSHAKE_HOST_DATA_MAX + HANDSHAKE_PORT_LEN + HANDSHAKE_INTENTION_MAX)

// login request packet
#define LOGIN_NAME_LEN_MIN MIN_VARINT_BYTES
#define LOGIN_NAME_LEN_MAX MAX_VARINT_BYTES

#define LOGIN_NAME_DATA_MIN (1)                               // empty names are not possible
#define LOGIN_NAME_DATA_MAX (16 * (ONLY_ASCII_NAMES ? 1 : UTF8_MAX_BYTES))

#define LOGIN_KEY_MIN 0
#define LOGIN_KEY_MAX 512

#define LOGIN_SIGNATURE_MIN 0
#define LOGIN_SIGNATURE_MAX 4096

#define LOGIN_PUBLIC_KEY_MIN (/*has key*/ 1)
#define LOGIN_PUBLIC_KEY_MAX (/*has key*/ 1 + /*expiry*/ 8 + /*length*/ MAX_VARINT_BYTES + LOGIN_KEY_MAX + /*length*/ MAX_VARINT_BYTES + LOGIN_SIGNATURE_MAX)

#define LOGIN_HAS_UUID_LEN 1
#define LOGIN_DATA_MIN (LOGIN_NAME_LEN_MIN + LOGIN_NAME_DATA_MIN)
#define LOGIN_DATA_MAX (LOGIN_NAME_LEN_MAX + LOGIN_NAME_DATA_MAX + LOGIN_PUBLIC_KEY_MAX + LOGIN_HAS_UUID_LEN + UUID_LEN)

struct varint_value
{
    __s32 value;
    __u32 bytes; // 1 to 5 bytes
};

static __always_inline struct varint_value varint(__s32 value, __u32 bytes)
{
    return (struct varint_value){value, bytes};
}

_Static_assert(sizeof(struct varint_value) == 8, "varint_value size mismatch!");

// Reads one varint byte, checks bounds, returns result if done, or continues
#define VARINT_BYTE(ptr, pend, dend, max, idx, shift, result)   \
    do {                                                         \
        if ((max) < (idx))                                       \
            goto error;                                          \
        if ((void *)(ptr) + 1 > (void *)(dend))                  \
            goto error;                                          \
        barrier_var(ptr);                                        \
        if ((void *)(ptr) + 1 > (void *)(pend))                  \
            goto error;                                          \
        barrier_var(ptr);                                        \
        __u8 _b = *(ptr)++;                                      \
        (result) |= ((__s32)(_b & 0x7F) << (shift));             \
        if (!(_b & 0x80))                                        \
            return varint((result), (idx));                      \
    } while (0)

static __always_inline struct varint_value read_varint_sized(__u8 *start, __u8 *payload_end, __u8 max_size, void *data_end)
{
    __s32 result = 0;

    VARINT_BYTE(start, payload_end, data_end, max_size, 1, 0, result);
    VARINT_BYTE(start, payload_end, data_end, max_size, 2, 7, result);
    VARINT_BYTE(start, payload_end, data_end, max_size, 3, 14, result);
    VARINT_BYTE(start, payload_end, data_end, max_size, 4, 21, result);
    VARINT_BYTE(start, payload_end, data_end, max_size, 5, 28, result);

error:
    return varint(0, 0);
}

#endif