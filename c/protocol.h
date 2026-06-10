#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <linux/types.h>

#include "common.h"
#include "config.h"
#include "varint.h"

/*
 * Inspection of the first Minecraft protocol packets of a connection.
 *
 * Every inspector walks the TCP payload with a bounds-checked cursor and
 * returns 0 (STATE_INVALID) as soon as anything does not look like a valid
 * packet of the expected type. Wire format reference:
 * https://github.com/SpigotMC/BungeeCord/tree/master/protocol
 */

// size limits, derived from the protocol definitions
#define UTF8_MAX_BYTES 3
#define UUID_LEN 16

#define PACKET_ID_MIN MIN_VARINT_BYTES
#define PACKET_ID_MAX MAX_VARINT_BYTES

// handshake packet: protocol version, server host, server port, intention
#define HANDSHAKE_VERSION_MIN MIN_VARINT_BYTES
#define HANDSHAKE_VERSION_MAX MAX_VARINT_BYTES

#define HANDSHAKE_HOSTLEN_MIN MIN_VARINT_BYTES
#define HANDSHAKE_HOSTLEN_MAX MAX_VARINT_BYTES

#define HANDSHAKE_HOST_DATA_MIN (0)
#define HANDSHAKE_HOST_DATA_MAX (255 * UTF8_MAX_BYTES)

#define HANDSHAKE_PORT_LEN (2)

#define HANDSHAKE_INTENTION_MIN MIN_VARINT_BYTES
#define HANDSHAKE_INTENTION_MAX MAX_VARINT_BYTES

#define HANDSHAKE_DATA_MIN (HANDSHAKE_VERSION_MIN + HANDSHAKE_HOSTLEN_MIN + HANDSHAKE_HOST_DATA_MIN + HANDSHAKE_PORT_LEN + HANDSHAKE_INTENTION_MIN)
#define HANDSHAKE_DATA_MAX (HANDSHAKE_VERSION_MAX + HANDSHAKE_HOSTLEN_MAX + HANDSHAKE_HOST_DATA_MAX + HANDSHAKE_PORT_LEN + HANDSHAKE_INTENTION_MAX)

// login request packet: username, optional public key (1.19 to 1.19.2), uuid
#define LOGIN_NAME_LEN_MIN MIN_VARINT_BYTES
#define LOGIN_NAME_LEN_MAX MAX_VARINT_BYTES

#define LOGIN_NAME_DATA_MIN (1) // empty names are not possible
#define LOGIN_NAME_DATA_MAX (16 * UTF8_MAX_BYTES)

#define LOGIN_KEY_MIN 0
#define LOGIN_KEY_MAX 512

#define LOGIN_SIGNATURE_MIN 0
#define LOGIN_SIGNATURE_MAX 4096

#define LOGIN_PUBLIC_KEY_MIN (/*has key*/ 1)
#define LOGIN_PUBLIC_KEY_MAX (/*has key*/ 1 + /*expiry*/ 8 + /*length*/ MAX_VARINT_BYTES + LOGIN_KEY_MAX + /*length*/ MAX_VARINT_BYTES + LOGIN_SIGNATURE_MAX)

#define LOGIN_HAS_UUID_LEN 1
#define LOGIN_DATA_MIN (LOGIN_NAME_LEN_MIN + LOGIN_NAME_DATA_MIN)
#define LOGIN_DATA_MAX (LOGIN_NAME_LEN_MAX + LOGIN_NAME_DATA_MAX + LOGIN_PUBLIC_KEY_MAX + LOGIN_HAS_UUID_LEN + UUID_LEN)

/*
 * Validates the handshake packet and returns the resulting connection state,
 * or 0 if the packet is invalid. A client may append the status request or
 * login packet to the same TCP segment (also seen after retransmissions); in
 * that case a DIRECT_READ_* state is returned and *resume_cursor points at
 * the remaining payload so the caller can continue inspecting it.
 */
static __always_inline __s32 inspect_handshake(const __u8 *cursor, const __u8 *payload_end, const void *data_end, __s32 *protocol_version, const __u8 **resume_cursor)
{
    CHECK_BOUNDS_OR_RETURN(cursor, 1, payload_end, data_end);
    // pre-1.7 clients open with 0xFE instead of a length prefix
    if (cursor[0] == (__u8)0xFE)
    {
        return RECEIVED_LEGACY_PING;
    }

    struct varint_value varint;

    // packet length
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(PACKET_ID_MAX + HANDSHAKE_DATA_MAX));
    ASSERT_IN_RANGE_OR_RETURN(varint.value, PACKET_ID_MIN + HANDSHAKE_DATA_MIN, PACKET_ID_MAX + HANDSHAKE_DATA_MAX);

    // packet id, must be 0
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(0x00));
    ASSERT_OR_RETURN(varint.value == 0x00);

    // protocol version
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, MAX_VARINT_BYTES);
    *protocol_version = varint.value;

    // host length, then skip the host data
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(HANDSHAKE_HOST_DATA_MAX));
    ASSERT_IN_RANGE_OR_RETURN(varint.value, HANDSHAKE_HOST_DATA_MIN, HANDSHAKE_HOST_DATA_MAX);
    SKIP_OR_RETURN(cursor, varint.value, payload_end, data_end);

    // server port
    SKIP_OR_RETURN(cursor, HANDSHAKE_PORT_LEN, payload_end, data_end);

    // intention: 1 (status), 2 (login), 3 (login via transfer, since 1.20.5)
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(3));
    const __s32 intention = varint.value;
    const __u8 supports_transfer = *protocol_version >= 766;
    ASSERT_OR_RETURN(intention == 1 || intention == 2 || (supports_transfer && intention == 3));

    // packet contained exactly the handshake
    if (cursor == payload_end)
    {
        return intention == 1 ? AWAIT_STATUS_REQUEST : AWAIT_LOGIN;
    }

    // more protocol data follows in the same packet
    *resume_cursor = cursor;
    return intention == 1 ? DIRECT_READ_STATUS_REQUEST : DIRECT_READ_LOGIN;
}

// returns 1 if the payload is exactly one valid status request packet
static __always_inline __u8 inspect_status_request(const __u8 *cursor, const __u8 *payload_end, const void *data_end)
{
    struct varint_value varint;

    // packet length, must be 1
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(0x01));
    ASSERT_OR_RETURN(varint.value == 0x01);

    // packet id, must be 0
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(0x00));
    ASSERT_OR_RETURN(varint.value == 0x00);

    return cursor == payload_end;
}

// returns 1 if the payload is exactly one valid ping request packet
static __always_inline __u8 inspect_ping_request(const __u8 *cursor, const __u8 *payload_end, const void *data_end)
{
    struct varint_value varint;

    // packet length, must be 9 (packet id + 8 byte timestamp)
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(0x09));
    ASSERT_OR_RETURN(varint.value == 0x09);

    // packet id, must be 1
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(0x01));
    ASSERT_OR_RETURN(varint.value == 0x01);

    __u64 timestamp;
    READ_VAL_OR_RETURN(timestamp, cursor, payload_end, data_end);
    return cursor == payload_end;
}

// returns 1 if the payload is exactly one valid login request packet
static __always_inline __u8 inspect_login_packet(const __u8 *cursor, const __u8 *payload_end, const void *data_end, const __s32 protocol_version)
{
    struct varint_value varint;

    // packet length
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(PACKET_ID_MAX + LOGIN_DATA_MAX));
    ASSERT_IN_RANGE_OR_RETURN(varint.value, PACKET_ID_MIN + LOGIN_DATA_MIN, PACKET_ID_MAX + LOGIN_DATA_MAX);

    // packet id, must be 0
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(0x00));
    ASSERT_OR_RETURN(varint.value == 0x00);

    // username length, then skip the username data
    READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(ONLINE_NAMES ? 16 : LOGIN_NAME_DATA_MAX));
    ASSERT_IN_RANGE_OR_RETURN(varint.value, LOGIN_NAME_DATA_MIN, ONLINE_NAMES ? 16 : LOGIN_NAME_DATA_MAX);
    SKIP_OR_RETURN(cursor, varint.value, payload_end, data_end);

    // optional chat signing key, 1.19 (759) up to 1.19.3 (761)
    if (protocol_version >= 759 && protocol_version < 761)
    {
        __u8 has_public_key;
        READ_VAL_OR_RETURN(has_public_key, cursor, payload_end, data_end);
        if (has_public_key)
        {
            // expiry timestamp
            SKIP_OR_RETURN(cursor, 8, payload_end, data_end);

            // public key length, then skip the key
            READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(LOGIN_KEY_MAX));
            ASSERT_IN_RANGE_OR_RETURN(varint.value, LOGIN_KEY_MIN, LOGIN_KEY_MAX);
            SKIP_OR_RETURN(cursor, varint.value, payload_end, data_end);

            // signature length, then skip the signature
            READ_VARINT_OR_RETURN(varint, cursor, payload_end, data_end, VARINT_SIZE(LOGIN_SIGNATURE_MAX));
            ASSERT_IN_RANGE_OR_RETURN(varint.value, LOGIN_SIGNATURE_MIN, LOGIN_SIGNATURE_MAX);
            SKIP_OR_RETURN(cursor, varint.value, payload_end, data_end);
        }
    }

    // uuid, optional from 1.19.1 (760), always present since 1.20.2 (764)
    if (protocol_version >= 760)
    {
        if (protocol_version >= 764)
        {
            SKIP_OR_RETURN(cursor, UUID_LEN, payload_end, data_end);
        }
        else
        {
            __u8 has_uuid;
            READ_VAL_OR_RETURN(has_uuid, cursor, payload_end, data_end);
            if (has_uuid)
            {
                SKIP_OR_RETURN(cursor, UUID_LEN, payload_end, data_end);
            }
        }
    }

    // valid only if the packet ends exactly here
    return cursor == payload_end;
}

#endif
