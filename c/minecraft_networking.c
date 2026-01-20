#include <linux/types.h>

#include "minecraft_helper.h"
#include "common.h"

// checks if the packet contains a valid ping request
__attribute__((noinline)) static __u8 inspect_ping_request(__u8 *start, __u8 *payload_end, void *data_end)
{
    struct varint_value varint;

    // len
    VARINT_OR_DIE(varint, start, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x09);

    // packet id
    VARINT_OR_DIE(varint, start, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x01);

    __u64 timestamp;
    READ_VAL_OR_RETURN(timestamp, start, payload_end, data_end);
    return start == payload_end;
}

// checks if the packet contains a valid status request
__attribute__((noinline)) static __u8 inspect_status_request(__u8 *start, __u8 *payload_end, void *data_end)
{
    struct varint_value varint;

    // len
    VARINT_OR_DIE(varint, start, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x01);

    // packet id
    VARINT_OR_DIE(varint, start, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x00);

    return start == payload_end;
}

// checks if the packet contains a valid login request
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/LoginRequest.java
__attribute__((noinline)) static __u8 inspect_login_packet(__u8 *reader_index, __u8 *payload_end, __s32 protocol_version, void *data_end)
{
    // length of the packet
    struct varint_value varint;

    // packet length
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
    ASSERT_IN_RANGE(varint.value, PACKET_ID_MAX + LOGIN_DATA_MIN, PACKET_ID_MAX + LOGIN_DATA_MAX);

    // packet id
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);

    // username length
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
    // bounce check, invalid username
    ASSERT_IN_RANGE(varint.value, LOGIN_NAME_DATA_MIN, LOGIN_NAME_DATA_MAX);
    // skip the username data
    READ_OR_RETURN(reader_index, varint.value, payload_end, data_end);

    // 1_19                                          1_19_3
    if (protocol_version >= 759 && protocol_version < 761)
    {
        __u8 has_public_key;
        READ_VAL_OR_RETURN(has_public_key, reader_index, payload_end, data_end);
        if (has_public_key)
        {
            // public key length
            READ_OR_RETURN(reader_index, 8, payload_end, data_end);

            // login key
            VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
            // assert reasonable size
            ASSERT_IN_RANGE(varint.value, LOGIN_KEY_MIN, LOGIN_KEY_MAX);
            // skip login key
            READ_OR_RETURN(reader_index, varint.value, payload_end, data_end);

            // signaturey length
            VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
            // assert reasonable size
            ASSERT_IN_RANGE(varint.value, LOGIN_SIGNATURE_MIN, LOGIN_SIGNATURE_MAX);
            // skip signature
            READ_OR_RETURN(reader_index, varint.value, payload_end, data_end);
        }
    }
    //  1_19_1
    if (protocol_version >= 760)
    {
        // 1_20_2
        if (protocol_version >= 764)
        {
            // check space for uuid
            READ_OR_RETURN(reader_index, 16, payload_end, data_end);
        }
        else
        {
            // check space for uuid and boolean
            __u8 has_uuid;
            READ_VAL_OR_RETURN(has_uuid, reader_index, payload_end, data_end);
            if (has_uuid)
            {
                READ_OR_RETURN(reader_index, 16, payload_end, data_end);
            }
        }
    }
    // no data left to read, this is a valid login packet
    return reader_index == payload_end;
}

// check for valid handshake packet
// note: it happens that the handshake and login or status request are in the same packet,
// so we have to check for both cases here. this can also happen after retransmition.
__attribute__((noinline)) static __s32 inspect_handshake(__u8 *reader_index, __u8 *payload_end, __s32 *protocol_version, void *data_end)
{

    if (OUT_OF_BOUNDS(reader_index, 1, payload_end, data_end))
    {
        return 0;
    }

    // check for legacy ping
    if (reader_index[0] == (__u8)0xFE)
    {
        return RECEIVED_LEGACY_PING;
    }

    // packet length
    struct varint_value varint;
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
    ASSERT_IN_RANGE(varint.value, (PACKET_ID_MIN + HANDSHAKE_DATA_MIN), (PACKET_ID_MAX + HANDSHAKE_DATA_MAX));
    // packet id
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x00); // packet id needs to be 0
    // protocol version
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
    *protocol_version = varint.value;
    // host len
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);
    ASSERT_IN_RANGE(varint.value, HANDSHAKE_HOSTLEN_MIN, HANDSHAKE_HOSTLEN_MAX);
    // read host
    READ_OR_RETURN(reader_index, varint.value, payload_end, data_end);
    // read port
    READ_OR_RETURN(reader_index, 2, payload_end, data_end);
    // intention
    VARINT_OR_DIE(varint, reader_index, payload_end, data_end);

    __s32 intention = varint.value;
    __u8 support_transfer = *protocol_version >= 766;

    // valid intentions: 1 (status), 2 (login), 3 (login with transfer request) since 766
    ASSERT_OR_RETURN((intention == 1 || intention == 2 || (support_transfer && intention == 3)));

    // this packet contained exactly the handshake
    if (reader_index == payload_end)
    {
        return intention == 1 ? AWAIT_STATUS_REQUEST : AWAIT_LOGIN;
    }

    if (intention == 1)
    {
        // the packet also contained the staus request
        if (inspect_status_request(reader_index, payload_end, data_end))
        {
            return AWAIT_PING;
        }
    }
    else
    {
        if (inspect_login_packet(reader_index, payload_end, *protocol_version, data_end))
        {
            // we received login here we have to disable the filter
            return LOGIN_FINISHED;
        }
    }

    return 0;
}
