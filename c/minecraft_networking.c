#include <linux/types.h>

// if you are running a premium server, you can enable this, it drops weird usernames
#ifndef ONLY_ASCII_NAMES
#define ONLY_ASCII_NAMES 0
#endif

// length pre checks
const __s64 MIN_HANDSHAKE_LEN = 1 + 1 + 1 + 2 + 2 + 1;
const __s64 MAX_HANDSHAKE_LEN = 2 + 1 + 5 + (255 * 3) + 2;
const __s64 MIN_LOGIN_LEN = 1 + 1 + 2; // drop empty names instantly
const __s64 STATUS_REQUEST_LEN = 2;
const __s64 PING_REQUEST_LEN = 10;
const __s64 MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 8 + 512 + 2 + 4096 + 2; // len, packetid, name, profilekey, uuid

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

__always_inline struct varint_value read_varint_sized(__u8 *start, __u8 *payload_end, __u8 max_size, void *data_end)
{
    // Byte 1
    if (max_size < 1 || OUT_OF_BOUNDS(start, 1, payload_end, data_end))
        goto error;

    register __u8 b = *start++;
    register __s32 result = (b & 0x7F);
    if (!(b & 0x80))    
        return varint(result, 1);

    // Byte 2
    if (max_size < 2 || OUT_OF_BOUNDS(start, 1, payload_end, data_end))
        goto error;
    b = *start++;
    result |= ((b & 0x7F) << 7);
    if (!(b & 0x80))
        return varint(result, 2);

    // Byte 3
    if (max_size < 3 || OUT_OF_BOUNDS(start, 1, payload_end, data_end))
        goto error;
    b = *start++;
    result |= ((b & 0x7F) << 14);
    if (!(b & 0x80))
        return varint(result, 3);

    // Byte 4
    if (max_size < 4 || OUT_OF_BOUNDS(start, 1, payload_end, data_end))
        goto error;
    b = *start++;
    result |= ((b & 0x7F) << 21);
    if (!(b & 0x80))
        return varint(result, 4);

    // Byte 5
    if (max_size < 5 || OUT_OF_BOUNDS(start, 1, payload_end, data_end))
        goto error;
    b = *start;
    result |= ((b & 0x7F) << 28);
    if (!(b & 0x80))
        return varint(result, 5);
    error:
        return varint(0, 0);
}

// checks if the packet contains a valid ping request
__attribute__((noinline)) static __u8 inspect_ping_request(__u8 *start, __u8 *payload_end, void *data_end)
{

    register struct varint_value varint;
    // len
    READ_VARINT_OR_RETURN(varint, start, 5, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x09);

    // packet id
    READ_VARINT_OR_RETURN(varint, start, 5, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x01);

    __u64 timestamp;
    READ_VAL_OR_RETURN(timestamp, start, payload_end, data_end);
    return start == payload_end;
}

// checks if the packet contains a valid status request
__attribute__((noinline)) static __u8 inspect_status_request(__u8 *start, __u8 *payload_end, void *data_end)
{

    #pragma unroll
    for(__u8 i = 0; i < 10; i++) {
        if ((void*)(start + i + 1) > data_end) {
            break;
        }
        __u8 value = start[i];
        struct ipv4_flow_key dump = {value, 0,0,0};
        LOG_DEBUG(dump, "status request byte");
    }

    // 1 and 6
    //__s32 len = payload_end - start;

    register struct varint_value varint;
    // len
    READ_VARINT_OR_RETURN(varint, start, 5, payload_end, data_end);
    struct ipv4_flow_key dump = {varint.value, 0,0,0};
    LOG_DEBUG(dump, "status request bytea");
    ASSERT_OR_RETURN(varint.value == 0x01);
    
    LOG_DEBUG(dump, "AFTER ASSERT_OR_RETURN(varint.value == 0x01);");
    // packet id
    READ_VARINT_OR_RETURN(varint, start, 5, payload_end, data_end);
    struct ipv4_flow_key dump2 = {varint.value, 0,0,0};
    LOG_DEBUG(dump2, "status request byteab");
    ASSERT_OR_RETURN(varint.value == 0x00);

    __u8 v = start == payload_end;
    struct ipv4_flow_key dump3 = {v, 0,0,0};
    LOG_DEBUG(dump3, "status request byteac");

    return v;
}

// checks if the packet contains a valid login request
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/LoginRequest.java
__attribute__((noinline)) static __u8 inspect_login_packet(__u8 *reader_index, __u8 *payload_end, __s32 protocol_version, void *data_end)
{
    // length of the packet
    register struct varint_value varint;

    // packet length
    READ_VARINT_OR_RETURN(varint, reader_index, 2, payload_end, data_end);
    ASSERT_IN_RANGE(varint.value, MIN_LOGIN_LEN, MAX_LOGIN_LEN);

    // packet id
    READ_VARINT_OR_RETURN(varint, reader_index, 1, payload_end, data_end);


    // username length
    READ_VARINT_OR_RETURN(varint, reader_index, 2, payload_end, data_end);
    // bounce check, invalid username
    ASSERT_IN_RANGE(varint.value, 1, 16 * (ONLY_ASCII_NAMES ? 1 : 3));
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
            READ_VARINT_OR_RETURN(varint, reader_index, 2, payload_end, data_end);
            // assert reasonable size
            ASSERT_IN_RANGE(varint.value, 0, 512);
            // skip login key
            READ_OR_RETURN(reader_index, varint.value, payload_end, data_end);

            // signaturey length
            READ_VARINT_OR_RETURN(varint, reader_index, 2, payload_end, data_end);
            // assert reasonable size
            ASSERT_IN_RANGE(varint.value, 0, 4096);
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

// Check for valid handshake packet
// Note: it happens that the handshake and login or status request are in the same packet,
// so we have to check for both cases here.
// this can also happen after retransmition.
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/Handshake.java
__attribute__((noinline)) static __s32 inspect_handshake(struct ipv4_flow_key *flow_key, __u8 *reader_index, __u8 *payload_end, __s32 *protocol_version, void *data_end)
{

    if(OUT_OF_BOUNDS(reader_index, 1, payload_end, data_end))
    {
        return 0;
    }

    // check for legacy ping
    if (reader_index[0] == (__u8)0xFE)
    { 
        return RECEIVED_LEGACY_PING;
    }

    // packet length
    register struct varint_value varint;
    READ_VARINT_OR_RETURN(varint, reader_index, 2, payload_end, data_end);
    ASSERT_IN_RANGE(varint.value, MIN_HANDSHAKE_LEN, MAX_HANDSHAKE_LEN);

    // packet id
    READ_VARINT_OR_RETURN(varint, reader_index, 1, payload_end, data_end);
    ASSERT_OR_RETURN(varint.value == 0x00); // packet id needs to be 0

    // protocol version
    READ_VARINT_OR_RETURN(varint, reader_index, 5, payload_end, data_end);
    *protocol_version = varint.value;

    // host len
    READ_VARINT_OR_RETURN(varint, reader_index, 2, payload_end, data_end);
    ASSERT_IN_RANGE(varint.value, 0, 255 * 3);

    // read host
    READ_OR_RETURN(reader_index, varint.value, payload_end, data_end);
    // read port
    READ_OR_RETURN(reader_index, 2, payload_end, data_end);

    // intention
    READ_VARINT_OR_RETURN(varint, reader_index, 1, payload_end, data_end);

    __s32 intention = varint.value;
    __u8 support_transfer = *protocol_version >= 766;

    // valid intentions: 1 (status), 2 (login), 3 (login with transfer request) since 766
    ASSERT_OR_RETURN((intention == 1 || intention == 2 || (support_transfer && intention == 3)));

    struct ipv4_flow_key flow_key_copy = (*flow_key);

    // this packet contained exactly the handshake
    if (reader_index == payload_end)
    {
        if(intention == 1) {
            LOG_DEBUG(flow_key_copy, "handshake with status request");
        } else {
            LOG_DEBUG(flow_key_copy, "handshake with login request");
        }

        return intention == 1 ? AWAIT_STATUS_REQUEST : AWAIT_LOGIN;
    }

    if (intention == 1)
    {
        LOG_DEBUG(flow_key_copy, "handshake with status request b");
        // the packet also contained the staus request
        if (inspect_status_request(reader_index, payload_end, data_end))
        {
            return AWAIT_PING;
        }
    }
    else
    {
        LOG_DEBUG(flow_key_copy, "handshake with login request b");
        if (inspect_login_packet(reader_index, payload_end, *protocol_version, data_end))
        {
            // we received login here we have to disable the filter
            return LOGIN_FINISHED;
        }
    }

    return 0;
}
