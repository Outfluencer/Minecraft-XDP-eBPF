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

struct varint_value {
    int value;
    unsigned int bytes; // 1 to 5 bytes
};

static __always_inline struct varint_value varint(int value, unsigned int bytes)
{
    return (struct varint_value) { value, bytes };
}

_Static_assert(sizeof(struct varint_value) == 8, "varint_value size mismatch!");


__always_inline struct varint_value read_varint_sized(__u8 *start, __u8 *end, __u8 max_size)
{
    // Byte 1
    if (max_size < 1 || start >= end) goto error;
    
    register __u8 b = *start++;
    register __s32 result = (b & 0x7F);
    if (!(b & 0x80)) return varint(result, 1);
    
    // Byte 2
    if (max_size < 2 || start >= end) goto error;
    b = *start++;
    result |= ((b & 0x7F) << 7);
    if (!(b & 0x80)) return varint(result, 2);
    
    // Byte 3
    if (max_size < 3 || start >= end) goto error;
    b = *start++;
    result |= ((b & 0x7F) << 14);
    if (!(b & 0x80)) return varint(result, 3);
    
    // Byte 4
    if (max_size < 4 || start >= end) goto error;
    b = *start++;
    result |= ((b & 0x7F) << 21);
    if (!(b & 0x80)) return varint(result, 4);
    
    // Byte 5
    if (max_size < 5 || start >= end) goto error;
    b = *start;
    result |= ((b & 0x7F) << 28);
    if (!(b & 0x80)) return varint(result, 5);
error:
    return varint(0, 0);
}

// checks if the packet contains a valid ping request
static __always_inline __u8 inspect_ping_request(__u8 *start, __u8 *end, __u8 *packet_end)
{
    // we could check if the timestamp is negative here
    return start + 2 <= end && packet_end - start == PING_REQUEST_LEN && start[0] == 9 && start[1] == 1;
}

// checks if the packet contains a valid status request
static __always_inline __u8 inspect_status_request(__u8 *start, __u8 *end, __u8 *packet_end)
{
    return start + 2 <= end && packet_end - start == STATUS_REQUEST_LEN && start[0] == 1 && start[1] == 0;
}

// checks if the packet contains a valid login request
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/LoginRequest.java
__attribute__((noinline)) static __u8 inspect_login_packet(__u8 *start, __u8 *end, __s32 protocol_version, __u8 *packet_end)
{
    __s64 size = packet_end - start;
    if (size > MAX_LOGIN_LEN || size < MIN_LOGIN_LEN)
        return 0;

    __u8 *reader_index = start;

    // length of the packet
    register struct varint_value varint = read_varint_sized(reader_index, end, 2);
    if (!varint.bytes || varint.value > MAX_LOGIN_LEN)
    {
        return 0;
    };
    reader_index += varint.bytes;

    // packet id
    varint = read_varint_sized(reader_index, end, 1);
    if (!varint.bytes || varint.value != 0x00)
    {
        return 0;
    };
    reader_index += varint.bytes;

    // username length
    varint = read_varint_sized(reader_index, end, 2);
    if (!varint.bytes)
    {
        return 0;
    };

    // invalid username
    if (varint.value > 16 * ( ONLY_ASCII_NAMES ? 1 : 3 ) || varint.value < 1)
    {
        return 0;
    }

    if (reader_index + varint.bytes > end)
    {
        return 0;
    }

    reader_index += varint.bytes;
    if (reader_index + varint.value > end)
    {
        return 0;
    }
    reader_index += varint.value;
    // 1_19                                          1_19_3
    if (protocol_version >= 759 && protocol_version < 761)
    {
        if (reader_index + 1 <= end)
        {
            __u8 has_public_key = reader_index[0];
            reader_index++;
            if (has_public_key)
            {
                if (reader_index + 8 > end)
                {
                    return 0;
                }
                reader_index += 8; // skip expiry time

                // login key
                varint = read_varint_sized(reader_index, end, 2);

                if (!varint.bytes)
                {
                    return 0;
                };

                if (varint.value < 0)
                {
                    return 0;
                }
                __u32 key_lenu = (__u32)varint.value;

                if (key_lenu > 512)
                {
                    return 0;
                }

                if (reader_index + varint.bytes > end)
                {
                    return 0;
                }

                reader_index += varint.bytes;

                if (reader_index + key_lenu > end)
                {
                    return 0;
                }
                reader_index += key_lenu;
                // signaturey length
                varint = read_varint_sized(reader_index, end, 2);


                if (!varint.bytes)
                {
                    return 0;
                }
                if (varint.value < 0)
                {
                    return 0;
                }
                __u32 signaturey_lenu = (__u32)varint.value;
                if (signaturey_lenu > 4096)
                {
                    return 0;
                }
                if (reader_index + varint.bytes > end)
                {
                    return 0;
                }
                reader_index += varint.bytes;
                if (reader_index + signaturey_lenu > end)
                {
                    return 0;
                }
                reader_index += signaturey_lenu;
            }
        }
        else
        {
            return 0;
        }
    }
    //  1_19_1
    if (protocol_version >= 760)
    {
        // 1_20_2
        if (protocol_version >= 764)
        {
            // check space for uuid
            if (reader_index + 16 > end)
            {
                return 0;
            }
            reader_index += 16;
        }
        else
        {
            // check space for uuid and boolean
            if (reader_index + 1 > end)
            {
                return 0;
            }
            __u8 has_uuid = reader_index[0];
            reader_index++;
            if (has_uuid)
            {
                if (reader_index + 16 > end)
                {
                    return 0;
                }
                reader_index += 16;
            }
        }
    }
    // no data left to read, this is a valid login packet
    return reader_index == packet_end;
}

// Check for valid handshake packet
// Note: it happens that the handshake and login or status request are in the same packet,
// so we have to check for both cases here.
// this can also happen after retransmition.
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/Handshake.java
__attribute__((noinline)) static __s32 inspect_handshake(__u8 *start, __u8 *end, __s32 *protocol_version, __u8 *packet_end)
{

    if (start + 1 <= end)
    {
        if (start[0] == (__u8)0xFE)
        {
            return RECEIVED_LEGACY_PING;
        }
    }

    __s64 size = packet_end - start;
    if (size > MAX_HANDSHAKE_LEN + MAX_LOGIN_LEN || size < MIN_HANDSHAKE_LEN)
    {
        return 0;
    }

    __u8 *reader_index = start;
    // packet length
    register struct varint_value varint = read_varint_sized(reader_index, end, 2);
    if (!varint.bytes || varint.value > MAX_HANDSHAKE_LEN)
    {
        return 0;
    };
    reader_index += varint.bytes;

    //packet id
    varint = read_varint_sized(reader_index, end, 1);
    if (!varint.bytes || varint.value != 0x00)
    {
        return 0;
    };
    reader_index += varint.bytes;

    // protocol version 
    varint = read_varint_sized(reader_index, end, 5);
    if (!varint.bytes)
    {
        return 0;
    };
    *protocol_version = varint.value;

    reader_index += varint.bytes;

    // host len
    varint = read_varint_sized(reader_index, end, 2);

    if (!varint.bytes)
    {
        return 0;
    };

    if (varint.value > 255 * 3 || varint.value < 1)
    {
        return 0;
    }

    if (reader_index + varint.bytes > end)
        return 0;
    reader_index += varint.bytes;
    if (reader_index + varint.value > end)
        return 0;
    reader_index += varint.value;
    if (reader_index + 2 > end)
        return 0;
    reader_index += 2;

    // intention
    varint = read_varint_sized(reader_index, end, 1);
    __s32 intention = varint.value;
    if (!varint.bytes || (intention != 1 && intention != 2 && (*protocol_version >= 766 ? intention != 3 : 1)))
    {
        return 0;
    };
    reader_index += varint.bytes;

    // this packet contained exactly the handshake
    if (reader_index == packet_end)
    {
        return intention == 1 ? AWAIT_STATUS_REQUEST : AWAIT_LOGIN;
    }

    if (intention == 1)
    {
        // the packet also contained the staus request
        if (inspect_status_request(reader_index, end, packet_end))
        {
            return AWAIT_PING;
        }
    }
    else
    {
        if (inspect_login_packet(reader_index, end, *protocol_version, packet_end))
        {
            // we received login here we have to disable the filter
            return LOGIN_FINISHED;
        }
    }

    return 0;
}
