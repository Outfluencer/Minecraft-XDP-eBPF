#include <linux/types.h>

// length pre checks
const __s64 MIN_HANDSHAKE_LEN = 1 + 1 + 1 + 2 + 2 + 1;
const __s64 MAX_HANDSHAKE_LEN = 2 + 1 + 5 + (255 * 3) + 2;
const __s64 MIN_LOGIN_LEN = 1 + 1 + 2; // drop empty names instantly
const __s64 STATUS_REQUEST_LEN = 2;
const __s64 PING_REQUEST_LEN = 10;
const __s64 MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 8 + 512 + 2 + 4096 + 2; // len, packetid, name, profilekey, uuid

// Read Minecraft varint
__attribute__((noinline)) static __u32 read_varint_sized(__s8 *start, __s8 *end, __s32 *return_value, __u8 max_size)
{
    // instant return if read already on the end
    if (start >= end)
        return 0;

    if (max_size < 1 || start + 1 > end)
        return 0;
    __s8 first = start[0];
    if ((first & 0x80) == 0)
    {
        *return_value = first;
        return 1;
    }

    if (max_size < 2 || start + 2 > end)
        return 0;
    __s8 second = start[1];
    if ((second & 0x80) == 0)
    {
        *return_value = (first & 0x7F) | ((second & 0x7F) << 7);
        return 2;
    }

    if (max_size < 3 || start + 3 > end)
        return 0;
    __s8 third = start[2];
    if ((third & 0x80) == 0)
    {
        *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14);
        return 3;
    }

    if (max_size < 4 || start + 4 > end)
        return 0;
    __s8 fourth = start[3];
    if ((fourth & 0x80) == 0)
    {
        *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14) | ((fourth & 0x7F) << 21);
        return 4;
    }

    if (max_size < 5 || start + 5 > end)
        return 0;
    __s8 fifth = start[4];
    if ((fifth & 0x80) == 0)
    {
        *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14) | ((fourth & 0x7F) << 21) | ((fifth & 0x7F) << 28);
        return 5;
    }
    // varint to big
    return 0;
}

// checks if the packet contains a valid ping request
static __always_inline __u8 inspect_ping_request(__s8 *start, __s8 *end, __s8 *packet_end)
{
    // we could check if the timestamp is negative here
    return start + 2 <= end && packet_end - start == PING_REQUEST_LEN && start[0] == 9 && start[1] == 1;
}

// checks if the packet contains a valid status request
static __always_inline __u8 inspect_status_request(__s8 *start, __s8 *end, __s8 *packet_end)
{
    return start + 2 <= end && packet_end - start == STATUS_REQUEST_LEN && start[0] == 1 && start[1] == 0;
}

// checks if the packet contains a valid login request
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/LoginRequest.java
__attribute__((noinline)) static __u8 inspect_login_packet(__s8 *start, __s8 *end, __s32 protocol_version, __s8 *packet_end)
{
    __s64 size = packet_end - start;
    if (size > MAX_LOGIN_LEN || size < MIN_LOGIN_LEN)
        return 0;

    __s8 *reader_index = start;
    __s32 packet_len;
    __u32 packet_len_bytes = read_varint_sized(start, end, &packet_len, 2);
    if (!packet_len_bytes || packet_len > MAX_LOGIN_LEN)
    {
        return 0;
    };
    reader_index += packet_len_bytes;

    __s32 packet_id;
    __u32 packet_id_bytes = read_varint_sized(reader_index, end, &packet_id, 1);
    if (!packet_id_bytes || packet_id != 0x00)
    {
        return 0;
    };
    reader_index += packet_id_bytes;

    __s32 name_len;
    __u32 name_len_bytes = read_varint_sized(reader_index, end, &name_len, 2);
    if (!name_len_bytes)
    {
        return 0;
    };

    // invalid username
    if (name_len > 16 * 3 || name_len < 1)
    {
        return 0;
    }

    if (reader_index + name_len_bytes > end)
    {
        return 0;
    }

    reader_index += name_len_bytes;
    if (reader_index + name_len > end)
    {
        return 0;
    }
    reader_index += name_len;
    // 1_19                                          1_19_3
    if (protocol_version >= 759 && protocol_version < 761)
    {
        if (reader_index + 1 <= end)
        {
            __s8 has_public_key = reader_index[0];
            reader_index++;
            if (has_public_key)
            {
                if (reader_index + 8 > end)
                {
                    return 0;
                }
                reader_index += 8; // skip expiry time
                __s32 key_len;
                __u32 key_len_bytes = read_varint_sized(reader_index, end, &key_len, 2);

                if (!key_len_bytes)
                {
                    return 0;
                };
                if (key_len < 0)
                {
                    return 0;
                }
                __u32 key_lenu = (__u32)key_len;

                if (key_lenu > 512)
                {
                    return 0;
                }

                if (reader_index + key_len_bytes > end)
                {
                    return 0;
                }

                reader_index += key_len_bytes;

                if (reader_index + key_lenu > end)
                {
                    return 0;
                }
                reader_index += key_lenu;
                __s32 signaturey_len;
                __u32 signaturey_len_bytes = read_varint_sized(reader_index, end, &signaturey_len, 2);

                if (!signaturey_len_bytes)
                {
                    return 0;
                }
                if (signaturey_len < 0)
                {
                    return 0;
                }
                __u32 signaturey_lenu = (__u32)signaturey_len;
                if (signaturey_lenu > 4096)
                {
                    return 0;
                }
                if (reader_index + signaturey_len_bytes > end)
                {
                    return 0;
                }
                reader_index += signaturey_len_bytes;
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
            __s8 has_uuid = reader_index[0];
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
__attribute__((noinline)) static __s32 inspect_handshake(__s8 *start, __s8 *end, __s32 *protocol_version, __s8 *packet_end)
{

    if (start + 1 <= end)
    {
        if (start[0] == (__s8)0xFE)
        {
            return RECEIVED_LEGACY_PING;
        }
    }

    __s64 size = packet_end - start;
    if (size > MAX_HANDSHAKE_LEN + MAX_LOGIN_LEN || size < MIN_HANDSHAKE_LEN)
    {
        return 0;
    }

    __s8 *reader_index = start;
    __s32 packet_len;
    __u32 packet_len_bytes = read_varint_sized(start, end, &packet_len, 2);
    if (!packet_len_bytes || packet_len > MAX_HANDSHAKE_LEN)
    {
        return 0;
    };
    reader_index += packet_len_bytes;

    __s32 packet_id;
    __u32 packet_id_bytes = read_varint_sized(reader_index, end, &packet_id, 1);
    if (!packet_id_bytes || packet_id != 0x00)
    {
        return 0;
    };
    reader_index += packet_id_bytes;

    __u32 protocol_version_bytes = read_varint_sized(reader_index, end, protocol_version, 5);
    if (!protocol_version_bytes)
    {
        return 0;
    };
    reader_index += protocol_version_bytes;

    __s32 host_len;
    __u32 host_len_bytes = read_varint_sized(reader_index, end, &host_len, 2);
    if (!host_len_bytes)
    {
        return 0;
    };

    if (host_len > 255 * 3 || host_len < 1)
    {
        return 0;
    }

    if (reader_index + host_len_bytes > end)
        return 0;
    reader_index += host_len_bytes;
    if (reader_index + host_len > end)
        return 0;
    reader_index += host_len;
    if (reader_index + 2 > end)
        return 0;
    reader_index += 2;

    __s32 intention;
    __u32 intention_bytes = read_varint_sized(reader_index, end, &intention, 1);

    if (!intention_bytes || (intention != 1 && intention != 2 && (*protocol_version >= 766 ? intention != 3 : 1)))
    {
        return 0;
    };
    reader_index += intention_bytes;

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
