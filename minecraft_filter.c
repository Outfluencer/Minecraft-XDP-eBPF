#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

#define HIT_COUNT 10

// Minecraft server port
const __u16 MINECRAFT_PORT = __constant_htons(25565);
const __u16 ETH_IP_PROTO = __constant_htons(ETH_P_IP);

// length pre checks
const __s64 MIN_HANDSHAKE_LEN = 1 + 1 + 1 + 2 + 2 + 1;
const __s64 MAX_HANDSHAKE_LEN = 2 + 1 + 5 + (255 * 3) + 2;
const __s64 MIN_LOGIN_LEN = 1 + 1 + 2; // drop empty names instantly
const __s64 STATUS_REQUEST_LEN = 2;
const __s64 PING_REQUEST_LEN = 10;
const __s64 MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 8 + 512 + 2 + 4096 + 2; // len, packetid, name, profilekey, uuid

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_flow_key);
    __type(value, struct initial_state);
} conntrack_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct ipv4_flow_key);
    __type(value, __u64); // last seen timestamp
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} player_connection_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);   // ipv4 address (4 bytes)
    __type(value, __u64); // blocked at time
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);   // ipv4 address (4 bytes)
    __type(value, __u32); // how many connections
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_throttle SEC(".maps");

static __always_inline __u8 detect_tcp_bypass(struct tcphdr *tcp)
{
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) || // no SYN/ACK/FIN/RST flag
        (tcp->syn && tcp->ack) ||                             // SYN+ACK from external (unexpected)
        tcp->urg)
    { // Drop if URG flag is set
        return 1;
    }
    return 0;
}

// Read Minecraft varint
__attribute__((noinline)) static __u32 read_varint_sized(__s8 *start, __s8 *end, __s32 *return_value, __u8 max_size)
{
    // i don't do loops in ebf
    if (start > end)
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

// Check for valid status request packet
static __always_inline __u8 inspect_status_request(__s8 *start, __s8 *end, __s8 *packet_end)
{
    return start + 2 <= end && packet_end - start == STATUS_REQUEST_LEN && start[0] == 1 && start[1] == 0;
}

// Check for valid login request packet
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
                // i hate this bpf verfier );, we can't merge this if's together
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

                // i hate this bpf verfier );, we can't merge this if's together
                if (!signaturey_len_bytes)
                {
                    return 0;
                };
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
__attribute__((noinline)) static __s32 inspect_handshake(__s8 *start, __s8 *end, __s32 *protocol_version, __u16 tcp_dest, __s8 *packet_end)
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

    // we could check if the version as state 3 (transfer) but as BungeeCord ignores it i also do so for now
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

static __always_inline __u8 inspect_ping_request(__s8 *start, __s8 *end, __s8 *packet_end)
{
    return start + 2 <= end && packet_end - start == PING_REQUEST_LEN && start[0] == 9 && start[1] == 1;
}

/*
 * Blocks the ip iü of the connection and drops the packet
 */
static __s32 block_and_drop(struct ipv4_flow_key *flow_key)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 src_ip = flow_key->src_ip;
    bpf_map_update_elem(&blocked_ips, &src_ip, &now, BPF_ANY);
    bpf_map_delete_elem(&conntrack_map, flow_key);
    return XDP_DROP;
}
/*
 * Out of order tcp data, drop or block if to many
 */
static __s32 out_of_order(struct initial_state *initial_state, struct ipv4_flow_key *flow_key)
{
    if (++initial_state->fails > MAX_OUT_OF_ORDER)
    {
        return block_and_drop(flow_key);
    }
    bpf_map_update_elem(&conntrack_map, flow_key, initial_state, BPF_ANY);
    return XDP_DROP;
}

/*
 * Tries to update the initial state
 * If unsuccessfull drops the packet, otherwise pass
 */
static __s32 update_state_or_drop(struct initial_state *initial_state, struct ipv4_flow_key *flow_key)
{
    if (bpf_map_update_elem(&conntrack_map, flow_key, initial_state, BPF_ANY) < 0)
    {
        // could not update the value, we need to drop and hope it works next time
        return XDP_DROP;
    }
    return XDP_PASS;
}

/*
 * Removes connection from initial map and puts it into the player map
 * No more packets of this connection will be checked now
 */
static __u32 switch_to_verified(struct ipv4_flow_key *flow_key)
{
    bpf_map_delete_elem(&conntrack_map, flow_key);
    __u64 now = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&player_connection_map, flow_key, &now, BPF_ANY) < 0)
    {
        return XDP_DROP;
    }
    return XDP_PASS;
}

SEC("xdp")
__s32 minecraft_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_ABORTED;
    }

    if (eth->h_proto != ETH_IP_PROTO)
    {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5)
    {
        return XDP_ABORTED;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    __u16 ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
    {
        return XDP_ABORTED;
    }

    // Check if TCP destination port matches mc server port
    if (tcp->dest != MINECRAFT_PORT)
    {
        return XDP_PASS; // not for our service
    }

    if (tcp->doff < 5)
    {
        return XDP_ABORTED;
    }

    __u32 tcp_hdr_len = tcp->doff * 4;
    if ((void *)tcp + tcp_hdr_len > data_end)
    {
        return XDP_ABORTED;
    }

    // Additional TCP bypass checks for abnormal flags
    if (detect_tcp_bypass(tcp))
    {
        return XDP_DROP;
    }

    __u32 src_ip = ip->saddr;

    // stateless new connection checks
    if (tcp->syn)
    {
        // drop syn's of new connections if blocked
        __u64 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (blocked)
        {
            return XDP_DROP;
        }

        // connection throttle
        // 10 connection per ip per 3 seconds, otherwise drop
        __u32 *hit_counter = bpf_map_lookup_elem(&connection_throttle, &src_ip);
        if (hit_counter)
        {
            __u32 count = *hit_counter;
            if (count > HIT_COUNT)
            {
                return XDP_DROP;
            }
            count++;
            if (bpf_map_update_elem(&connection_throttle, &src_ip, &count, BPF_ANY) < 0)
            {
                return XDP_DROP;
            }
        }
        else
        {
            __u32 new_counter = 1;
            if (bpf_map_update_elem(&connection_throttle, &src_ip, &new_counter, BPF_ANY) < 0)
            {
                return XDP_DROP;
            }
        }

        struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
        struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);

        if (initial_state)
        {
            return XDP_DROP; // drop, we already have a connection
        }
        // it's a valid new SYN, create a new flow entry
        struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, __builtin_bswap32(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
    // Compute flow key for TCP connection
    __u64 *lastTime = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (lastTime)
    {
        __u64 now = bpf_ktime_get_ns();
        if (*lastTime + SECOND_TO_NANOS < now)
        {
            if (bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY) < 0)
            {
                // not sure how to handle this, just ignore?
            }
        }
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!initial_state)
    {
        return XDP_DROP; // no connection, pass
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack or invalid ack number
        if (!tcp->ack || initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            return XDP_DROP;
        }
        initial_state->state = state = AWAIT_MC_HANDSHAKE;
        if (bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_ANY) < 0)
        {
            // we could not update the value we need to drop.
            return XDP_DROP;
        }
        // do not return here, the ack of the tcp handshake can contain application data
        // return XDP_PASS;
    }

    __s8 *tcp_payload = (__s8 *)((__u8 *)tcp + tcp_hdr_len);
    __s8 *tcp_payload_end = (__s8 *)data_end;

    __u16 ip_total_len = __builtin_bswap16(ip->tot_len);

    // Check: sind IP-Header und TCP-Header im IP-Paket enthalten?
    __u16 tcp_payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    __s8 *packet_end = tcp_payload + tcp_payload_len;

    // tcp packet is split in multiple ethernet frames, we don't support that
    if (packet_end > tcp_payload_end)
    {
        return block_and_drop(&flow_key);
    }

    if (tcp_payload < tcp_payload_end && tcp_payload < packet_end)
    {

        if (!tcp->ack)
        {
            return block_and_drop(&flow_key);
        }

        // we fully track the tcp packet order with this check,
        // this mean we can hard punish invalid packets below, as they are not out of order
        // but invalid data
        if (initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            return out_of_order(initial_state, &flow_key);
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, &initial_state->protocol, tcp->dest, packet_end);
            // if the first packet has invalid length, we can block it
            // even with retransmition this len should always be valid‚
            if (!next_state)
            {
                return block_and_drop(&flow_key);
            }

            if (next_state == RECEIVED_LEGACY_PING)
            { // fully drop legacy ping
                bpf_map_delete_elem(&conntrack_map, &flow_key);
                return XDP_DROP;
            }

            initial_state->state = next_state;
            initial_state->expected_sequence += tcp_payload_len;
            return next_state == LOGIN_FINISHED ? switch_to_verified(&flow_key) : update_state_or_drop(initial_state, &flow_key);
        }
        else if (state == AWAIT_STATUS_REQUEST)
        {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, packet_end))
            {
                return block_and_drop(&flow_key);
            }
            initial_state->state = AWAIT_PING;
            initial_state->expected_sequence += tcp_payload_len;
            return update_state_or_drop(initial_state, &flow_key);
        }
        else if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, packet_end))
            {
                return block_and_drop(&flow_key);
            }
            initial_state->state = PING_COMPLETE;
            initial_state->expected_sequence += tcp_payload_len;
            return update_state_or_drop(initial_state, &flow_key);
        }
        else if (state == AWAIT_LOGIN)
        {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, initial_state->protocol, packet_end))
            {
                return block_and_drop(&flow_key);
            }
            return switch_to_verified(&flow_key);
        }
        else if (state == PING_COMPLETE)
        {
            bpf_map_delete_elem(&conntrack_map, &flow_key);
            return XDP_DROP;
        }
        else
        {
            // should never happen
        }
    }
    else
    {
        // bpf_printk("no payload seq %lu, ack %lu", __builtin_bswap32(tcp->seq), __builtin_bswap32(tcp->ack_seq));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Proprietary";