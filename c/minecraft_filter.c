#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "minecraft_networking.c"

#ifndef HIT_COUNT
#define HIT_COUNT 10
#endif

// make ports configurable during compilation
#ifndef START_PORT
#define START_PORT 25565
#endif

#ifndef END_PORT
#define END_PORT 25565
#endif

#ifndef BLOCK_IPS
#define BLOCK_IPS 1
#endif

#ifndef CONNECTION_THROTTLE
#define CONNECTION_THROTTLE 1
#endif

// Minecraft server port
const __u16 ETH_IP_PROTO = __constant_htons(ETH_P_IP);

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

/*
 * Blocks the ip if of the connection and drops the packet
 */
static __always_inline __s32 block_and_drop(struct ipv4_flow_key *flow_key)
{
    #if BLOCK_IPS
    __u64 now = bpf_ktime_get_ns();
    __u32 src_ip = flow_key->src_ip;
    // here we use any as we want to punish as long as possible
    bpf_map_update_elem(&blocked_ips, &src_ip, &now, BPF_ANY);
    #endif
    bpf_map_delete_elem(&conntrack_map, flow_key);
    return XDP_DROP;
}

/*
 * Tries to update the initial state
 * If unsuccessfull drops the packet, otherwise pass
 */
static __always_inline __s32 update_state_or_drop(struct initial_state *initial_state, struct ipv4_flow_key *flow_key)
{
    // if we update it it should exists, if not it was removed by another thread
    if (bpf_map_update_elem(&conntrack_map, flow_key, initial_state, BPF_EXIST) < 0)
    {
        // could not update the value, we need to drop and hope it works next time
        return XDP_DROP;
    }
    return XDP_PASS;
}
/*
 * Drops the current packet and removes the connection from the conntrack_map
 */
static __always_inline __s32 drop_connection(struct ipv4_flow_key *flow_key)
{
    bpf_map_delete_elem(&conntrack_map, flow_key);
    return XDP_DROP;
}
/*
 * Removes connection from initial map and puts it into the player map
 * No more packets of this connection will be checked now
 */
static __always_inline __u32 switch_to_verified(struct ipv4_flow_key *flow_key)
{
    bpf_map_delete_elem(&conntrack_map, flow_key);
    __u64 now = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&player_connection_map, flow_key, &now, BPF_NOEXIST) < 0)
    {
        return XDP_DROP;
    }
    return XDP_PASS;
}
#ifdef STATELESS
static __u32 check_options(__u8 *opt_ptr, __u8 *opt_end, __u8 *packet_end)
{
    __u8 *reader_index = opt_ptr;
    #pragma unroll
    for(__u8 i = 0; i < 10; i++)
    {
        if ( reader_index >= packet_end || reader_index >= opt_end)
        {
            return 0; // end of options
        }
        __u8 kind = reader_index[0];
        reader_index += 1;

        if (kind == 0)
        {
            return 0;
        }

        if (kind == 1) // NOP
        {
            continue;
        }

        if ( reader_index >= packet_end || reader_index >= opt_end)
        {
            // cannot read length, unexpected end of options
            return 1; 
        }
        __u8 len = reader_index[0];

        if (len < 2 || len > 40)
        {
            return 1; // invalid option length
        }
        reader_index += 1;

        if (kind == 2) // MSS
        {
            if (len != 4)
            {
                return 1; // invalid MSS option length
            }

            if ( reader_index + 1 >= packet_end || reader_index + 1 >= opt_end)
            {
                return 1;
            }
            __u16 mss = (__u16)(reader_index[0] << 8) | reader_index[1];
            //bpf_printk("mss: %lu", mss);
            reader_index += 2; // skip length
            continue;
        }

        if (kind == 3) // window scale
        {
            if (len != 3)
            {
                return 1; // invalid window scale option length
            }

            if ( reader_index >= packet_end || reader_index >= opt_end)
            {
                return 1; // unexpected end of options
            }
            __u8 scale = reader_index[0];
            //bpf_printk("scale: %lu", scale);
            reader_index += 1; // skip length
            continue;
        }

        if (kind == 4) // sack permitted
        {
            if (len != 2)
            {
                return 1; // invalid window scale option length
            }
           // bpf_printk("sack permitted");
            continue;
        }

        // just skiip the len if we do not know
        __u8 skip = len - 2;
    	if (reader_index + skip > packet_end || reader_index + skip > opt_end ) return 1;
    	reader_index += skip;
    }

    return 1; // too many opotions, probably attack
}
#endif

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
    __u16 dest_port = __builtin_bswap16(tcp->dest);

    #if START_PORT == END_PORT
    if (dest_port != START_PORT)
    {
        return XDP_PASS; // not for our service
    }
    #else
    if (dest_port < START_PORT || dest_port > END_PORT)
    {
        return XDP_PASS; // not for our service
    }
    #endif

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
        #if BLOCK_IPS
        __u64 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (blocked)
        {
            return XDP_DROP;
        }
        #endif

        // this works perfectly for now but, experimental 
        #ifdef STATELESS
        /* PARSE TCP OPTIONS*/
        __u8 *opt_ptr = (__u8 *)tcp + sizeof(struct tcphdr);
        __u32 opts_len = tcp_hdr_len - sizeof(struct tcphdr);
        __u8 *opt_end = opt_ptr + opts_len;

        if (check_options(opt_ptr, opt_end, (void *)data_end) != 0) {
            // invalid options, drop the packet
            return XDP_DROP;
        }
        #endif


        #if CONNECTION_THROTTLE
        // connection throttle
        // 10 connection per ip per 3 seconds, otherwise drop
        __u32 *hit_counter = bpf_map_lookup_elem(&connection_throttle, &src_ip);
        if (hit_counter)
        {
            if (*hit_counter > HIT_COUNT)
            {
                return XDP_DROP;
            }
            (*hit_counter)++;
        }
        else
        {
            __u32 new_counter = 1;
            if (bpf_map_update_elem(&connection_throttle, &src_ip, &new_counter, BPF_NOEXIST) < 0)
            {
                return XDP_DROP;
            }
        }
        #endif

        struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
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
        if (*lastTime + ( SECOND_TO_NANOS * 10 ) < now)
        {
            *lastTime = now;
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
        if (bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST) < 0)
        {
            // we could not update the value we need to drop.
            return XDP_DROP;
        }
        // do not return here, the ack of the tcp handshake can contain application data
        // return XDP_PASS;
    }

    __u8 *tcp_payload = (__u8 *)((__u8 *)tcp + tcp_hdr_len);
    __u8 *tcp_payload_end = (__u8 *)data_end;

    __u16 ip_total_len = __builtin_bswap16(ip->tot_len);

    // Check: sind IP-Header und TCP-Header im IP-Paket enthalten?
    __u16 tcp_payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    __u8 *packet_end = tcp_payload + tcp_payload_len;

    // tcp packet is split in multiple ethernet frames, we don't support that
    if (packet_end > tcp_payload_end)
    {
        goto block_and_drop;
    }

    if (tcp_payload < tcp_payload_end && tcp_payload < packet_end)
    {

        if (!tcp->ack)
        {
            goto block_and_drop;
        }

        // we fully track the tcp packet order with this check,
        // this mean we can hard punish invalid packets below, as they are not out of order
        // but invalid data
        if (initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
            {
                goto block_and_drop;
            }
            // if it does not exist the connection was closed by another thread
            bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST);
            return XDP_DROP;
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, &initial_state->protocol, packet_end);
            // if the first packet has invalid length, we can block it
            // even with retransmition this len should always be valid‚
            if (!next_state)
            {
                goto block_and_drop;
            }

            // fully drop legacy ping
            if (next_state == RECEIVED_LEGACY_PING)
            {
                return drop_connection(&flow_key);
            }

            initial_state->state = next_state;
            initial_state->expected_sequence += tcp_payload_len;
            if (next_state == LOGIN_FINISHED)
            {
                goto switch_to_verified;
            } else {
                goto update_state_or_drop;
            }
        }
        else if (state == AWAIT_STATUS_REQUEST)
        {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, packet_end))
            {
                goto block_and_drop;
            }
            initial_state->state = AWAIT_PING;
            initial_state->expected_sequence += tcp_payload_len;
            goto update_state_or_drop;
        }
        else if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, packet_end))
            {
                goto block_and_drop;
            }
            initial_state->state = PING_COMPLETE;
            initial_state->expected_sequence += tcp_payload_len;
            goto update_state_or_drop;
        }
        else if (state == AWAIT_LOGIN)
        {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, initial_state->protocol, packet_end))
            {
                goto block_and_drop;
            }
            goto switch_to_verified;
        }
        else if (state == PING_COMPLETE)
        {
            goto block_and_drop;
        }
    }
    return XDP_PASS;

// Using this labels drasticly reduce the file size
block_and_drop:
    return block_and_drop(&flow_key);
update_state_or_drop:
    return update_state_or_drop(initial_state, &flow_key);
switch_to_verified:
    return switch_to_verified(&flow_key);
}

char _license[] SEC("license") = "Proprietary";
// bpf_printk("no payload seq %lu, ack %lu", __builtin_bswap32(tcp->seq), __builtin_bswap32(tcp->ack_seq));
