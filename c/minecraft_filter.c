#ifndef HIT_COUNT
#define HIT_COUNT 10
#endif

#ifndef START_PORT
#define START_PORT 25000
#endif
#ifndef END_PORT
#define END_PORT 26000
#endif

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "minecraft_networking.c"
#include "stats.h"

// Minecraft server port
const __u16 ETH_IP_PROTO = __constant_htons(ETH_P_IP);

struct
{
    __uint(type,
#if IP_AND_PORT_PER_CPU
           BPF_MAP_TYPE_LRU_PERCPU_HASH
#else
           BPF_MAP_TYPE_LRU_HASH
#endif
    );
    __uint(max_entries, 4096);
    __type(key, struct ipv4_flow_key);
    __type(value, struct initial_state);
} conntrack_map SEC(".maps");

struct
{
    __uint(type,
#if IP_AND_PORT_PER_CPU
           BPF_MAP_TYPE_LRU_PERCPU_HASH
#else
           BPF_MAP_TYPE_LRU_HASH
#endif
    );
    __uint(max_entries, 65535);
    __type(key, struct ipv4_flow_key);
    __type(value, __u64); // last seen timestamp
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} player_connection_map SEC(".maps");

struct
{
    __uint(type,
#if IP_PER_CPU
           BPF_MAP_TYPE_PERCPU_HASH
#else
           BPF_MAP_TYPE_HASH
#endif
    );
    __uint(max_entries, 65535);
    __type(key, __u32);   // ipv4 address (4 bytes)
    __type(value, __u32); // how many connections
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_throttle SEC(".maps");

#if PROMETHEUS_METRICS
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");
#endif

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
 * The compiler will optimize this function well
 */
static __always_inline void count_stats(struct statistics *stats_ptr, __u32 bitmask, __u64 amount)
{
#if PROMETHEUS_METRICS
    if (bitmask & INCOMING_BYTES)
    {
        stats_ptr->incoming_bytes += amount;
    }

    if (bitmask & DROPPED_BYTES)
    {
        stats_ptr->dropped_bytes += amount;
    }

    if (bitmask & IP_BLOCK)
    {
        stats_ptr->ip_blocks += amount;
    }

    if (bitmask & VERIFIED)
    {
        stats_ptr->verified += amount;
    }

    if (bitmask & DROPPED_PACKET)
    {
        stats_ptr->dropped_packets += amount;
    }

    if (bitmask & STATE_SWITCH)
    {
        stats_ptr->state_switches += amount;
    }

    if (bitmask & DROP_CONNECTION)
    {
        stats_ptr->drop_connection += amount;
    }

    if (bitmask & SYN_RECEIVE)
    {
        stats_ptr->syn += amount;
    }

    if (bitmask & TCP_BYPASS)
    {
        stats_ptr->tcp_bypass += amount;
    }
#endif
}

/*
 * Tries to update the initial state
 * If unsuccessful drops the packet, otherwise pass
 */
static __always_inline __s32 update_state_or_drop(__u64 packet_size, struct statistics *stats_ptr, struct initial_state *initial_state, struct ipv4_flow_key *flow_key)
{
    // if we update it it should exists, if not it was removed by another thread
    if (bpf_map_update_elem(&conntrack_map, flow_key, initial_state, BPF_EXIST) < 0)
    {
        // could not update the value, we need to drop and hope it works next time
        count_stats(stats_ptr, DROPPED_PACKET, 1);
        count_stats(stats_ptr, DROPPED_BYTES, packet_size);
        return XDP_DROP;
    }
    count_stats(stats_ptr, STATE_SWITCH, 1);
    return XDP_PASS;
}
/*
 * Drops the current packet and removes the connection from the conntrack_map
 */
static __always_inline void drop_connection(struct statistics *stats_ptr, struct ipv4_flow_key *flow_key)
{
    count_stats(stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, flow_key);
}
/*
 * Removes connection from initial map and puts it into the player map
 * No more packets of this connection will be checked now
 */
static __always_inline __u32 switch_to_verified(__u64 raw_packet_len, struct statistics *stats_ptr, struct ipv4_flow_key *flow_key)
{
    bpf_map_delete_elem(&conntrack_map, flow_key);
    __u64 now = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&player_connection_map, flow_key, &now, BPF_NOEXIST) < 0)
    {
        count_stats(stats_ptr, DROPPED_BYTES, raw_packet_len);
        count_stats(stats_ptr, DROP_CONNECTION | DROPPED_PACKET, 1);
        return XDP_DROP;
    }
    count_stats(stats_ptr, VERIFIED, 1);
    return XDP_PASS;
}
#if STATELESS
static __u32 check_options(__u8 *opt_ptr, __u8 *opt_end, __u8 *packet_end)
{
    __u8 *reader_index = opt_ptr;
#pragma unroll
    for (__u8 i = 0; i < 10; i++)
    {
        if (reader_index >= packet_end || reader_index >= opt_end)
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

        if (reader_index >= packet_end || reader_index >= opt_end)
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

            if (reader_index + 1 >= packet_end || reader_index + 1 >= opt_end)
            {
                return 1;
            }
            __u16 mss = (__u16)(reader_index[0] << 8) | reader_index[1];
            // bpf_printk("mss: %lu", mss);
            reader_index += 2; // skip length
            continue;
        }

        if (kind == 3) // window scale
        {
            if (len != 3)
            {
                return 1; // invalid window scale option length
            }

            if (reader_index >= packet_end || reader_index >= opt_end)
            {
                return 1; // unexpected end of options
            }
            __u8 scale = reader_index[0];
            // bpf_printk("scale: %lu", scale);
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

        // just skip the len if we do not know
        __u8 skip = len - 2;
        if (reader_index + skip > packet_end || reader_index + skip > opt_end)
            return 1;
        reader_index += skip;
    }

    return 1; // too many options, probably attack
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
        return XDP_DROP;
    }

    if (eth->h_proto != ETH_IP_PROTO)
    {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5)
    {
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
    {
        return XDP_DROP;
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

    // bpf_printk("CPU: %u SRC: %x", bpf_get_smp_processor_id(), ip->saddr);

#if PROMETHEUS_METRICS
    __u32 key = 0;
    struct statistics *stats_ptr = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats_ptr)
    {
        // this should be impossible
        return XDP_ABORTED;
    }
#else
    struct statistics *stats_ptr = 0;
#endif

    __u64 raw_packet_len = (__u64)(data_end - data);
    count_stats(stats_ptr, INCOMING_BYTES, raw_packet_len);
    __u32 src_ip = ip->saddr;
    struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
    // Additional TCP bypass checks for abnormal flags
    if (detect_tcp_bypass(tcp))
    {
        // LOG_DEBUG(flow_key, "detect_tcp_bypass");
        count_stats(stats_ptr, TCP_BYPASS, 1);
        goto drop;
    }

    // stateless new connection checks
    if (tcp->syn)
    {
        // LOG_DEBUG(flow_key, "sent syn");
        count_stats(stats_ptr, SYN_RECEIVE, 1);

// this works perfectly for now but, experimental
#if STATELESS
        /* PARSE TCP OPTIONS*/
        __u8 *opt_ptr = (__u8 *)tcp + sizeof(struct tcphdr);
        __u32 opts_len = tcp_hdr_len - sizeof(struct tcphdr);
        __u8 *opt_end = opt_ptr + opts_len;

        if (check_options(opt_ptr, opt_end, (void *)data_end) != 0)
        {
            // LOG_DEBUG(flow_key, "check_options");
            //  invalid options, drop the packet
            goto drop;
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
                // LOG_DEBUG(flow_key, "syn connection throttle");
                goto drop;
            }
            (*hit_counter)++;
        }
        else
        {
            __u32 new_counter = 1;
            if (bpf_map_update_elem(&connection_throttle, &src_ip, &new_counter, BPF_NOEXIST) < 0)
            {
                // LOG_DEBUG(flow_key, "syn could not add connection throttle map");
                goto drop;
            }
        }
#endif

        struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, __builtin_bswap32(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            // LOG_DEBUG(flow_key, "syn could not add conntrack map");
            goto drop;
        }

        return XDP_PASS;
    }

    // Compute flow key for TCP connection
    __u64 *lastTime = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (lastTime)
    {
        __u64 now = bpf_ktime_get_ns();
        if (*lastTime + (SECOND_TO_NANOS * 10) < now)
        {
            *lastTime = now;
        }
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!initial_state)
    {
        // LOG_DEBUG(flow_key, "received packet for untracked connection");
        goto drop; // no connection tracked, drop
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack or invalid ack number
        if (!tcp->ack || initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            // LOG_DEBUG(flow_key, "waiting for ack but no ack or invalid seq");
            goto drop;
        }
        // LOG_DEBUG(flow_key, "recieved ack, switch to mc handshake");
        initial_state->state = state = AWAIT_MC_HANDSHAKE;
        if (bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST) < 0)
        {
            // we could not update the value we need to drop.
            // LOG_DEBUG(flow_key, "could not update state to AWAIT_MC_HANDSHAKE");
            goto drop;
        }
        // do not return here, the ack of the tcp handshake can contain application data
        // return XDP_PASS;
    }

    __u8 *tcp_payload = (__u8 *)((__u8 *)tcp + tcp_hdr_len);

    // total length of ip packet
    __u16 ip_tot_len = __builtin_bswap16(ip->tot_len);
    // total ip - ip header - tcp header = length of tcp payload
    __u16 tcp_payload_len = ip_tot_len - (ip->ihl * 4) - tcp_hdr_len;
    // tcp payload end = start + length
    __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // tcp packet is split in multiple ethernet frames, we don't support that
    if (tcp_payload_end > (__u8 *)data_end)
    {
        // LOG_DEBUG(flow_key, "tcp packet split in multiple frames (block)");
        goto drop;
    }

    if (tcp_payload < tcp_payload_end)
    {

        if (!tcp->ack)
        {
            // LOG_DEBUG(flow_key, "expected ack for data packet (block)");
            goto drop_connection;
        }

        // we fully track the tcp packet order with this check,
        // this mean we can hard punish invalid packets below, as they are not out of order
        // but invalid data
        if (initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
            {
                // LOG_DEBUG(flow_key, "too many out of order packets (block)");
                goto drop_connection;
            }
            // if it does not exist the connection was closed by another thread
            bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST);
            // LOG_DEBUG(flow_key, "out of order packet");
            goto drop;
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, &initial_state->protocol, data_end);
            // if the first packet has invalid length, we can block it
            // even with retransmition this len should always be valid‚
            if (!next_state)
            {
                // LOG_DEBUG(flow_key, "invalid mc handshake (block)");
                goto drop;
            }

            // fully drop legacy ping
            if (next_state == RECEIVED_LEGACY_PING)
            {
                // LOG_DEBUG(flow_key, "legacy ping");
                drop_connection(stats_ptr, &flow_key);
                goto drop;
            }

            initial_state->state = next_state;
            initial_state->expected_sequence += tcp_payload_len;
            if (next_state == LOGIN_FINISHED)
            {
                goto switch_to_verified;
            }
            else
            {
                goto update_state_or_drop;
            }
        }
        else if (state == AWAIT_STATUS_REQUEST)
        {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, data_end))
            {
                // LOG_DEBUG(flow_key, "invalid status request (block)");
                goto drop;
            }
            initial_state->state = AWAIT_PING;
            initial_state->expected_sequence += tcp_payload_len;
            goto update_state_or_drop;
        }
        else if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, data_end))
            {
                // LOG_DEBUG(flow_key, "invalid ping request (block)");
                goto drop;
            }
            initial_state->state = PING_COMPLETE;
            initial_state->expected_sequence += tcp_payload_len;
            goto update_state_or_drop;
        }
        else if (state == AWAIT_LOGIN)
        {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, initial_state->protocol, data_end))
            {
                // LOG_DEBUG(flow_key, "invalid login packet (block)");
                goto drop;
            }
            // as tracking ends here we do not need to update the sequence
            // initial_state->expected_sequence += tcp_payload_len;
            goto switch_to_verified;
        }
        else if (state == PING_COMPLETE)
        {
            // LOG_DEBUG(flow_key, "extra packet after ping complete (block)");
            goto drop_connection;
        }
    }
    return XDP_PASS;

// Using this labels drastically reduce the file size
drop_connection:
    drop_connection(stats_ptr, &flow_key);
    goto drop;
drop:
    count_stats(stats_ptr, DROPPED_PACKET, 1);
    count_stats(stats_ptr, DROPPED_BYTES, raw_packet_len);
    return XDP_DROP;
update_state_or_drop:
    return update_state_or_drop(raw_packet_len, stats_ptr, initial_state, &flow_key);
switch_to_verified:
    return switch_to_verified(raw_packet_len, stats_ptr, &flow_key);
}

char _license[] SEC("license") = "proprietary";
