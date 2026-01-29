#ifndef HIT_COUNT
#define HIT_COUNT 10
#endif

#ifndef START_PORT
#define START_PORT 25565
#endif
#ifndef END_PORT
#define END_PORT 25565
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "minecraft_networking.c"
#include "stats.h"

// Minecraft server port
#define ETH_P_IP 0x0800
struct
{
    __uint(type,
#if IP_AND_PORT_PER_CPU
           BPF_MAP_TYPE_LRU_PERCPU_HASH
#else
           BPF_MAP_TYPE_LRU_HASH
#endif
    );
    __uint(max_entries, 4096);           // max amount of 4096 concurrent initial connections
    __type(key, struct ipv4_flow_key);   // flow key
    __type(value, struct initial_state); // initial state
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
    __type(key, struct ipv4_flow_key); // flow key
    __type(value, __u64);              // last seen timestamp
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
    __type(key, __u32);   // ipv4 address
    __type(value, __u32); // throttle hit counter
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

static __always_inline __u8 detect_tcp_bypass(const struct tcphdr *tcp)
{
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) || // no SYN/ACK/FIN/RST flag
        (tcp->syn && tcp->ack) ||                             // SYN+ACK from external (unexpected)
        tcp->urg)
    { // drop if URG flag is set
        return 1;
    }
    return 0;
}

/*
 * tries to update the initial state, if unsuccessful, packet is dropped
 */
static __always_inline __s32 update_state_or_drop(const __u64 packet_size, const struct statistics *stats_ptr, const struct initial_state *initial_state, const struct ipv4_flow_key *flow_key)
{
    // if we update it, it should exist, if not it was removed by another thread
    if (bpf_map_update_elem(&conntrack_map, flow_key, initial_state, BPF_EXIST) < 0)
    {
        // could not update the value, we need to drop and hope it works next time
        count_stats(stats_ptr, DROPPED_PACKET, 1);
        count_stats(stats_ptr, DROPPED_BYTES, packet_size);
        return XDP_DROP;
    }
    count_stats(stats_ptr, STATE_SWITCH, 1);

    // for compiler
    (void)stats_ptr;
    (void)packet_size;

    return XDP_PASS;
}
/*
 * removes the connection from the conntrack_map
 */
static __always_inline void remove_connection(const struct statistics *stats_ptr, const struct ipv4_flow_key *flow_key)
{
    count_stats(stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, flow_key);
    (void)stats_ptr; // for compiler
}
/*
 * removes connection from conntrack map and puts it into the player map
 * no more packets of this connection will be checked now
 */
static __always_inline __u32 switch_to_verified(const __u64 raw_packet_len, const struct statistics *stats_ptr, const struct ipv4_flow_key *flow_key)
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
    // for compiler
    (void)raw_packet_len;
    (void)stats_ptr;

    return XDP_PASS;
}

SEC("xdp")
__s32 minecraft_filter(struct xdp_md *ctx)
{
    const void *data = (const void *)(long)ctx->data;
    const void *data_end = (const void *)(long)ctx->data_end;

    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end)
    {
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    const struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((const void *)(ip + 1) > data_end || ip->ihl < 5)
    {
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    const struct tcphdr *tcp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(tcp + 1) > data_end)
    {
        return XDP_DROP;
    }

    // check if TCP destination port matches mc server port
    const __u16 dest_port = __builtin_bswap16(tcp->dest);

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
        return XDP_DROP;
    }

    const __u32 tcp_hdr_len = tcp->doff * 4;
    if ((const void *)tcp + tcp_hdr_len > data_end)
    {
        return XDP_DROP;
    }

#if PROMETHEUS_METRICS
    __u32 key = 0;
    struct statistics *stats_ptr = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats_ptr)
    {
        // this should be impossible
        return XDP_DROP;
    }
#else
    struct statistics *stats_ptr = 0;
#endif

    const __u64 raw_packet_len = (__u64)(data_end - data);
    count_stats(stats_ptr, INCOMING_BYTES, raw_packet_len);

    // additional TCP bypass checks for abnormal flags
    if (detect_tcp_bypass(tcp))
    {
        count_stats(stats_ptr, TCP_BYPASS, 1);
        goto drop;
    }

    const __u32 src_ip = ip->saddr;

    // stateless new connection checks
    if (tcp->syn)
    {
        count_stats(stats_ptr, SYN_RECEIVE, 1);

#if CONNECTION_THROTTLE
        // connection throttle
        // 10 connection per ip per 3 seconds, otherwise drop
        __u32 *hit_counter = bpf_map_lookup_elem(&connection_throttle, &src_ip);
        if (hit_counter)
        {
            if (*hit_counter > HIT_COUNT)
            {
                goto drop;
            }
            (*hit_counter)++;
        }
        else
        {
            __u32 new_counter = 1;
            if (bpf_map_update_elem(&connection_throttle, &src_ip, &new_counter, BPF_NOEXIST) < 0)
            {
                goto drop;
            }
        }
#endif
        // compute flow key
        const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, __builtin_bswap32(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            goto drop;
        }

        return XDP_PASS;
    }

    // compute flow key
    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
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
        goto drop; // no connection tracked, drop
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack or invalid ack number
        if (!tcp->ack || initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            goto drop;
        }
        initial_state->state = state = AWAIT_MC_HANDSHAKE;
        if (bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST) < 0)
        {
            // we could not update the value, we need to drop.
            goto drop;
        }
        // do not return here, the ack of the tcp handshake can contain application data
        // return XDP_PASS;
    }

    __u8 *tcp_payload = (__u8 *)((__u8 *)tcp + tcp_hdr_len);

    // total length of ip packet
    const __u16 ip_tot_len = __builtin_bswap16(ip->tot_len);
    // total ip - ip header - tcp header = length of tcp payload
    const __u16 tcp_payload_len = ip_tot_len - (ip->ihl * 4) - tcp_hdr_len;
    // tcp payload end = start + length
    const __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // tcp packet is split in multiple ethernet frames, we don't support that
    if (tcp_payload_end > (__u8 *)data_end)
    {
        goto drop;
    }

    if (tcp_payload < tcp_payload_end)
    {

        if (!tcp->ack)
        {
            goto drop_connection;
        }

        // we fully track the tcp packet order with this check,
        // this mean we can hard punish invalid packets below, as they are not out of order
        // but invalid data
        if (initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
            {
                goto drop_connection;
            }
            // if it does not exist the connection was closed by another thread
            bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST);
            goto drop;
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            // returns the next state
            // if the login data or motd request is included in the same tcp data as the handshake
            // the tcp_payload reader index will be updated to the next position
            __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, &initial_state->protocol, data_end, &tcp_payload);
            // if the first packet has invalid length, we can block it
            // even with retransmission this len should always be valid‚
            if (!next_state)
            {
                goto drop;
            }

            // fully drop legacy ping
            if (next_state == RECEIVED_LEGACY_PING)
            {
                goto drop_connection;
            }
            if (next_state == DIRECT_READ_STATUS_REQUEST)
            {
                goto read_status;
            }
            if (next_state == DIRECT_READ_LOGIN)
            {
                goto read_login;
            }
            initial_state->state = next_state;
            goto update_state_or_drop;
        }
        if (state == AWAIT_STATUS_REQUEST)
        read_status: {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, data_end))
            {
                goto drop;
            }
            initial_state->state = AWAIT_PING;
            goto update_state_or_drop;
        }
        if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, data_end))
            {
                goto drop;
            }
            initial_state->state = PING_COMPLETE;
            goto update_state_or_drop;
        }
        if (state == AWAIT_LOGIN)
        read_login: {
        
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, initial_state->protocol, data_end))
            {
                goto drop;
            }
            // as tracking ends here we do not need to update the sequence
            // initial_state->expected_sequence += tcp_payload_len;
            goto switch_to_verified;
        }
        if (state == PING_COMPLETE)
        {
            goto drop_connection;
        }
    }
    return XDP_PASS;

// Using this labels drastically reduce the file size
drop_connection:
    remove_connection(stats_ptr, &flow_key);
    goto drop;
drop:
    count_stats(stats_ptr, DROPPED_PACKET, 1);
    count_stats(stats_ptr, DROPPED_BYTES, raw_packet_len);
    return XDP_DROP;
update_state_or_drop:
    initial_state->expected_sequence += tcp_payload_len;
    return update_state_or_drop(raw_packet_len, stats_ptr, initial_state, &flow_key);
switch_to_verified:
    return switch_to_verified(raw_packet_len, stats_ptr, &flow_key);
}

char _license[] SEC("license") = "Proprietary";
