#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "minecraft_networking.c"
#define HIT_COUNT 10

// Minecraft server port
const __u16 MINECRAFT_PORT = __constant_htons(25565);
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
            __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, &initial_state->protocol, packet_end);
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
