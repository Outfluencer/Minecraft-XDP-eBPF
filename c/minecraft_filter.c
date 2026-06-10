#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// Runtime configuration. The Rust loader overrides these at load time via
// aya's set_global() (BPF .rodata). They are declared before the project
// headers below because minecraft_networking.h (ONLINE_NAMES) and stats.h
// (PROMETHEUS) reference them; the values here are the compiled-in fallback.
volatile const __u8 PROMETHEUS = 0;
volatile const __u32 START_PORT = 25565;
volatile const __u32 END_PORT = 25565;
volatile const __u32 HIT_COUNT = 10;
volatile const __u64 HIT_COUNT_RESET_NS = 3000000000ULL;
volatile const __u8 ONLINE_NAMES = 1;

#include "common.h"
#include "minecraft_networking.h"
#include "stats.h"


struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);          // max amount of 16384 concurrent initial connections
    __type(key, struct ipv4_flow_key);   // flow key
    __type(value, struct initial_state); // initial state
} conntrack_map SEC(".maps");

// idle check interval for verified connections: removal happens after one to
// two intervals (60 to 120 seconds) without packets
#define PLAYER_IDLE_NS (60ULL * SECOND_TO_NANOS)

struct player_entry
{
    struct bpf_timer timer; // deletes the entry when the connection goes idle
    __u64 packets;          // incremented for every packet of this flow
    __u64 last_packets;     // snapshot taken by the idle check timer
};
_Static_assert(sizeof(struct player_entry) == 32, "player_entry size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct ipv4_flow_key);  // flow key
    __type(value, struct player_entry); // idle timer + packet counter
} player_connection_map SEC(".maps");

/*
 * bpf_timer callback: delete the verified connection if it was idle for a
 * full interval, otherwise snapshot the counter and check again next interval
 */
static __s32 player_connection_idle_check(void *map, struct ipv4_flow_key *key, struct player_entry *entry)
{
    const __u64 packets = entry->packets;
    if (packets == entry->last_packets)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    entry->last_packets = packets;
    bpf_timer_start(&entry->timer, PLAYER_IDLE_NS, 0);
    return 0;
}

struct throttle_entry
{
    struct bpf_timer timer; // deletes the entry when the window expires
    __u32 hits;             // SYNs counted within the current window
    __u32 pad;
};
_Static_assert(sizeof(struct throttle_entry) == 24, "throttle_entry size mismatch!");

struct
{
    // plain HASH on purpose (no LRU): during a big attack the map fills up,
    // inserts fail and ALL unverified traffic is dropped; only verified
    // connections keep passing. Capacity recovers in-kernel as the per-entry
    // timers fire and delete the expired windows.
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);                   // ipv4 address
    __type(value, struct throttle_entry); // window timer + hit counter
} connection_throttle SEC(".maps");

// while connection_throttle is full, only retry inserting after this long
// (per core): a failed insert on a full preallocated map scans every cpu's
// freelist under spinlocks, so during that time we drop without even trying
#define THROTTLE_BACKOFF_NS (100ULL * 1000000ULL) // 100ms

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // per-cpu: no insert retry before this ktime
} throttle_insert_backoff SEC(".maps");

/*
 * bpf_timer callback: the throttle window of this ip is over. Entries that
 * saw SYNs during the window are recycled (counter reset, timer re-armed) so
 * repeat senders cause no map/timer churn; entries that were idle for the
 * whole window are deleted.
 */
static __s32 throttle_window_expired(void *map, __u32 *key, struct throttle_entry *entry)
{
    if (__sync_lock_test_and_set(&entry->hits, 0) == 0)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    bpf_timer_start(&entry->timer, HIT_COUNT_RESET_NS, 0);
    return 0;
}

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
} stats_map SEC(".maps");

static __always_inline __u8 detect_tcp_bypass(const struct tcphdr *tcp)
{
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) || // no SYN/ACK/FIN/RST flag
        (tcp->syn && tcp->ack) ||                             // SYN+ACK from external (unexpected)
        (tcp->syn && (tcp->fin || tcp->rst)) ||               // SYN+FIN/SYN+RST never occur legitimately
        tcp->urg)
    { // drop if URG flag is set
        return 1;
    }
    return 0;
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
    const struct player_entry fresh = {.packets = 1, .last_packets = 0};
    if (bpf_map_update_elem(&player_connection_map, flow_key, &fresh, BPF_NOEXIST) < 0)
    {
        goto drop;
    }
    struct player_entry *entry = bpf_map_lookup_elem(&player_connection_map, flow_key);
    if (!entry)
    {
        goto drop;
    }
    if (bpf_timer_init(&entry->timer, &player_connection_map, CLOCK_MONOTONIC) < 0 ||
        bpf_timer_set_callback(&entry->timer, player_connection_idle_check) < 0 ||
        bpf_timer_start(&entry->timer, PLAYER_IDLE_NS, 0) < 0)
    {
        // never leak an entry that has no idle timer armed
        bpf_map_delete_elem(&player_connection_map, flow_key);
        goto drop;
    }
    count_stats(stats_ptr, VERIFIED, 1);
    return XDP_PASS;
drop:
    count_stats(stats_ptr, DROPPED_BYTES, raw_packet_len);
    count_stats(stats_ptr, DROP_CONNECTION | DROPPED_PACKET, 1);
    return XDP_DROP;
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

    // drop fragmented tcp packets (MF flag or fragment offset set): non-first
    // fragments carry no tcp header so the port check below would run on
    // payload bytes, and after kernel reassembly the backend would receive
    // data the state machine never inspected. Legitimate tcp does not
    // fragment, the MSS keeps segments below the MTU
    if (ip->frag_off & bpf_htons(0x3FFF))
    {
        return XDP_DROP;
    }

    const struct tcphdr *tcp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(tcp + 1) > data_end)
    {
        return XDP_DROP;
    }

    // check if TCP destination port matches mc server port
    const __u16 dest_port = bpf_ntohs(tcp->dest);

    if (dest_port < START_PORT || dest_port > END_PORT)
    {
        return XDP_PASS; // not for our service
    }

    if (tcp->doff < 5)
    {
        return XDP_DROP;
    }

    const __u32 tcp_hdr_len = tcp->doff * 4;
    if ((const void *)tcp + tcp_hdr_len > data_end)
    {
        return XDP_DROP;
    }
    struct statistics *stats_ptr = 0;
    if(PROMETHEUS) {
        __u32 key = 0;
        stats_ptr = bpf_map_lookup_elem(&stats_map, &key);
        if (!stats_ptr)
        {
            // this should be impossible
            return XDP_DROP;
        }
    }


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
        // drop SYNs carrying payload (e.g. TCP fast open): the data would
        // reach the backend without ever passing the inspection state machine
        if (bpf_ntohs(ip->tot_len) > (ip->ihl * 4) + tcp_hdr_len)
        {
            count_stats(stats_ptr, TCP_BYPASS, 1);
            goto drop;
        }
        if(HIT_COUNT) {
            // connection throttle, fully in kernel: every source ip gets its
            // own window of HIT_COUNT_RESET_NS, opened by its first SYN and
            // closed by the bpf_timer that deletes the entry again
            struct throttle_entry *entry = bpf_map_lookup_elem(&connection_throttle, &src_ip);
            if (entry)
            {
                if (entry->hits >= HIT_COUNT)
                {
                    goto drop;
                }
                __sync_fetch_and_add(&entry->hits, 1);
            }
            else
            {
                __u32 zero = 0;
                __u64 *backoff = bpf_map_lookup_elem(&throttle_insert_backoff, &zero);
                if (!backoff)
                {
                    // this should be impossible
                    goto drop;
                }
                const __u64 now = bpf_ktime_get_ns();
                if (now < *backoff)
                {
                    // the map was full just before: fail closed without
                    // paying for another doomed insert attempt
                    goto drop;
                }
                const struct throttle_entry fresh = {.hits = 1, .pad = 0};
                const long err = bpf_map_update_elem(&connection_throttle, &src_ip, &fresh, BPF_NOEXIST);
                if (err < 0)
                {
                    if (err != -EEXIST)
                    {
                        // map full (attack): fail closed and back off
                        *backoff = now + THROTTLE_BACKOFF_NS;
                    }
                    goto drop;
                }
                entry = bpf_map_lookup_elem(&connection_throttle, &src_ip);
                if (!entry)
                {
                    goto drop;
                }
                if (bpf_timer_init(&entry->timer, &connection_throttle, CLOCK_MONOTONIC) < 0 ||
                    bpf_timer_set_callback(&entry->timer, throttle_window_expired) < 0 ||
                    bpf_timer_start(&entry->timer, HIT_COUNT_RESET_NS, 0) < 0)
                {
                    // never leak an entry that has no expiry timer armed
                    bpf_map_delete_elem(&connection_throttle, &src_ip);
                    goto drop;
                }
            }
        }

        // compute flow key
        const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, bpf_ntohl(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            goto drop;
        }

        return XDP_PASS;
    }

    // compute flow key
    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
    struct player_entry *player = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (player)
    {
        // non-atomic on purpose: racing increments (flow migrating cpus) can
        // only lose single steps, never regress the counter across a window.
        // The idle check thus only false-matches if the connection sent
        // nothing for ~a full window, and minecraft clients keepalive every
        // few seconds, so such a connection is dead anyway
        player->packets++;
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!initial_state)
    {
        goto drop; // no connection tracked, drop
    }

    __u8 *tcp_payload = (__u8 *)((__u8 *)tcp + tcp_hdr_len);

    // total length of ip packet
    const __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
    // total ip - ip header - tcp header = length of tcp payload
    const __u16 tcp_payload_len = ip_tot_len - (ip->ihl * 4) - tcp_hdr_len;
    // tcp payload end = start + length
    const __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // tcp packet is split in multiple ethernet frames, we don't support that
    if (tcp_payload_end > (__u8 *)data_end)
    {
        goto drop;
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack or invalid ack number
        if (!tcp->ack || initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            goto drop;
        }

        // set state here even tho we may retrun as we need the state for the next packet
        initial_state->state = state = AWAIT_MC_HANDSHAKE;

        // we can drop original pure ack from the tcp 3 way handshake
        // the backend will accept the first minecraft data packet as the ack of the 3 way handshake
        // that's an elegant way to only let the backend accept connections that have a mc handshake in it.
        // Only drop if there is no TCP payload; if there is payload, continue into payload inspection.
        if (tcp_payload >= tcp_payload_end)
        {
            goto drop;
        }

        // do not return here, the ack of the tcp handshake can contain application data
        // return XDP_PASS;
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
        if (initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
            {
                goto drop_connection;
            }
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
            goto update_state;
        }
        if (state == AWAIT_STATUS_REQUEST)
        read_status: {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, data_end))
            {
                goto drop;
            }
            initial_state->state = AWAIT_PING;
            goto update_state;
        }
        if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, data_end))
            {
                goto drop;
            }
            initial_state->state = PING_COMPLETE;
            goto update_state;
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
    } else if (state == AWAIT_MC_HANDSHAKE) {
        // no ack's are allowed, we are waiting for the handshake
        // otherwise an attacker could bypass the 3 way handshake hack
        goto drop; 
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
update_state:
    initial_state->expected_sequence += tcp_payload_len;
    count_stats(stats_ptr, STATE_SWITCH, 1);
    return XDP_PASS;
switch_to_verified:
    return switch_to_verified(raw_packet_len, stats_ptr, &flow_key);
}

// must be GPL-compatible: the bpf_timer_* helpers used by the connection
// throttle are gpl_only, the kernel refuses to load them otherwise
char _license[] SEC("license") = "GPL";
