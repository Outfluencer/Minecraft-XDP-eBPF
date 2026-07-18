/*
 * minecraft_filter - XDP program protecting Minecraft Java Edition servers
 * against L7 (D)DoS attacks.
 *
 * Every TCP packet for the filtered port range runs through a small state
 * machine that validates the TCP handshake and the first Minecraft packets
 * of the connection (handshake, then status+ping or login). Connections that
 * complete the sequence are promoted to a verified fast path and are no
 * longer inspected; everything else is dropped at the driver level. New
 * connections are additionally rate limited per source ip. All map cleanup
 * happens in-kernel via bpf_timer, userspace never has to touch the maps.
 */
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

#include "common.h"
#include "config.h"
#include "protocol.h"
#include "stats.h"

// fragment bits of iphdr->frag_off (kernel-internal net/ip.h, not uapi)
#ifndef IP_MF
#define IP_MF 0x2000 // flag: "more fragments"
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF // "fragment offset" part
#endif

/* ------------------------------------------------------------------------
 * Connection tracking of unverified connections
 * --------------------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);          // placeholder, set by the loader ([xdp] max_pending_connections)
    __type(key, struct ipv4_flow_key);   // flow key
    __type(value, struct initial_state); // inspection state machine data
} conntrack_map SEC(".maps");

/* ------------------------------------------------------------------------
 * Verified connections (players)
 * --------------------------------------------------------------------- */

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
    __uint(max_entries, 65535);         // placeholder, set by the loader ([xdp] max_player_connections)
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
    // re-arming can only fail if this entry is concurrently being freed (map
    // delete/teardown NULLs the timer under its lock); then there is nothing
    // left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, PLAYER_IDLE_NS, 0);
    return 0;
}

/* ------------------------------------------------------------------------
 * Per-ip connection throttle
 * --------------------------------------------------------------------- */

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
    __uint(max_entries, 65535);           // placeholder, set by the loader ([xdp] max_throttled_ips)
    __type(key, __u32);                   // ipv4 source address
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
    // re-arming can only fail if this entry is concurrently being freed (map
    // delete/teardown NULLs the timer under its lock); then there is nothing
    // left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, HIT_COUNT_RESET_NS, 0);
    return 0;
}

/* ------------------------------------------------------------------------
 * Statistics (only used when PROMETHEUS is enabled, see stats.h)
 * --------------------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
} stats_map SEC(".maps");

/* ------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

// flag combinations that never occur on legitimate client traffic
static __always_inline __u8 detect_tcp_bypass(const struct tcphdr *tcp)
{
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) || // none of SYN/ACK/FIN/RST set
        (tcp->syn && tcp->ack) ||                             // SYN+ACK from outside is never a client
        (tcp->syn && (tcp->fin || tcp->rst)) ||               // SYN+FIN / SYN+RST are always forged
        tcp->urg)                                             // URG is unused by the protocol
    {
        return 1;
    }
    return 0;
}

/*
 * The connection passed the full inspection sequence: move it from the
 * conntrack map into the player map so its packets skip inspection from now
 * on, and arm the idle timer that will eventually clean the entry up.
 */
static __always_inline __u32 switch_to_verified(const __u64 raw_packet_len, struct statistics *stats_ptr, const struct ipv4_flow_key *flow_key)
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

/* ------------------------------------------------------------------------
 * XDP entry point
 * --------------------------------------------------------------------- */

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

    // non-first fragments (fragment offset != 0) carry no tcp header, so the
    // port check below cannot run on them: pass them up the stack so other
    // services keep receiving their fragmented traffic. Safe for the filtered
    // range because the matching first fragment is dropped after the port
    // check, so reassembly never completes and the kernel discards the rest
    // after the frag timeout. The ports can not be forged via fragment
    // overlap either: they live in bytes 0-3 of the tcp header while the
    // smallest non-first offset is 8 bytes, and linux >= 4.19 drops
    // overlapping fragments outright
    if (ip->frag_off & bpf_htons(IP_OFFSET))
    {
        return XDP_PASS;
    }

    const struct tcphdr *tcp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(tcp + 1) > data_end)
    {
        return XDP_DROP;
    }

    // everything outside the filtered port range is not our business
    const __u16 dest_port = bpf_ntohs(tcp->dest);
    if (dest_port < START_PORT || dest_port > END_PORT)
    {
        return XDP_PASS;
    }

    // first fragment of a fragmented packet (MF set, offset 0) aimed at our
    // range: the remaining payload is in fragments the state machine never
    // sees, so after kernel reassembly the backend would receive uninspected
    // data. Legitimate tcp does not fragment, the MSS keeps segments below
    // the MTU. Dropping the first fragment makes reassembly impossible, the
    // kernel discards the passed non-first fragments after the frag timeout
    if (ip->frag_off & bpf_htons(IP_MF))
    {
        return XDP_DROP;
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

    struct statistics *stats_ptr = NULL;
    if (PROMETHEUS)
    {
        __u32 key = 0;
        stats_ptr = bpf_map_lookup_elem(&stats_map, &key);
        if (!stats_ptr)
        {
            // per-cpu array index 0 always exists, this is unreachable
            return XDP_DROP;
        }
    }

    const __u64 raw_packet_len = (__u64)(data_end - data);
    count_stats(stats_ptr, INCOMING_BYTES, raw_packet_len);

    if (detect_tcp_bypass(tcp))
    {
        count_stats(stats_ptr, TCP_BYPASS, 1);
        goto drop;
    }

    const __u32 src_ip = ip->saddr;
    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);

    // new connection: throttle it, then start tracking it
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

        if (HIT_COUNT)
        {
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
                    // per-cpu array index 0 always exists, this is unreachable
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

        // track the connection: the next packet has to be the ACK finishing
        // the TCP handshake, with the sequence number following this SYN
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, bpf_ntohl(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            goto drop;
        }

        return XDP_PASS;
    }

    // verified connections skip all further inspection
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
        goto drop; // neither tracked nor verified
    }

    const __u8 *tcp_payload = (const __u8 *)tcp + tcp_hdr_len;

    // ip total length - ip header - tcp header = length of the tcp payload
    const __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
    const __u16 tcp_payload_len = ip_tot_len - (ip->ihl * 4) - tcp_hdr_len;
    const __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // tcp packet split over multiple ethernet frames, we don't support that
    if (tcp_payload_end > (const __u8 *)data_end)
    {
        goto drop;
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack, or not the ack matching our SYN
        if (!tcp->ack || initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            goto drop;
        }

        // advance the state machine before the early drop below, the next
        // packet has to be matched against AWAIT_MC_HANDSHAKE
        initial_state->state = state = AWAIT_MC_HANDSHAKE;

        // the empty ack finishing the TCP handshake is dropped on purpose:
        // the backend will accept the first minecraft data packet as that
        // ack, which elegantly limits backend connections to clients whose
        // handshake passed inspection. If the ack already carries payload,
        // fall through into payload inspection instead
        if (tcp_payload >= tcp_payload_end)
        {
            goto drop;
        }
    }

    if (tcp_payload < tcp_payload_end)
    {
        // payload without an ack flag is never legitimate mid-handshake
        if (!tcp->ack)
        {
            goto drop_connection;
        }

        // we fully track the tcp sequence, so a mismatch here is either a
        // retransmission or an out-of-order packet: drop the packet, and
        // drop the whole connection once that happens too often. Everything
        // that survives this check is exactly the in-order byte stream the
        // backend would see, which is what allows the hard punishments below
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
            // if the status request or login packet is in the same tcp
            // segment as the handshake, inspect_handshake returns a
            // DIRECT_READ_* state and advances tcp_payload to the rest
            const __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, data_end, &initial_state->protocol, &tcp_payload);
            if (!next_state)
            {
                // even with retransmissions the handshake of a legitimate
                // client is always parseable, this connection is bogus
                goto drop;
            }
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
        read_status:
        {
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
        read_login:
        {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, data_end, initial_state->protocol))
            {
                goto drop;
            }
            // tracking ends here, no need to update the expected sequence
            return switch_to_verified(raw_packet_len, stats_ptr, &flow_key);
        }
        if (state == PING_COMPLETE)
        {
            // a finished ping flow has nothing more to say
            goto drop_connection;
        }
    }
    else if (state == AWAIT_MC_HANDSHAKE)
    {
        // empty acks are not allowed while the handshake is pending,
        // otherwise an attacker could sit on a half-inspected connection
        goto drop;
    }

    // empty segments in the remaining states (pure acks, FIN/RST teardown)
    return XDP_PASS;

// shared exit paths: jumping here instead of duplicating these blocks keeps
// the generated program drastically smaller
drop_connection:
    count_stats(stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, &flow_key);
    // fall through
drop:
    count_stats(stats_ptr, DROPPED_PACKET, 1);
    count_stats(stats_ptr, DROPPED_BYTES, raw_packet_len);
    return XDP_DROP;
update_state:
    initial_state->expected_sequence += tcp_payload_len;
    count_stats(stats_ptr, STATE_SWITCH, 1);
    return XDP_PASS;
}

// must be GPL-compatible: the bpf_timer_* helpers used by the connection
// throttle are gpl_only, the kernel refuses to load them otherwise
char _license[] SEC("license") = "Dual BSD/GPL";
