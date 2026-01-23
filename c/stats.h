#ifndef STATS_H
#define STATS_H

#include <linux/types.h>

// bitmask for statistics types
enum stats_mask {
    VERIFIED        = 1u << 0,
    DROPPED_PACKET  = 1u << 1,
    STATE_SWITCH    = 1u << 2,
    DROP_CONNECTION = 1u << 3,
    SYN_RECEIVE     = 1u << 4,
    TCP_BYPASS      = 1u << 5,
    INCOMING_BYTES  = 1u << 6,
    DROPPED_BYTES   = 1u << 7,
};

struct statistics
{
    __u64 verified;
    __u64 dropped_packets;
    __u64 state_switches;
    __u64 drop_connection;
    __u64 syn;
    __u64 tcp_bypass;
    __u64 incoming_bytes;
    __u64 dropped_bytes;
};

_Static_assert(sizeof(struct statistics) == 64, "statistics size mismatch!");

/*
 * the compiler will optimize this function well
 */
#if PROMETHEUS_METRICS
static __always_inline void count_stats_impl(struct statistics *stats_ptr, const __u32 bitmask, const __u64 amount)
{
    if (bitmask & INCOMING_BYTES)
    {
        stats_ptr->incoming_bytes += amount;
    }

    if (bitmask & DROPPED_BYTES)
    {
        stats_ptr->dropped_bytes += amount;
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
}

#define count_stats(stats_ptr, bitmask, amount) count_stats_impl(stats_ptr, bitmask, amount)
#else
#define count_stats(stats_ptr, bitmask, amount)
#endif

#endif