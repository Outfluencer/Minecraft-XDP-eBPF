#include <linux/types.h>

// bitmask for statistics types
const __u32 IP_BLOCK =        1u << 0;
const __u32 VERIFIED =        1u << 1;
const __u32 DROPPED_PACKET =  1u << 2;
const __u32 STATE_SWITCH =    1u << 3;
const __u32 DROP_CONNECTION = 1u << 4;
const __u32 SYN_RECEIVE =     1u << 5;
const __u32 TCP_BYPASS =      1u << 6;
const __u32 INCOMING_BYTES =  1u << 7;
const __u32 DROPPED_BYTES =   1u << 8;

struct statistics
{
    __u64 ip_blocks;
    __u64 verified;
    __u64 dropped_packets;
    __u64 state_switches;
    __u64 drop_connection;
    __u64 syn;
    __u64 tcp_bypass;
    __u64 incoming_bytes;
    __u64 dropped_bytes;
};

_Static_assert(sizeof(struct statistics) == 72, "statistics size mismatch!");