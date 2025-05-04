#include <linux/types.h>

// STATE TRACKING
#define AWAIT_ACK 1
#define AWAIT_STATUS_REQUEST 2
#define AWAIT_LOGIN 3
#define AWAIT_PING 4
#define PING_COMPLETE 5
#define AWAIT_MC_HANDSHAKE 100 // counting this higher is alowed for counting invalid packets

#define SECOND_TO_NANOS 1000000000ULL

struct ipv4_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct initial_state {
    __u32 state;
    __u32 protocol;
};

static __always_inline struct ipv4_flow_key gen_ipv4_flow_key(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port) {
    struct ipv4_flow_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port
    };
    return key;
}

static __always_inline struct initial_state gen_initial_state(__u32 state, __u32 protocol) {
    struct initial_state new_state = {
        .state = state,
        .protocol = protocol,
    };
    return new_state;
}