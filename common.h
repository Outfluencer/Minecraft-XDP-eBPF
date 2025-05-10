#include <linux/types.h>

// maximum amount of retransmission packets before blocking
#define MAX_RETRANSMISSION 20

// STATE TRACKING
#define AWAIT_ACK 1
#define AWAIT_MC_HANDSHAKE 2
#define RECEIVED_LEGACY_PING 3 // this connection will be fully dropped
#define AWAIT_STATUS_REQUEST 4
#define AWAIT_LOGIN 5
#define AWAIT_PING 6
#define PING_COMPLETE 7
#define LOGIN_FINISHED 8 // disables filter


#define SECOND_TO_NANOS 1000000000ULL

struct ipv4_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};
_Static_assert(sizeof(struct ipv4_flow_key) == 12, "ipv4_flow_key size mismatch!");


struct initial_state {
    __u16 state;
    __u16 fails;
    __u32 protocol;
};
_Static_assert(sizeof(struct initial_state) == 8, "initial_state size mismatch!");


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