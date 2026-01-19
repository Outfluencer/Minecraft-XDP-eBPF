#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>

// maximum amount of retransmission packets before blocking
#define MAX_OUT_OF_ORDER 4

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

// Returns TRUE if the access would be out of bounds (UNSAFE)
// Casts everything to (void *) to prevent "distinct pointer type" warnings
#define OUT_OF_BOUNDS(ptr, n, pend, dend) \
    ((void *)(ptr) + (n) > (void *)(dend) || (void *)(ptr) + (n) > (void *)(pend))

// Checks bounds. If bad, returns 0. If good, increments ptr.
// usage: READ_OR_RETURN(reader_index, 2, payload_end, data_end);
#define READ_OR_RETURN(ptr, n, pend, dend)     \
    do                                         \
    {                                          \
        if (OUT_OF_BOUNDS(ptr, n, pend, dend)) \
            return 0;                          \
        ptr += (n);                            \
    } while (0)

// Reads a value into 'dest' and increments 'ptr', or returns 0 if OOB
#define READ_VAL_OR_RETURN(dest, ptr, pend, dend)         \
    do                                                    \
    {                                                     \
        if (OUT_OF_BOUNDS(ptr, sizeof(dest), pend, dend)) \
            return 0;                                     \
        dest = *(__typeof__(dest) *)(ptr);                \
        ptr += sizeof(dest);                              \
    } while (0)

// If condition is false, returns 0 immediately.
#define ASSERT_OR_RETURN(cond) \
    do                         \
    {                          \
        if (!(cond))           \
            return 0;          \
    } while (0)

#define ASSERT_IN_RANGE(val, min, max)      \
    do                                      \
    {                                       \
        if ((val) < (min) || (val) > (max)) \
            return 0;                       \
    } while (0)
// Reads a VarInt into 'dest_struct', increments 'ptr', or returns 0 on failure.
// dest_struct: variables of type 'struct varint_value'
// max_bytes: usually 5 for Int, or 1-2 for lengths
#define READ_VARINT_OR_RETURN(dest_struct, ptr, max_bytes, pend, dend) \
    do                                                                 \
    {                                                                  \
        dest_struct = read_varint_sized(ptr, pend, max_bytes, dend);   \
        if (!(dest_struct).bytes)                                      \
            return 0;                                                  \
        (ptr) += (dest_struct).bytes;                                  \
    } while (0)

struct ipv4_flow_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};
_Static_assert(sizeof(struct ipv4_flow_key) == 12, "ipv4_flow_key size mismatch!");

struct initial_state
{
    __u16 state;    // we only need u8, but padding....
    __u16 fails;    // we only need u8, but padding....
    __s32 protocol; // minecraft protocol versions are signed
    __u32 expected_sequence;
};
_Static_assert(sizeof(struct initial_state) == 12, "initial_state size mismatch!");

static __always_inline struct ipv4_flow_key gen_ipv4_flow_key(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port)
{
    struct ipv4_flow_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port};
    return key;
}

static __always_inline struct initial_state gen_initial_state(__u16 state, __s32 protocol, __u32 expected_sequence)
{
    struct initial_state new_state = {
        .state = state,
        .fails = 0,
        .protocol = protocol,
        .expected_sequence = expected_sequence,
    };
    return new_state;
}
#endif