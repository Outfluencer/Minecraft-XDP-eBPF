#ifndef COMMON_H
#define COMMON_H

#include "vmlinux.h"

#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

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
#define DIRECT_READ_STATUS_REQUEST 8
#define DIRECT_READ_LOGIN 9

#define SECOND_TO_NANOS 1000000000ULL


// Checks bounds and returns 0 if out of bounds (does NOT increment ptr)
#define CHECK_BOUNDS_OR_RETURN(ptr, n, pend, dend)          \
    do                                                      \
    {                                                       \
        if ((void *)(ptr) + (n) > (const void *)(dend))           \
            return 0;                                       \
        barrier_var(ptr);                                   \
        if ((void *)(ptr) + (n) > (const void *)(pend))           \
            return 0;                                       \
        barrier_var(ptr);                                   \
    } while (0)

// checks bounds. if bad, returns 0. if good, increments ptr.
// usage: READ_OR_RETURN(reader_index, 2, payload_end, data_end);
#define READ_OR_RETURN(ptr, n, pend, dend)       \
    do                                           \
    {                                            \
        if ((void *)(ptr) + (n) > (const void *)(dend)) \
            return 0;                            \
        barrier_var(ptr);                        \
        if ((void *)(ptr) + (n) > (const void *)(pend)) \
            return 0;                            \
        barrier_var(ptr);                        \
        ptr += (n);                              \
    } while (0)

// reads a value into 'dest' and increments 'ptr', or returns 0 if OOB
#define READ_VAL_OR_RETURN(dest, ptr, pend, dend)           \
    do                                                      \
    {                                                       \
        if ((void *)(ptr) + sizeof(dest) > (const void *)(dend))  \
            return 0;                                       \
        barrier_var(ptr);                                   \
        if ((void *)(ptr) + sizeof(dest) > (const void *)(pend))  \
            return 0;                                       \
        barrier_var(ptr);                                   \
        dest = *(__typeof__(dest) *)(ptr);                  \
        ptr += sizeof(dest);                                \
    } while (0)

// if condition is false, returns 0 immediately.
#define ASSERT_OR_RETURN(cond) \
    do                         \
    {                          \
        if (!(cond))           \
            return 0;          \
    } while (0)

// if val is not in [min, max], returns 0 immediately.
#define ASSERT_IN_RANGE(val, min, max)      \
    do                                      \
    {                                       \
        if ((val) < (min) || (val) > (max)) \
            return 0;                       \
    } while (0)

// reads a varint into 'dest_struct', increments 'ptr', or returns 0 on failure.
#define VARINT_OR_DIE(dest_struct, ptr, pend, dend) \
    do                                                                 \
    {                                                                  \
        dest_struct = read_varint_sized(ptr, pend, 5, dend);   \
        if (!(dest_struct).bytes)                                      \
            return 0;                                                  \
        (ptr) += (dest_struct).bytes;                                  \
        barrier_var(ptr);                                              \
    } while (0)

// minecraft has a 21bit varint framedecoder so for packet length by protocol difinition only 3 bytes are allowed
#define PACKET_LEN_OR_DIE(dest_struct, ptr, pend, dend) \
    do                                                                 \
    {                                                                  \
        dest_struct = read_varint_sized(ptr, pend, 3, dend);   \
        if (!(dest_struct).bytes)                                      \
            return 0;                                                  \
        (ptr) += (dest_struct).bytes;                                  \
        barrier_var(ptr);                                              \
    } while (0)

struct ipv4_flow_key
{
    const __u32 src_ip;
    const __u32 dst_ip;
    const __u16 src_port;
    const __u16 dst_port;
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

static __always_inline struct ipv4_flow_key gen_ipv4_flow_key(const __u32 src_ip, const __u32 dst_ip, const __u16 src_port, const __u16 dst_port)
{
    struct ipv4_flow_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port};
    return key;
}

static __always_inline struct initial_state gen_initial_state(const __u16 state, const __s32 protocol, const __u32 expected_sequence)
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
