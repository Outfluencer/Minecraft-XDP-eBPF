#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>

// compiler barrier: prevents clang from merging or reordering the pointer
// arithmetic around bounds checks, which would make the verifier lose track
// of the checked range
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

// maximum amount of out-of-order/retransmitted packets before a tracked
// connection is dropped entirely
#define MAX_OUT_OF_ORDER 4

/*
 * Connection states stored in initial_state.state, plus pseudo states only
 * returned by inspect_handshake() (RECEIVED_LEGACY_PING and the DIRECT_READ_*
 * values, which signal that more protocol data follows in the same packet).
 * STATE_INVALID doubles as the generic "parse failed" return value of all
 * inspectors.
 */
enum connection_state
{
    STATE_INVALID = 0,
    AWAIT_ACK = 1,
    AWAIT_MC_HANDSHAKE = 2,
    RECEIVED_LEGACY_PING = 3, // this connection will be fully dropped
    AWAIT_STATUS_REQUEST = 4,
    AWAIT_LOGIN = 5,
    AWAIT_PING = 6,
    PING_COMPLETE = 7,
    DIRECT_READ_STATUS_REQUEST = 8,
    DIRECT_READ_LOGIN = 9,
};

/*
 * Bounds-check macros.
 *
 * All of them bail out of the CALLING function with `return 0` when the
 * requested bytes are not fully inside both the TCP payload (pend) and the
 * packet (dend). Checking against both bounds with a barrier in between is
 * what convinces the verifier that every later access is safe.
 */

// checks that [ptr, ptr + n) is in bounds; does NOT advance ptr
#define CHECK_BOUNDS_OR_RETURN(ptr, n, pend, dend)        \
    do                                                    \
    {                                                     \
        if ((void *)(ptr) + (n) > (const void *)(dend))   \
            return 0;                                     \
        barrier_var(ptr);                                 \
        if ((void *)(ptr) + (n) > (const void *)(pend))   \
            return 0;                                     \
        barrier_var(ptr);                                 \
    } while (0)

// checks that [ptr, ptr + n) is in bounds and advances ptr past those bytes
#define SKIP_OR_RETURN(ptr, n, pend, dend)                \
    do                                                    \
    {                                                     \
        CHECK_BOUNDS_OR_RETURN(ptr, n, pend, dend);       \
        (ptr) += (n);                                     \
    } while (0)

// reads a fixed-size value into dest and advances ptr past it
#define READ_VAL_OR_RETURN(dest, ptr, pend, dend)               \
    do                                                          \
    {                                                           \
        CHECK_BOUNDS_OR_RETURN(ptr, sizeof(dest), pend, dend);  \
        (dest) = *(const __typeof__(dest) *)(ptr);              \
        (ptr) += sizeof(dest);                                  \
    } while (0)

// returns 0 from the calling function if the condition does not hold
#define ASSERT_OR_RETURN(cond) \
    do                         \
    {                          \
        if (!(cond))           \
            return 0;          \
    } while (0)

// returns 0 from the calling function if val is not in [min, max]
#define ASSERT_IN_RANGE_OR_RETURN(val, min, max) \
    do                                           \
    {                                            \
        if ((val) < (min) || (val) > (max))      \
            return 0;                            \
    } while (0)

// key identifying one TCP flow (all fields in network byte order)
struct ipv4_flow_key
{
    const __u32 src_ip;
    const __u32 dst_ip;
    const __u16 src_port;
    const __u16 dst_port;
};
_Static_assert(sizeof(struct ipv4_flow_key) == 12, "ipv4_flow_key size mismatch!");

// per-connection tracking data while the handshake sequence is inspected
struct initial_state
{
    __u16 state;    // enum connection_state; u16 to keep the struct padding-free
    __u16 fails;    // out-of-order packets seen so far (see MAX_OUT_OF_ORDER)
    __s32 protocol; // minecraft protocol version (signed by protocol definition)
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
