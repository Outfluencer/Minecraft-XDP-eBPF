/*
 * Native unit tests for the eBPF parsing code (varint.h, protocol.h and the
 * bounds-check macros in common.h).
 *
 * Compiled for the host (not for BPF) and executed by tests/c_unit_tests.rs
 * as part of `cargo test`, with ASan/UBSan enabled when available. Every
 * inspector call runs on an exact-size heap copy of the packet, so any read
 * past data_end trips the address sanitizer instead of going unnoticed.
 */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// provided by bpf/bpf_helpers.h in the BPF build
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/*
 * Stand-in for xdp/config.h, suppressed via its include guard: the real header
 * defines the knobs `volatile const`, but the login tests need to flip
 * ONLINE_NAMES at runtime.
 */
#define CONFIG_H
static volatile __u8 ONLINE_NAMES = 1;

#include "../common.h"
#include "../varint.h"
#include "../protocol.h"

/* ------------------------------------------------------------------------
 * Tiny test framework
 * --------------------------------------------------------------------- */

static unsigned checks_run = 0;
static unsigned checks_failed = 0;

#define CHECK(cond)                                                          \
    do                                                                       \
    {                                                                        \
        checks_run++;                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            checks_failed++;                                                 \
            printf("FAIL %s:%d in %s: %s\n", __FILE__, __LINE__, __func__,   \
                   #cond);                                                   \
        }                                                                    \
    } while (0)

/* ------------------------------------------------------------------------
 * Packet building helpers
 * --------------------------------------------------------------------- */

// reference varint encoder, validated against the wiki.vg test vectors below
static __u32 write_varint(__u8 *out, __s32 value)
{
    __u32 v = (__u32)value;
    __u32 n = 0;
    do
    {
        __u8 byte = v & 0x7F;
        v >>= 7;
        if (v)
        {
            byte |= 0x80;
        }
        out[n++] = byte;
    } while (v);
    return n;
}

struct buf
{
    __u8 b[2048];
    __u32 n;
};

static void put_varint(struct buf *p, __s32 value)
{
    p->n += write_varint(p->b + p->n, value);
}

static void put_u8(struct buf *p, __u8 value)
{
    p->b[p->n++] = value;
}

static void put_fill(struct buf *p, __u8 fill, __u32 count)
{
    memset(p->b + p->n, fill, count);
    p->n += count;
}

// prefixes a packet body with its length varint, like the protocol does
static struct buf packetize(const struct buf *body)
{
    struct buf pkt = {{0}, 0};
    put_varint(&pkt, (__s32)body->n);
    memcpy(pkt.b + pkt.n, body->b, body->n);
    pkt.n += body->n;
    return pkt;
}

/* ------------------------------------------------------------------------
 * Runners: every parse happens on an exact-size heap copy so ASan catches
 * any access past data_end. `slack` adds extra bytes between payload_end
 * and data_end to exercise the dual-bounds checks.
 * --------------------------------------------------------------------- */

static __u8 *heap_copy(const __u8 *bytes, __u32 len, __u32 slack)
{
    const __u32 size = len + slack;
    __u8 *heap = malloc(size ? size : 1); // malloc(0) may return NULL
    if (len)
    {
        memcpy(heap, bytes, len);
    }
    if (slack)
    {
        // 0x01 terminates a varint, so a parser that wrongly runs past
        // payload_end produces a successful-looking parse the assertions
        // can catch (instead of failing by coincidence)
        memset(heap + len, 0x01, slack);
    }
    return heap;
}

static struct varint_value run_varint_slack(const __u8 *bytes, __u32 payload_len, __u32 slack, __u8 max_size)
{
    __u8 *heap = heap_copy(bytes, payload_len, slack);
    const struct varint_value v =
        read_varint_sized(heap, heap + payload_len, max_size, heap + payload_len + slack);
    free(heap);
    return v;
}

static struct varint_value run_varint(const __u8 *bytes, __u32 payload_len, __u8 max_size)
{
    return run_varint_slack(bytes, payload_len, 0, max_size);
}

static __u8 run_status_slack(const __u8 *pkt, __u32 len, __u32 slack)
{
    __u8 *heap = heap_copy(pkt, len, slack);
    const __u8 ok = inspect_status_request(heap, heap + len, heap + len + slack);
    free(heap);
    return ok;
}

static __u8 run_status(const __u8 *pkt, __u32 len)
{
    return run_status_slack(pkt, len, 0);
}

static __u8 run_ping(const __u8 *pkt, __u32 len)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 ok = inspect_ping_request(heap, heap + len, heap + len);
    free(heap);
    return ok;
}

static __u8 run_login(const __u8 *pkt, __u32 len, __s32 protocol)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 ok = inspect_login_packet(heap, heap + len, heap + len, protocol);
    free(heap);
    return ok;
}

static __s32 run_handshake(const __u8 *pkt, __u32 len, __s32 *proto_out, __u32 *resume_off)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 *resume = NULL;
    __s32 proto = 0;
    const __s32 state = inspect_handshake(heap, heap + len, heap + len, &proto, &resume);
    if (proto_out)
    {
        *proto_out = proto;
    }
    if (resume_off)
    {
        *resume_off = resume ? (__u32)(resume - heap) : 0;
    }
    free(heap);
    return state;
}

/* ------------------------------------------------------------------------
 * VARINT_SIZE (compile-time)
 * --------------------------------------------------------------------- */

_Static_assert(VARINT_SIZE(0x00) == 1, "VARINT_SIZE(0)");
_Static_assert(VARINT_SIZE(0x7F) == 1, "VARINT_SIZE(127)");
_Static_assert(VARINT_SIZE(0x80) == 2, "VARINT_SIZE(128)");
_Static_assert(VARINT_SIZE(0x3FFF) == 2, "VARINT_SIZE(16383)");
_Static_assert(VARINT_SIZE(0x4000) == 3, "VARINT_SIZE(16384)");
_Static_assert(VARINT_SIZE(0x1FFFFF) == 3, "VARINT_SIZE(2097151)");
_Static_assert(VARINT_SIZE(0x200000) == 4, "VARINT_SIZE(2097152)");
_Static_assert(VARINT_SIZE(0xFFFFFFF) == 4, "VARINT_SIZE(268435455)");
_Static_assert(VARINT_SIZE(0x10000000) == 5, "VARINT_SIZE(268435456)");

/* ------------------------------------------------------------------------
 * Varint reader
 * --------------------------------------------------------------------- */

// test vectors from the protocol documentation (wiki.vg)
static const struct
{
    __u8 bytes[5];
    __u32 len;
    __s32 value;
} VARINT_VECTORS[] = {
    {{0x00}, 1, 0},
    {{0x01}, 1, 1},
    {{0x02}, 1, 2},
    {{0x7F}, 1, 127},
    {{0x80, 0x01}, 2, 128},
    {{0xFF, 0x01}, 2, 255},
    {{0xDD, 0xC7, 0x01}, 3, 25565},
    {{0xFF, 0xFF, 0x7F}, 3, 2097151},
    {{0xFF, 0xFF, 0xFF, 0xFF, 0x07}, 5, 2147483647},
    {{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, 5, -1},
    {{0x80, 0x80, 0x80, 0x80, 0x08}, 5, -2147483647 - 1},
};

static void test_varint_decodes_known_vectors(void)
{
    for (__u32 i = 0; i < sizeof(VARINT_VECTORS) / sizeof(VARINT_VECTORS[0]); i++)
    {
        const struct varint_value v =
            run_varint(VARINT_VECTORS[i].bytes, VARINT_VECTORS[i].len, MAX_VARINT_BYTES);
        CHECK(v.value == VARINT_VECTORS[i].value);
        CHECK(v.bytes == VARINT_VECTORS[i].len);

        // the encoder used by the packet builders must produce these
        // exact bytes, otherwise all later tests would test nothing
        __u8 encoded[5] = {0};
        const __u32 n = write_varint(encoded, VARINT_VECTORS[i].value);
        CHECK(n == VARINT_VECTORS[i].len);
        CHECK(memcmp(encoded, VARINT_VECTORS[i].bytes, n) == 0);
    }
}

static void test_varint_roundtrip(void)
{
    static const __s32 VALUES[] = {0,     1,        2,       127,        128,        255,
                                   300,   16383,    16384,   25565,      2097151,    2097152,
                                   -1,    -25565,   268435455, 268435456, 2147483647, -2147483647 - 1};
    for (__u32 i = 0; i < sizeof(VALUES) / sizeof(VALUES[0]); i++)
    {
        __u8 encoded[5];
        const __u32 n = write_varint(encoded, VALUES[i]);
        const struct varint_value v = run_varint(encoded, n, MAX_VARINT_BYTES);
        CHECK(v.value == VALUES[i]);
        CHECK(v.bytes == n);
    }
}

static void test_varint_rejects_truncated_input(void)
{
    const __u8 two_byte[] = {0x80, 0x01};
    CHECK(run_varint(two_byte, 1, MAX_VARINT_BYTES).bytes == 0); // continuation cut off
    CHECK(run_varint(two_byte, 0, MAX_VARINT_BYTES).bytes == 0); // empty payload

    const __u8 three_byte[] = {0xDD, 0xC7, 0x01};
    CHECK(run_varint(three_byte, 2, MAX_VARINT_BYTES).bytes == 0);
}

static void test_varint_respects_max_size(void)
{
    const __u8 two_byte[] = {0x80, 0x01};
    CHECK(run_varint(two_byte, 2, 1).bytes == 0);
    CHECK(run_varint(two_byte, 2, 2).bytes == 2);

    const __u8 three_byte[] = {0xDD, 0xC7, 0x01};
    CHECK(run_varint(three_byte, 3, 2).bytes == 0);
    CHECK(run_varint(three_byte, 3, 3).bytes == 3);
}

static void test_varint_never_reads_past_payload_end(void)
{
    // a continuation byte at the end of the payload, with valid-looking
    // bytes behind payload_end: must fail instead of reading the slack
    const __u8 bytes[] = {0x80};
    CHECK(run_varint_slack(bytes, 1, 4, MAX_VARINT_BYTES).bytes == 0);
}

static void test_varint_stops_at_terminator(void)
{
    // trailing bytes after a complete varint are someone else's business
    const __u8 bytes[] = {0x01, 0xFF, 0xFF};
    const struct varint_value v = run_varint(bytes, 3, MAX_VARINT_BYTES);
    CHECK(v.value == 1);
    CHECK(v.bytes == 1);
}

static void test_varint_rejects_overlong_encoding(void)
{
    // continuation bit still set on the fifth byte: a sixth byte would be
    // required, which no 32-bit varint may have
    const __u8 bytes[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    CHECK(run_varint(bytes, 6, MAX_VARINT_BYTES).bytes == 0);
}

/* ------------------------------------------------------------------------
 * Bounds-check macros
 * --------------------------------------------------------------------- */

static __u8 wrap_check_bounds(const __u8 *cursor, __u32 n, const __u8 *pend, const void *dend)
{
    CHECK_BOUNDS_OR_RETURN(cursor, n, pend, dend);
    return 1;
}

static __u8 wrap_skip_twice(const __u8 *cursor, __u32 a, __u32 b, const __u8 *pend, const void *dend)
{
    SKIP_OR_RETURN(cursor, a, pend, dend);
    SKIP_OR_RETURN(cursor, b, pend, dend);
    return 1;
}

static __u8 wrap_read_u64(const __u8 *cursor, const __u8 *pend, const void *dend, __u64 *out)
{
    READ_VAL_OR_RETURN(*out, cursor, pend, dend);
    return 1;
}

static void test_bounds_macros(void)
{
    __u8 *heap = malloc(16);
    for (__u8 i = 0; i < 16; i++)
    {
        heap[i] = i;
    }
    const __u8 *pend = heap + 16;

    CHECK(wrap_check_bounds(heap, 16, pend, pend) == 1);
    CHECK(wrap_check_bounds(heap, 17, pend, pend) == 0);
    CHECK(wrap_check_bounds(heap + 16, 0, pend, pend) == 1);
    // payload_end binds even when data_end leaves room
    CHECK(wrap_check_bounds(heap, 10, heap + 8, pend) == 0);

    CHECK(wrap_skip_twice(heap, 8, 8, pend, pend) == 1);
    CHECK(wrap_skip_twice(heap, 8, 9, pend, pend) == 0);

    __u64 value = 0;
    CHECK(wrap_read_u64(heap, pend, pend, &value) == 1);
    CHECK(value == 0x0706050403020100ULL); // little endian
    // unaligned read is fine by design (network data)
    CHECK(wrap_read_u64(heap + 1, pend, pend, &value) == 1);
    CHECK(value == 0x0807060504030201ULL);
    CHECK(wrap_read_u64(heap + 9, pend, pend, &value) == 0);

    free(heap);
}

/* ------------------------------------------------------------------------
 * Status request: [len=0x01][id=0x00]
 * --------------------------------------------------------------------- */

static void test_status_request(void)
{
    const __u8 valid[] = {0x01, 0x00};
    CHECK(run_status(valid, 2) == 1);
    // bytes beyond payload_end must not change the verdict
    CHECK(run_status_slack(valid, 2, 8) == 1);

    const __u8 wrong_len[] = {0x02, 0x00};
    CHECK(run_status(wrong_len, 2) == 0);

    const __u8 wrong_id[] = {0x01, 0x01};
    CHECK(run_status(wrong_id, 2) == 0);

    const __u8 trailing[] = {0x01, 0x00, 0x00};
    CHECK(run_status(trailing, 3) == 0);

    const __u8 non_canonical_len[] = {0x81, 0x00, 0x00};
    CHECK(run_status(non_canonical_len, 3) == 0);

    CHECK(run_status(valid, 1) == 0);
    CHECK(run_status(valid, 0) == 0);
}

/* ------------------------------------------------------------------------
 * Ping request: [len=0x09][id=0x01][8 byte timestamp]
 * --------------------------------------------------------------------- */

static void test_ping_request(void)
{
    const __u8 valid[] = {0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(valid, 10) == 1);

    CHECK(run_ping(valid, 9) == 0); // truncated timestamp

    const __u8 wrong_id[] = {0x09, 0x00, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(wrong_id, 10) == 0);

    const __u8 wrong_len[] = {0x08, 0x01, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(wrong_len, 10) == 0);

    const __u8 trailing[] = {0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    CHECK(run_ping(trailing, 11) == 0);
}

/* ------------------------------------------------------------------------
 * Handshake: [len][id=0x00][protocol][host len][host][port][intention]
 * --------------------------------------------------------------------- */

static struct buf build_handshake(__s32 protocol, __u32 host_len, __s32 intention)
{
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00); // packet id
    put_varint(&body, protocol);
    put_varint(&body, (__s32)host_len);
    put_fill(&body, 'h', host_len);
    put_u8(&body, 0x63); // port 25565
    put_u8(&body, 0xDD);
    put_varint(&body, intention);
    return packetize(&body);
}

static void test_handshake_intentions(void)
{
    __s32 proto = 0;

    struct buf status = build_handshake(763, 14, 1);
    CHECK(run_handshake(status.b, status.n, &proto, NULL) == AWAIT_STATUS_REQUEST);
    CHECK(proto == 763);

    struct buf login = build_handshake(763, 14, 2);
    CHECK(run_handshake(login.b, login.n, &proto, NULL) == AWAIT_LOGIN);

    // intention 3 (transfer) exists since 1.20.5 (766)
    struct buf transfer_new = build_handshake(766, 14, 3);
    CHECK(run_handshake(transfer_new.b, transfer_new.n, &proto, NULL) == AWAIT_LOGIN);
    struct buf transfer_old = build_handshake(765, 14, 3);
    CHECK(run_handshake(transfer_old.b, transfer_old.n, &proto, NULL) == STATE_INVALID);

    struct buf intention_zero = build_handshake(763, 14, 0);
    CHECK(run_handshake(intention_zero.b, intention_zero.n, &proto, NULL) == STATE_INVALID);
    struct buf intention_four = build_handshake(763, 14, 4);
    CHECK(run_handshake(intention_four.b, intention_four.n, &proto, NULL) == STATE_INVALID);
}

static void test_handshake_legacy_ping(void)
{
    const __u8 legacy[] = {0xFE, 0x01};
    CHECK(run_handshake(legacy, 2, NULL, NULL) == RECEIVED_LEGACY_PING);
    CHECK(run_handshake(legacy, 1, NULL, NULL) == RECEIVED_LEGACY_PING);
    CHECK(run_handshake(legacy, 0, NULL, NULL) == STATE_INVALID);
}

static void test_handshake_rejects_malformed(void)
{
    // wrong packet id
    struct buf body = {{0}, 0};
    put_varint(&body, 0x01); // packet id 1 instead of 0
    put_varint(&body, 763);
    put_varint(&body, 0);
    put_u8(&body, 0x63);
    put_u8(&body, 0xDD);
    put_varint(&body, 1);
    struct buf wrong_id = packetize(&body);
    CHECK(run_handshake(wrong_id.b, wrong_id.n, NULL, NULL) == STATE_INVALID);

    // truncated: every prefix of a valid handshake must be rejected
    struct buf valid = build_handshake(763, 14, 1);
    for (__u32 len = 0; len < valid.n; len++)
    {
        CHECK(run_handshake(valid.b, len, NULL, NULL) == STATE_INVALID);
    }

    // length field below the minimum (smallest possible body is 6 bytes)
    const __u8 len_too_small[] = {0x03, 0x00, 0x00};
    CHECK(run_handshake(len_too_small, 3, NULL, NULL) == STATE_INVALID);

    // length field above the maximum (787)
    struct buf len_too_big = {{0}, 0};
    put_varint(&len_too_big, 788);
    put_fill(&len_too_big, 0x00, 8);
    CHECK(run_handshake(len_too_big.b, len_too_big.n, NULL, NULL) == STATE_INVALID);

    // host longer than the protocol allows (255 * 3 = 765)
    struct buf host_too_long = build_handshake(763, 766, 1);
    CHECK(run_handshake(host_too_long.b, host_too_long.n, NULL, NULL) == STATE_INVALID);

    // the longest legal host must still parse
    struct buf host_max = build_handshake(763, 765, 1);
    CHECK(run_handshake(host_max.b, host_max.n, NULL, NULL) == AWAIT_STATUS_REQUEST);

    // empty host is allowed by the protocol bounds
    struct buf host_empty = build_handshake(763, 0, 1);
    CHECK(run_handshake(host_empty.b, host_empty.n, NULL, NULL) == AWAIT_STATUS_REQUEST);
}

static void test_handshake_combined_with_status_request(void)
{
    struct buf pkt = build_handshake(763, 14, 1);
    const __u32 handshake_len = pkt.n;
    put_u8(&pkt, 0x01); // status request appended in the same segment
    put_u8(&pkt, 0x00);

    __s32 proto = 0;
    __u32 resume = 0;
    CHECK(run_handshake(pkt.b, pkt.n, &proto, &resume) == DIRECT_READ_STATUS_REQUEST);
    CHECK(resume == handshake_len);
    CHECK(run_status(pkt.b + resume, pkt.n - resume) == 1);
}

static void test_handshake_combined_with_login(void)
{
    struct buf pkt = build_handshake(765, 14, 2);
    const __u32 handshake_len = pkt.n;

    struct buf login_body = {{0}, 0};
    put_varint(&login_body, 0x00); // packet id
    put_varint(&login_body, 5);    // username length
    put_fill(&login_body, 'a', 5);
    put_fill(&login_body, 0xAB, 16); // uuid (1.20.2+)
    struct buf login = packetize(&login_body);
    memcpy(pkt.b + pkt.n, login.b, login.n);
    pkt.n += login.n;

    __s32 proto = 0;
    __u32 resume = 0;
    CHECK(run_handshake(pkt.b, pkt.n, &proto, &resume) == DIRECT_READ_LOGIN);
    CHECK(resume == handshake_len);
    CHECK(proto == 765);
    CHECK(run_login(pkt.b + resume, pkt.n - resume, proto) == 1);
}

static void test_handshake_rejects_length_mismatch(void)
{
    // valid fields, but the declared length is off by one: the backend's
    // frame decoder would cut the stream at a different offset than the
    // filter's state machine
    struct buf too_big = build_handshake(763, 14, 1);
    too_big.b[0]++;
    CHECK(run_handshake(too_big.b, too_big.n, NULL, NULL) == STATE_INVALID);

    struct buf too_small = build_handshake(763, 14, 1);
    too_small.b[0]--;
    CHECK(run_handshake(too_small.b, too_small.n, NULL, NULL) == STATE_INVALID);

    // the appended status request must not be reachable through a lying
    // handshake length either (the backend would read its bytes as part of
    // the handshake frame)
    struct buf combined = build_handshake(763, 14, 1);
    combined.b[0]++;
    put_u8(&combined, 0x01);
    put_u8(&combined, 0x00);
    CHECK(run_handshake(combined.b, combined.n, NULL, NULL) == STATE_INVALID);
}

/* ------------------------------------------------------------------------
 * Login request, all protocol eras:
 *   < 759            [id][name]
 *   759 (1.19)       [id][name][key block]
 *   760 (1.19.1/2)   [id][name][key block][has uuid + uuid]
 *   761+ (1.19.3)    [id][name][has uuid + uuid]
 *   764+ (1.20.2)    [id][name][uuid]
 * --------------------------------------------------------------------- */

static struct buf build_simple_login(__u32 name_len)
{
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00); // packet id
    put_varint(&body, (__s32)name_len);
    put_fill(&body, 'a', name_len);
    return body; // callers append era-specific fields, then packetize
}

static void test_login_pre_1_19(void)
{
    struct buf body = build_simple_login(5);
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 47) == 1);  // 1.8
    CHECK(run_login(pkt.b, pkt.n, 758) == 1); // 1.18.2

    // 1.20.2+ requires a uuid after the name, so the same bytes must fail
    CHECK(run_login(pkt.b, pkt.n, 764) == 0);

    CHECK(run_login(pkt.b, pkt.n - 1, 47) == 0); // truncated
    put_u8(&pkt, 0x00);
    CHECK(run_login(pkt.b, pkt.n, 47) == 0); // trailing byte
    CHECK(run_login(pkt.b, 0, 47) == 0);     // empty payload
}

static void test_login_username_rules(void)
{
    // 16 chars is the online-mode maximum
    struct buf name16 = build_simple_login(16);
    struct buf pkt16 = packetize(&name16);
    CHECK(run_login(pkt16.b, pkt16.n, 758) == 1);

    struct buf name17 = build_simple_login(17);
    struct buf pkt17 = packetize(&name17);
    CHECK(run_login(pkt17.b, pkt17.n, 758) == 0);

    // offline mode allows up to 48 bytes (16 chars * 3 utf-8 bytes)
    ONLINE_NAMES = 0;
    CHECK(run_login(pkt17.b, pkt17.n, 758) == 1);
    struct buf name48 = build_simple_login(48);
    struct buf pkt48 = packetize(&name48);
    CHECK(run_login(pkt48.b, pkt48.n, 758) == 1);
    struct buf name49 = build_simple_login(49);
    struct buf pkt49 = packetize(&name49);
    CHECK(run_login(pkt49.b, pkt49.n, 758) == 0);
    ONLINE_NAMES = 1;

    // empty names are impossible
    struct buf name0 = build_simple_login(0);
    struct buf pkt0 = packetize(&name0);
    CHECK(run_login(pkt0.b, pkt0.n, 758) == 0);

    // a non-canonical two-byte encoding of name length 16 must be rejected
    // (the reader is limited to the canonical varint width)
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00);
    put_u8(&body, 0x90); // 16 with a needless continuation byte
    put_u8(&body, 0x00);
    put_fill(&body, 'a', 16);
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 758) == 0);
}

static void test_login_1_19_key_block(void)
{
    // 1.19 - 1.19.2 (759/760): optional chat signing key after the name
    struct buf no_key = build_simple_login(5);
    put_u8(&no_key, 0x00); // has_public_key = false
    struct buf no_key_pkt = packetize(&no_key);
    CHECK(run_login(no_key_pkt.b, no_key_pkt.n, 759) == 1);

    struct buf with_key = build_simple_login(5);
    put_u8(&with_key, 0x01);       // has_public_key = true
    put_fill(&with_key, 0xEE, 8);  // expiry timestamp
    put_varint(&with_key, 16);     // key length
    put_fill(&with_key, 0xBB, 16); // key
    put_varint(&with_key, 32);     // signature length
    put_fill(&with_key, 0xCC, 32); // signature
    struct buf with_key_pkt = packetize(&with_key);
    CHECK(run_login(with_key_pkt.b, with_key_pkt.n, 759) == 1);

    // key larger than the protocol maximum (512)
    struct buf big_key = build_simple_login(5);
    put_u8(&big_key, 0x01);
    put_fill(&big_key, 0xEE, 8);
    put_varint(&big_key, 513);
    put_fill(&big_key, 0xBB, 513);
    put_varint(&big_key, 32);
    put_fill(&big_key, 0xCC, 32);
    struct buf big_key_pkt = packetize(&big_key);
    CHECK(run_login(big_key_pkt.b, big_key_pkt.n, 759) == 0);

    // 1.19.3 (761) dropped the key block again, so a packet carrying one
    // must be rejected there. (The no-key packet is coincidentally also a
    // valid 761 packet: its 0x00 then reads as has_uuid = false.)
    CHECK(run_login(with_key_pkt.b, with_key_pkt.n, 761) == 0);
    CHECK(run_login(no_key_pkt.b, no_key_pkt.n, 761) == 1);
}

static void test_login_uuid_eras(void)
{
    // 760 (1.19.1): key block, then optional uuid
    struct buf v760 = build_simple_login(5);
    put_u8(&v760, 0x00);          // has_public_key = false
    put_u8(&v760, 0x01);          // has_uuid = true
    put_fill(&v760, 0xAB, 16);    // uuid
    struct buf v760_pkt = packetize(&v760);
    CHECK(run_login(v760_pkt.b, v760_pkt.n, 760) == 1);

    struct buf v760_no_uuid = build_simple_login(5);
    put_u8(&v760_no_uuid, 0x00); // has_public_key = false
    put_u8(&v760_no_uuid, 0x00); // has_uuid = false
    struct buf v760_no_uuid_pkt = packetize(&v760_no_uuid);
    CHECK(run_login(v760_no_uuid_pkt.b, v760_no_uuid_pkt.n, 760) == 1);

    // 761/762 (1.19.3/4): no key block, optional uuid
    struct buf v762 = build_simple_login(5);
    put_u8(&v762, 0x01);
    put_fill(&v762, 0xAB, 16);
    struct buf v762_pkt = packetize(&v762);
    CHECK(run_login(v762_pkt.b, v762_pkt.n, 762) == 1);

    // 764+ (1.20.2): uuid always present, no flag
    struct buf v765 = build_simple_login(5);
    put_fill(&v765, 0xAB, 16);
    struct buf v765_pkt = packetize(&v765);
    CHECK(run_login(v765_pkt.b, v765_pkt.n, 765) == 1);

    // truncated uuid
    struct buf v765_short = build_simple_login(5);
    put_fill(&v765_short, 0xAB, 8);
    struct buf v765_short_pkt = packetize(&v765_short);
    CHECK(run_login(v765_short_pkt.b, v765_short_pkt.n, 765) == 0);
}

static void test_login_rejects_length_mismatch(void)
{
    // modern login (1.20.2+): name + uuid, with a length prefix off by one
    struct buf body = build_simple_login(5);
    put_fill(&body, 0xAB, 16); // uuid
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 765) == 1); // consistent length is fine

    pkt.b[0]++;
    CHECK(run_login(pkt.b, pkt.n, 765) == 0);

    pkt.b[0] -= 2;
    CHECK(run_login(pkt.b, pkt.n, 765) == 0);
}

/* --------------------------------------------------------------------- */

int main(void)
{
    test_varint_decodes_known_vectors();
    test_varint_roundtrip();
    test_varint_rejects_truncated_input();
    test_varint_respects_max_size();
    test_varint_never_reads_past_payload_end();
    test_varint_stops_at_terminator();
    test_varint_rejects_overlong_encoding();
    test_bounds_macros();
    test_status_request();
    test_ping_request();
    test_handshake_intentions();
    test_handshake_legacy_ping();
    test_handshake_rejects_malformed();
    test_handshake_combined_with_status_request();
    test_handshake_combined_with_login();
    test_handshake_rejects_length_mismatch();
    test_login_pre_1_19();
    test_login_username_rules();
    test_login_1_19_key_block();
    test_login_uuid_eras();
    test_login_rejects_length_mismatch();

    printf("%u checks, %u failures\n", checks_run, checks_failed);
    return checks_failed ? 1 : 0;
}
