#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

/*
 * Runtime configuration.
 *
 * The Rust loader patches these values into the BPF .rodata section via
 * aya's set_global() before the program is loaded, so changing them only
 * requires a restart of the loader, not a rebuild. The definitions (and
 * compiled-in fallbacks) live in minecraft_filter.c; the types must match
 * the set_global() calls in src/ebpf.rs exactly.
 */
extern volatile const __u8 PROMETHEUS;        // collect statistics in stats_map
extern volatile const __u8 ONLINE_NAMES;      // enforce online-mode usernames (max 16 chars)
extern volatile const __u32 START_PORT;       // first TCP port of the filtered range (inclusive)
extern volatile const __u32 END_PORT;         // last TCP port of the filtered range (inclusive)
extern volatile const __u32 HIT_COUNT;        // max SYNs per source ip per window, 0 disables the throttle
extern volatile const __u64 HIT_COUNT_RESET_NS; // throttle window length in nanoseconds

#endif
