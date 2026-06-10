#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

/*
 * Runtime configuration.
 *
 * The Rust loader patches these values into the BPF .rodata section via
 * aya's set_global() (with must_exist) before the program is loaded, so all
 * of them are always overridden; the zeros are only placeholders. The types
 * must match the set_global() calls in loader/ebpf.rs exactly. Loaded
 * standalone (without the loader), the all-zero config filters nothing.
 *
 * Defining (not just declaring) these in a header is safe because the BPF
 * program is a single translation unit; the test build replaces this header
 * entirely via its include guard.
 */
volatile const __u8 PROMETHEUS = 0;           // collect statistics in stats_map
volatile const __u8 ONLINE_NAMES = 0;         // enforce online-mode usernames (max 16 chars)
volatile const __u32 START_PORT = 0;          // first TCP port of the filtered range (inclusive)
volatile const __u32 END_PORT = 0;            // last TCP port of the filtered range (inclusive)
volatile const __u32 HIT_COUNT = 0;           // max SYNs per source ip per window, 0 disables the throttle
volatile const __u64 HIT_COUNT_RESET_NS = 0;  // throttle window length in nanoseconds
volatile const __u64 PLAYER_IDLE_NS = 0;      // idle check interval for verified connections in nanoseconds;
                                              // entries are removed after one to two intervals without packets

#endif
