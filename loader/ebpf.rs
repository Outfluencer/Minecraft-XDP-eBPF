use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, EbpfLoader, include_bytes_aligned};
use log::info;

use crate::config::{Config, XdpMode};

/// Loads the embedded eBPF object, applies the runtime configuration and
/// attaches the XDP program to `interface`.
///
/// The returned handle owns the attachment: dropping it detaches the filter.
/// No userspace involvement is needed while it runs, all map cleanup
/// (throttle windows, idle player connections) happens in-kernel via
/// `bpf_timer`.
pub fn load_and_attach(interface: &str, config: &Config) -> Result<Ebpf> {
    let object =
        include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/xdp/minecraft_filter.o"));
    info!("Loaded BPF object ({} bytes)", object.len());

    // Push the runtime configuration into the program's `volatile const`
    // globals (BPF .rodata). Each Rust type MUST match its C declaration in
    // xdp/config.h exactly, since set_global() patches size_of::<T>() bytes at
    // the symbol's offset. `must_exist = true` fails loudly if a symbol is
    // missing (e.g. renamed on the C side) instead of silently ignoring the
    // configured value.
    let filter = &config.filter;
    let prometheus: u8 = config.metrics.enabled as u8;
    let online_names: u8 = filter.online_names as u8;
    let start_port: u32 = filter.start_port as u32;
    let end_port: u32 = filter.end_port as u32;
    let hit_count: u32 = filter.hit_count;
    let hit_count_reset_ns: u64 = filter.hit_count_reset_secs * 1_000_000_000;
    let player_idle_ns: u64 = filter.player_idle_timeout_secs * 1_000_000_000;

    let mut ebpf = EbpfLoader::new()
        .set_global("PROMETHEUS", &prometheus, true)
        .set_global("ONLINE_NAMES", &online_names, true)
        .set_global("START_PORT", &start_port, true)
        .set_global("END_PORT", &end_port, true)
        .set_global("HIT_COUNT", &hit_count, true)
        .set_global("HIT_COUNT_RESET_NS", &hit_count_reset_ns, true)
        .set_global("PLAYER_IDLE_NS", &player_idle_ns, true)
        // Replace the placeholder map capacities baked into the object with
        // the configured ones. The names must match the map definitions in
        // xdp/minecraft_filter.c; unlike set_global() there is no must_exist
        // flag, a mismatched name would be silently ignored.
        .set_max_entries("conntrack_map", config.xdp.max_pending_connections)
        .set_max_entries("player_connection_map", config.xdp.max_player_connections)
        .set_max_entries("connection_throttle", config.xdp.max_throttled_ips)
        .load(object)
        .context("failed to load BPF program")?;

    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;
    program.load()?;

    // Auto does its own driver -> skb fallback instead of leaving the choice
    // to the kernel, so the mode that is actually active can be logged.
    let (link, mode) = match config.xdp.mode {
        XdpMode::Auto => match program.attach(interface, XdpFlags::DRV_MODE) {
            Ok(link) => (link, XdpMode::Driver),
            Err(err) => {
                info!("'{interface}' does not support native XDP ({err}), using generic skb mode");
                let link = program
                    .attach(interface, XdpFlags::SKB_MODE)
                    .with_context(|| format!("failed to attach to interface '{interface}'"))?;
                (link, XdpMode::Skb)
            }
        },
        XdpMode::Driver => {
            let link = program.attach(interface, XdpFlags::DRV_MODE).with_context(|| {
                format!(
                    "failed to attach to interface '{interface}' in native driver mode \
                     (the NIC driver may not support XDP; try mode = \"skb\")"
                )
            })?;
            (link, XdpMode::Driver)
        }
        XdpMode::Skb => {
            let link = program
                .attach(interface, XdpFlags::SKB_MODE)
                .with_context(|| format!("failed to attach to interface '{interface}' in skb mode"))?;
            (link, XdpMode::Skb)
        }
    };
    info!("BPF program attached to interface {interface} in {mode} mode ({link:?})");

    for (name, _) in ebpf.maps() {
        info!("Found map: {name}");
    }

    Ok(ebpf)
}
