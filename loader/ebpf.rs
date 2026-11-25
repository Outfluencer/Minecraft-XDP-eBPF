use std::ffi::CString;

use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader, include_bytes_aligned};
use log::info;

use crate::config::{Config, ConfigXdpMode};

/// Loads the embedded eBPF object, applies the runtime configuration and
/// attaches the XDP program to `interface`.
///
/// The returned handle owns the attachment: dropping it detaches the filter.
/// No userspace involvement is needed while it runs, all map cleanup
/// (throttle windows, idle player connections) happens in-kernel via
/// `bpf_timer`.
pub fn load_and_attach(interface: &str, config: &Config) -> Result<Ebpf> {
    let mut ebpf = load(config)?;
    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;

    // aya takes interface names as C strings; `interface` stays around for
    // the log and error messages
    let ifname =
        CString::new(interface).with_context(|| format!("invalid interface name '{interface}'"))?;

    // Auto does its own driver -> skb fallback instead of leaving the choice
    // to the kernel, so the mode that is actually active can be logged.
    let (link, mode) = match config.xdp.mode {
        ConfigXdpMode::Auto => match program.attach(&ifname, XdpMode::Driver) {
            Ok(link) => (link, ConfigXdpMode::Driver),
            Err(err) => {
                info!("'{interface}' does not support native XDP ({err}), using generic skb mode");
                let link = program
                    .attach(&ifname, aya::programs::XdpMode::Skb)
                    .with_context(|| format!("failed to attach to interface '{interface}'"))?;
                (link, ConfigXdpMode::Skb)
            }
        },
        ConfigXdpMode::Driver => {
            let link = program.attach(&ifname, XdpMode::Driver).with_context(|| {
                format!(
                    "failed to attach to interface '{interface}' in native driver mode \
                     (the NIC driver may not support XDP; try mode = \"skb\")"
                )
            })?;
            (link, ConfigXdpMode::Driver)
        }
        ConfigXdpMode::Skb => {
            let link = program.attach(&ifname, XdpMode::Skb).with_context(|| {
                format!("failed to attach to interface '{interface}' in skb mode")
            })?;
            (link, ConfigXdpMode::Skb)
        }
    };
    info!("BPF program attached to interface {interface} in {mode} mode ({link:?})");

    for (name, _) in ebpf.maps() {
        info!("Found map: {name}");
    }

    Ok(ebpf)
}

/// `xdp-loader --check`: loads the filter with this configuration into the
/// kernel, which runs it through the verifier, and unloads it again.
/// Nothing is attached to any interface.
pub fn check(config: &Config) -> Result<()> {
    load(config).map(drop)
}

/// Loads the embedded eBPF object with the runtime configuration applied and
/// runs the program through the kernel verifier, without attaching it.
fn load(config: &Config) -> Result<Ebpf> {
    let object = include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/xdp/minecraft_filter.o"
    ));
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
        .override_global("PROMETHEUS", &prometheus, true)
        .override_global("ONLINE_NAMES", &online_names, true)
        .override_global("START_PORT", &start_port, true)
        .override_global("END_PORT", &end_port, true)
        .override_global("HIT_COUNT", &hit_count, true)
        .override_global("HIT_COUNT_RESET_NS", &hit_count_reset_ns, true)
        .override_global("PLAYER_IDLE_NS", &player_idle_ns, true)
        // Replace the placeholder map capacities baked into the object with
        // the configured ones. The names must match the map definitions in
        // xdp/minecraft_filter.c; unlike set_global() there is no must_exist
        // flag, a mismatched name would be silently ignored.
        .map_max_entries("conntrack_map", config.xdp.max_pending_connections)
        .map_max_entries("player_connection_map", config.xdp.max_player_connections)
        .map_max_entries("connection_throttle", config.xdp.max_throttled_ips)
        .load(object)
        .context("failed to load BPF program")?;

    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;
    program
        .load()
        .context("the kernel rejected the BPF program")?;

    Ok(ebpf)
}
