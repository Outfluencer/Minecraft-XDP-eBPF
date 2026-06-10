use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, EbpfLoader, include_bytes_aligned};
use log::info;

use crate::config::Config;

/// Loads the embedded eBPF object, applies the runtime configuration and
/// attaches the XDP program to `interface`.
///
/// The returned handle owns the attachment: dropping it detaches the filter.
/// No userspace involvement is needed while it runs, all map cleanup
/// (throttle windows, idle player connections) happens in-kernel via
/// `bpf_timer`.
pub fn load_and_attach(interface: &str, config: &Config) -> Result<Ebpf> {
    let object =
        include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/c/minecraft_filter.o"));
    info!("Loaded BPF object ({} bytes)", object.len());

    // Push the runtime configuration into the program's `volatile const`
    // globals (BPF .rodata). Each Rust type MUST match its C declaration in
    // c/config.h exactly, since set_global() patches size_of::<T>() bytes at
    // the symbol's offset. `must_exist = true` fails loudly if a symbol is
    // missing (e.g. renamed on the C side) instead of silently ignoring the
    // configured value.
    let prometheus: u8 = config.prometheus as u8;
    let online_names: u8 = config.online_names as u8;
    let start_port: u32 = config.start_port as u32;
    let end_port: u32 = config.end_port as u32;
    let hit_count: u32 = config.hit_count;
    let hit_count_reset_ns: u64 = config.hit_count_reset_secs * 1_000_000_000;

    let mut ebpf = EbpfLoader::new()
        .set_global("PROMETHEUS", &prometheus, true)
        .set_global("ONLINE_NAMES", &online_names, true)
        .set_global("START_PORT", &start_port, true)
        .set_global("END_PORT", &end_port, true)
        .set_global("HIT_COUNT", &hit_count, true)
        .set_global("HIT_COUNT_RESET_NS", &hit_count_reset_ns, true)
        .load(object)
        .context("failed to load BPF program")?;

    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;
    program.load()?;

    let link = program.attach(interface, XdpFlags::empty())?;
    info!("BPF program attached to interface: {interface} ({link:?})");

    for (name, _) in ebpf.maps() {
        info!("Found map: {name}");
    }

    Ok(ebpf)
}
