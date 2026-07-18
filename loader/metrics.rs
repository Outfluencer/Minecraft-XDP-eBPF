use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use aya::{Ebpf, Pod};
use log::{debug, error, info};
use prometheus::{Encoder, IntCounter, TextEncoder, register_int_counter};

use crate::config::Config;
use crate::shutdown::Shutdown;

/// Defines the userspace mirror of `struct statistics` (see xdp/stats.h)
/// together with one Prometheus counter per field, so the struct layout, the
/// per-cpu summing and the published metrics all stay in sync from a single
/// field list. Field order and types must match the C struct exactly.
macro_rules! statistics {
    ($($field:ident => $metric:literal, $help:literal;)+) => {
        #[repr(C)]
        #[derive(Copy, Clone, Debug, Default)]
        pub struct Statistics {
            $(pub $field: u64,)+
        }

        // SAFETY: repr(C) struct of plain u64 fields without padding, valid
        // for any bit pattern read from the map.
        unsafe impl Pod for Statistics {}

        impl Statistics {
            fn add(&mut self, other: &Statistics) {
                $(self.$field += other.$field;)+
            }
        }

        struct Counters {
            $($field: IntCounter,)+
        }

        impl Counters {
            fn new() -> Self {
                Self {
                    $($field: register_int_counter!($metric, $help).unwrap(),)+
                }
            }

            /// Publishes cumulative map totals as counter increments. The
            /// unpinned stats map and this process always die together, so
            /// publishing the delta since the last poll keeps proper counter
            /// semantics; on restart both reset together, which Prometheus
            /// handles as a regular counter reset.
            fn publish(&self, total: &Statistics) {
                $(self.$field.inc_by(total.$field.saturating_sub(self.$field.get()));)+
            }
        }
    };
}

statistics! {
    verified        => "minecraft_verified_connections", "Total verified connections";
    dropped_packets => "minecraft_dropped_packets", "Total dropped packets";
    state_switches  => "minecraft_state_switches", "Total state switches";
    drop_connection => "minecraft_dropped_connections", "Total dropped connections";
    syn             => "minecraft_syn_packets", "Total SYN packets";
    tcp_bypass      => "minecraft_tcp_bypass", "Total TCP bypass attempts";
    incoming_bytes  => "minecraft_incoming_bytes", "Total incoming bytes";
    dropped_bytes   => "minecraft_dropped_bytes", "Total dropped bytes";
}

// compile-time layout check, mirrors the _Static_assert in xdp/stats.h
const _: () = assert!(std::mem::size_of::<Statistics>() == 64);

static COUNTERS: LazyLock<Counters> = LazyLock::new(Counters::new);

/// Starts the metrics machinery if enabled in the config: takes ownership of
/// the stats map, spawns the polling thread and (when an address is
/// configured) the HTTP endpoint. Returns the polling thread's handle.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    if !config.metrics.enabled {
        return Ok(None);
    }

    let map = ebpf
        .take_map("stats_map")
        .context("can't take map 'stats_map'")?;
    let stats = PerCpuArray::try_from(map)?;

    match &config.metrics.addr {
        Some(addr) => serve_http(addr.clone()),
        None => info!("Metrics collection enabled but no addr set; HTTP endpoint disabled"),
    }

    let poll_interval = Duration::from_secs(config.metrics.poll_secs);
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("track-stats".into())
        .spawn(move || poll_loop(stats, shutdown, poll_interval))?;
    Ok(Some(handle))
}

/// Sums the per-cpu slices of the stats map and publishes the totals every
/// `poll_interval` until shutdown ends the loop. Read errors are logged and
/// retried next interval: metrics are auxiliary and must never take down the
/// filter itself.
fn poll_loop(
    stats: PerCpuArray<MapData, Statistics>,
    shutdown: Arc<Shutdown>,
    poll_interval: Duration,
) {
    loop {
        match stats.get(&0, 0) {
            Ok(per_cpu) => {
                let mut total = Statistics::default();
                for cpu_stats in per_cpu.iter() {
                    total.add(cpu_stats);
                }
                debug!("Stats: {total:?}");
                COUNTERS.publish(&total);
            }
            Err(e) => {
                error!("Failed to read stats map (retrying next interval): {e}");
            }
        }
        if !shutdown.sleep(poll_interval) {
            return;
        }
    }
}

/// Serves the Prometheus text endpoint on `addr` from its own thread.
fn serve_http(addr: String) {
    thread::spawn(move || {
        let server = match tiny_http::Server::http(&addr) {
            Ok(server) => server,
            Err(e) => {
                error!("Failed to start metrics server: {e}");
                return;
            }
        };
        info!("Prometheus metrics server running on {addr}/metrics");
        for request in server.incoming_requests() {
            if request.url() != "/metrics" {
                let _ = request.respond(tiny_http::Response::empty(404));
                continue;
            }
            debug!("Received metrics request from {:?}", request.remote_addr());
            let mut buffer = vec![];
            if let Err(e) = TextEncoder::new().encode(&prometheus::gather(), &mut buffer) {
                error!("Failed to encode metrics: {e}");
                continue;
            }
            let response = tiny_http::Response::from_data(buffer).with_header(
                tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/plain; version=0.0.4; charset=utf-8"[..],
                )
                .unwrap(),
            );
            let _ = request.respond(response);
        }
    });
}
