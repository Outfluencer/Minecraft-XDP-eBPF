use crate::common::Ipv4AddrImpl;
use anyhow::Context;
use anyhow::Result;
use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    maps::{HashMap, MapData, PerCpuArray},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use colored::Colorize;
use common::{Ipv4FlowKey, Statistics};
use fern::colors::Color;
use file_rotate::{ContentLimit, FileRotate, compression::Compression, suffix::AppendCount};
use lazy_static::lazy_static;
use log::LevelFilter;
use log::debug;
use log::warn;
use log::{error, info};
use prometheus::{IntGauge, register_int_gauge};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use std::path::Path;
use std::{
    env,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to attach to
    #[arg(required_unless_present = "license")]
    interface: Option<String>,

    /// Path to the TOML configuration file (created with defaults if missing)
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Print license information
    #[arg(long, action)]
    license: bool,
}

mod common;
mod config;
mod mapimpl;

use config::Config;

const OLD_CONNECTION_TIMEOUT: u64 = 60; // every 60 seconds
const STATS_TRACKING_CYCLE: u64 = 10; // every 10 seconds

lazy_static! {
    static ref INCOMING_BYTES: IntGauge =
        register_int_gauge!("minecraft_incoming_bytes", "Total incoming bytes").unwrap();
    static ref DROPPED_BYTES: IntGauge =
        register_int_gauge!("minecraft_dropped_bytes", "Total dropped bytes").unwrap();
    static ref VERIFIED: IntGauge = register_int_gauge!(
        "minecraft_verified_connections",
        "Total verified connections"
    )
    .unwrap();
    static ref DROPPED_PACKETS: IntGauge =
        register_int_gauge!("minecraft_dropped_packets", "Total dropped packets").unwrap();
    static ref STATE_SWITCHES: IntGauge =
        register_int_gauge!("minecraft_state_switches", "Total state switches").unwrap();
    static ref DROP_CONNECTION: IntGauge =
        register_int_gauge!("minecraft_dropped_connections", "Total dropped connections").unwrap();
    static ref SYN: IntGauge =
        register_int_gauge!("minecraft_syn_packets", "Total SYN packets").unwrap();
    static ref TCP_BYPASS: IntGauge =
        register_int_gauge!("minecraft_tcp_bypass", "Total TCP bypass attempts").unwrap();
}

fn setup_logger() -> Result<(), anyhow::Error> {
    let colors = fern::colors::ColoredLevelConfig::new()
        .debug(Color::Magenta)
        .info(Color::Green)
        .warn(Color::Yellow)
        .error(Color::Red);

    let level_filter = match std::env::var("RUST_LOG") {
        Ok(var) => match var.to_lowercase().as_str() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        },
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                LevelFilter::Debug
            }
            #[cfg(not(debug_assertions))]
            {
                LevelFilter::Info
            }
        }
    };

    let console_dispatch = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} {}{}{} {}",
                chrono::Local::now()
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
                    .white(),
                "[".bright_black(),
                colors.color(record.level()),
                "]".bright_black(),
                message
            ))
        })
        .chain(std::io::stdout());

    let file_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .chain(Box::new(FileRotate::new(
            "xdp-loader.log",
            AppendCount::new(5),
            ContentLimit::Bytes(100 * 1024 * 1024), // 100 MB
            Compression::None,
            #[cfg(unix)]
            None,
        )) as Box<dyn std::io::Write + Send>);

    fern::Dispatch::new()
        .level(level_filter)
        .chain(console_dispatch)
        .chain(file_dispatch)
        .apply()?;

    Ok(())
}

fn shutdown(running: Arc<AtomicBool>, condvar: Arc<Condvar>) {
    if running.load(Ordering::SeqCst) {
        info!("Shutting down...");
        running.store(false, Ordering::SeqCst);
        condvar.notify_all();
    }
}

fn main() {
    let args = Args::parse();

    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            #[cfg(debug_assertions)]
            std::env::set_var("RUST_LOG", "debug");
            #[cfg(not(debug_assertions))]
            std::env::set_var("RUST_LOG", "info");
        }
    }

    if args.license {
        println!(include_str!("../LICENSE"));
        return;
    }
    setup_logger().expect("Failed to setup logger");

    info!("Loading minecraft xdp filter v3 by Outfluencer...");

    let running = Arc::new(AtomicBool::new(true));
    let condvar = Arc::new(Condvar::new());

    start_shutdown_hook(running.clone(), condvar.clone());

    let mut epbf: Option<Ebpf> = None;
    if let Some(interface) = args.interface {
        match Config::load(Path::new(&args.config)) {
            Err(e) => {
                error!("Failed to load config '{}': {:?}", args.config, e);
            }
            Ok(config) => {
                info!("Loaded configuration: {:?}", config);
                match load(&interface, &config, running.clone(), condvar.clone()) {
                    Err(e) => {
                        error!("Failed to load BPF program: {}", e);
                    }
                    Ok(value) => {
                        epbf = Some(value);
                    }
                }
            }
        }
    } else {
        error!("Interface is required unless --license is specified");
    }

    shutdown(running, condvar);
    drop(epbf);

    info!("Good bye!");
}

fn start_shutdown_hook(arc: Arc<AtomicBool>, condvar: Arc<Condvar>) {
    let mut signals = Signals::new(TERM_SIGNALS).expect("Couldn't register signals");
    thread::spawn(move || {
        for signal in signals.forever() {
            warn!("Received termination signal: {signal}");
            shutdown(arc, condvar);
            break; // Stop on first termination signal
        }
    });
}
fn start_metrics_server(addr: String) {
    thread::spawn(move || {
        let server = match tiny_http::Server::http(&addr) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to start metrics server: {}", e);
                return;
            }
        };
        info!("Prometheus metrics server running on {}/metrics", addr);
        for request in server.incoming_requests() {
            if request.url() == "/metrics" {
                use prometheus::Encoder;

                debug!("Received metrics request from {:?}", request.remote_addr());
                let encoder = prometheus::TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = vec![];
                if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                    error!("Failed to encode metrics: {}", e);
                    continue;
                }
                let response = tiny_http::Response::from_data(buffer)
                    .with_header(tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"text/plain; version=0.0.4; charset=utf-8"[..],
                    ).unwrap());
                let _ = request.respond(response);
            } else {
                let _ = request.respond(tiny_http::Response::empty(404));
            }
        }
    });
}

fn load(
    interface: &str,
    config: &Config,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
) -> Result<Ebpf, anyhow::Error> {
    let data = include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/c/minecraft_filter.o"));
    info!("Loaded BPF program (size: {})", data.len());

    // Push the runtime configuration into the eBPF program's `volatile const`
    // globals (.rodata). The Rust types MUST match the C declarations exactly,
    // since `set_global` patches `size_of::<T>()` bytes at the symbol offset:
    //   __u8  PROMETHEUS, ONLINE_NAMES
    //   __u32 START_PORT, END_PORT, HIT_COUNT
    let prometheus: u8 = config.prometheus as u8;
    let online_names: u8 = config.online_names as u8;
    let start_port: u32 = config.start_port as u32;
    let end_port: u32 = config.end_port as u32;
    let hit_count: u32 = config.hit_count;

    // `must_exist = true`: fail loudly if a symbol is missing (e.g. the C side
    // was renamed) instead of silently ignoring the configured value.
    let mut ebpf = EbpfLoader::new()
        .set_global("PROMETHEUS", &prometheus, true)
        .set_global("ONLINE_NAMES", &online_names, true)
        .set_global("START_PORT", &start_port, true)
        .set_global("END_PORT", &end_port, true)
        .set_global("HIT_COUNT", &hit_count, true)
        .load(data)?;

    let programm: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .ok_or_else(|| anyhow::anyhow!("Program 'minecraft_filter' not found"))?
        .try_into()?;
    programm.load()?;

    let result = programm.attach(interface, XdpFlags::empty())?;
    info!(
        "BPF program attached to interface: {} ({:?})",
        interface, result
    );

    for (name, _) in ebpf.maps() {
        info!("Found map: {}", name);
    }

    let player_connection_map = {
        let map = ebpf
            .take_map("player_connection_map")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'player_connection_map'"))?;
        HashMap::<MapData, Ipv4FlowKey, u64>::try_from(map)
            .context("try to get player_connection_map HashMap")?
    };
    let player_connection_map_ref = Arc::new(Mutex::new(player_connection_map));

    let connection_throttle = {
        let map = ebpf
            .take_map("connection_throttle")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'connection_throttle'"))?;
        HashMap::<MapData, Ipv4AddrImpl, u32>::try_from(map)
            .context("try to get connection_throttle HashMap")?
    };
    let connection_throttle_ref = Arc::new(Mutex::new(connection_throttle));

    // Only claim the stats map / run the metrics machinery when enabled in config.
    let stats_ref: Option<Arc<Mutex<PerCpuArray<MapData, Statistics>>>> = if config.prometheus {
        let map = ebpf
            .take_map("stats_map")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'stats_map'"))?;
        let stats = PerCpuArray::<MapData, Statistics>::try_from(map)?;
        Some(Arc::new(Mutex::new(stats)))
    } else {
        None
    };

    let handle1 = spawn_old_connection_clear(
        "clear-old",
        running.clone(),
        condvar.clone(),
        player_connection_map_ref,
    )?;
    let handle2 = spawn_connection_throttle_clear(
        "clear-throttle",
        running.clone(),
        condvar.clone(),
        connection_throttle_ref,
        config.hit_count_reset_secs,
    )?;

    let stats_handle = match &stats_ref {
        Some(stats_ref) => {
            let handle = spawn_stats_thread(
                "track-stats",
                running.clone(),
                condvar.clone(),
                stats_ref.clone(),
            )?;
            match &config.metrics_addr {
                Some(addr) => start_metrics_server(addr.clone()),
                None => info!(
                    "Prometheus stats enabled but no metrics_addr set; HTTP endpoint disabled"
                ),
            }
            Some(handle)
        }
        None => None,
    };

    let _ = handle1
        .join()
        .map_err(|e| anyhow::anyhow!("clear-old thread panicked: {:?}", e))?;
    let _ = handle2
        .join()
        .map_err(|e| anyhow::anyhow!("clear-throttle thread panicked: {:?}", e))?;
    if let Some(handle) = stats_handle {
        let _ = handle
            .join()
            .map_err(|e| anyhow::anyhow!("track-stats thread panicked: {:?}", e))?;
    }

    Ok(ebpf)
}

fn spawn_stats_thread(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    stats_ref: Arc<Mutex<PerCpuArray<MapData, Statistics>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) = track_stats(running.clone(), condvar.clone(), stats_ref) {
                error!("Failed to track stats: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

fn track_stats(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    stats_ref: Arc<Mutex<PerCpuArray<MapData, Statistics>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    while running.load(Ordering::SeqCst) {
        let stats = stats_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;

        let values = stats.get(&0, 0)?;
        let mut total = Statistics::default();
        for cpu_stat in values.iter() {
            total.incoming_bytes += cpu_stat.incoming_bytes;
            total.dropped_bytes += cpu_stat.dropped_bytes;
            total.verified += cpu_stat.verified;
            total.dropped_packets += cpu_stat.dropped_packets;
            total.state_switches += cpu_stat.state_switches;
            total.drop_connection += cpu_stat.drop_connection;
            total.syn += cpu_stat.syn;
            total.tcp_bypass += cpu_stat.tcp_bypass;
        }
        debug!(
            "Stats: Incoming: {} bytes, Dropped: {} bytes, Packets Dropped: {}, Verified: {}, Syn: {}, Bypass: {}, State Switches: {}, Drop Conn: {}",
            total.incoming_bytes,
            total.dropped_bytes,
            total.dropped_packets,
            total.verified,
            total.syn,
            total.tcp_bypass,
            total.state_switches,
            total.drop_connection,
        );

        // Update Prometheus metrics
        INCOMING_BYTES.set(total.incoming_bytes as i64);
        DROPPED_BYTES.set(total.dropped_bytes as i64);
        VERIFIED.set(total.verified as i64);
        DROPPED_PACKETS.set(total.dropped_packets as i64);
        STATE_SWITCHES.set(total.state_switches as i64);
        DROP_CONNECTION.set(total.drop_connection as i64);
        SYN.set(total.syn as i64);
        TCP_BYPASS.set(total.tcp_bypass as i64);
        drop(stats); // release lock before waiting

        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(STATS_TRACKING_CYCLE))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

fn spawn_connection_throttle_clear(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    connection_throttle_ref: Arc<Mutex<HashMap<MapData, Ipv4AddrImpl, u32>>>,
    reset_secs: u64,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) = connection_throttle_clear(
                running.clone(),
                condvar.clone(),
                connection_throttle_ref,
                reset_secs,
            ) {
                error!("Failed to clear connection throttles: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

fn connection_throttle_clear(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    connection_throttle_ref: Arc<Mutex<HashMap<MapData, Ipv4AddrImpl, u32>>>,
    reset_secs: u64,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    while running.load(Ordering::SeqCst) {
        {
            let mut throttle = connection_throttle_ref
                .lock()
                .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;
            mapimpl::clear(&mut throttle)?;
        }
        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(reset_secs))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

fn spawn_old_connection_clear(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    player_connection_map_ref: Arc<Mutex<HashMap<MapData, Ipv4FlowKey, u64>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) =
                clear_old_connections(running.clone(), condvar.clone(), player_connection_map_ref)
            {
                error!("Failed to clear old connections: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

fn clear_old_connections(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    player_connection_map_ref: Arc<Mutex<HashMap<MapData, Ipv4FlowKey, u64>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    let mut last_seen: std::collections::HashMap<Ipv4FlowKey, u64> = std::collections::HashMap::new();
    while running.load(Ordering::SeqCst) {
        let mut current_snapshot = std::collections::HashMap::new();
        {
            let mut players = player_connection_map_ref
                .lock()
                .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;
            mapimpl::remove_if(&mut players, |key, counter| {
                let stale = last_seen.get(key).is_some_and(|prev| *prev == *counter);
                current_snapshot.insert(*key, *counter);
                stale
            })?;
        }
        last_seen = current_snapshot;
        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(OLD_CONNECTION_TIMEOUT))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

