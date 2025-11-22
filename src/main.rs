use anyhow::Result;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap, MapData, PerCpuArray, PerCpuValues},
    programs::{Xdp, XdpFlags},
};
use common::Ipv4FlowKey;
use env_logger::{Builder, Env};
use libc::{CLOCK_BOOTTIME, clock_gettime, timespec};
use log::{debug, error, info};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use std::{
    env,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use crate::common::Statistics;

mod common;

const SECOND_TO_NANOS: u64 = 1_000_000_000;

const OLD_CONNECTION_TIMEOUT: u64 = 60; // every 60 seconds
const BLOCKED_IP_TIMEOUT: u64 = 60; // every 60 seconds
const THROTTLE_CLEAR_CYCLE: u64 = 3; // every 3 seconds
const STATS_TRACKING_CYCLE: u64 = 10; // every 10 seconds


fn shutdown(running: Arc<AtomicBool>, condvar: Arc<Condvar>) {
    if running.load(Ordering::SeqCst) {
        info!("Shutting down...");
        running.store(false, Ordering::SeqCst);
        condvar.notify_all();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <interface> or '--license'", args[0]);
        return;
    }
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            #[cfg(debug_assertions)]
            std::env::set_var("RUST_LOG", "debug");
            #[cfg(not(debug_assertions))]
            std::env::set_var("RUST_LOG", "info");
        }
    }
    if args[1] == "--license" {
        println!(include_str!("../LICENSE"));
        return;
    }
    Builder::from_env(Env::default())
        .format_timestamp_secs()
        .init();

    info!("Loading minecraft xdp filter v1.9 by Outfluencer...");

    let running = Arc::new(AtomicBool::new(true));
    let condvar = Arc::new(Condvar::new());

    start_shutdown_hook(running.clone(), condvar.clone());

    match load(args[1].as_str(), running.clone(), condvar.clone()) {
        Err(e) => {
            error!("Failed to load BPF program: {}", e);
        }
        _ => {}
    }

    shutdown(running, condvar);

    info!("Good bye!");
}

fn start_shutdown_hook(arc: Arc<AtomicBool>, condvar: Arc<Condvar>) {
    let mut signals = Signals::new(TERM_SIGNALS).expect("Couldn't register signals");
    thread::spawn(move || {
        for signal in signals.forever() {
            info!("Received termination signal: {signal}");
            shutdown(arc, condvar);
            break; // Stop on first termination signal
        }
    });
}

fn load(
    interface: &str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
) -> Result<(), anyhow::Error> {
    let data = include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/c/minecraft_filter.o"));
    info!("Loaded BPF proagram (size: {})", data.len());

    let mut ebpf = Ebpf::load(data)?;

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
        HashMap::<MapData, Ipv4FlowKey, u64>::try_from(map)?
    };
    let player_connection_map_ref: Arc<Mutex<HashMap<MapData, Ipv4FlowKey, u64>>> =
        Arc::new(Mutex::new(player_connection_map));

    let connection_throttle = {
        let map = ebpf
            .take_map("connection_throttle")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'connection_throttle'"))?;
        HashMap::<MapData, u32, u32>::try_from(map)?
    };
    let connection_throttle_ref: Arc<Mutex<HashMap<MapData, u32, u32>>> =
        Arc::new(Mutex::new(connection_throttle));

    let blocked_ips = {
        let map = ebpf
            .take_map("blocked_ips")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'blocked_ips'"))?;
        HashMap::<MapData, u32, u64>::try_from(map)?
    };
    let blocked_ips_ref: Arc<Mutex<HashMap<MapData, u32, u64>>> = Arc::new(Mutex::new(blocked_ips));
    let stats = {
        let map = ebpf
            .take_map("stats_map")
            .ok_or_else(|| anyhow::anyhow!("Can't take map 'stats_map'"))?;
        PerCpuArray::<MapData, Statistics>::try_from(map)?
    };

    let stats_ref: Arc<Mutex<PerCpuArray<MapData, Statistics>>> = Arc::new(Mutex::new(stats));

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
    )?;
    let handle3 = spawn_block_clear("clear-blocks", running.clone(), condvar.clone(), blocked_ips_ref)?;
    let handle4 = spawn_stats_thread("track-stats", running.clone(), condvar.clone(), stats_ref.clone())?;

    let _ = handle1
        .join()
        .map_err(|e| anyhow::anyhow!("clear-old thread panicked: {:?}", e))?;
    let _ = handle2
        .join()
        .map_err(|e| anyhow::anyhow!("clear-throttle thread panicked: {:?}", e))?;
    let _ = handle3
        .join()
        .map_err(|e| anyhow::anyhow!("clear-blocks thread panicked: {:?}", e))?;
    let _ = handle4
        .join()
        .map_err(|e| anyhow::anyhow!("track-stats thread panicked: {:?}", e))?;

    Ok(())
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
        let mut stats = stats_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;

        let values = stats.get(&0, 0)?;
        let mut total = Statistics::default();
        for cpu_stat in values.iter() {
            total.incoming_bytes += cpu_stat.incoming_bytes;
            total.dropped_bytes += cpu_stat.dropped_bytes;
            total.ip_blocks += cpu_stat.ip_blocks;
            total.verified += cpu_stat.verified;
            total.dropped_packets += cpu_stat.dropped_packets;
            total.state_switches += cpu_stat.state_switches;
            total.drop_connection += cpu_stat.drop_connection;
            total.syn += cpu_stat.syn;
            total.tcp_bypass += cpu_stat.tcp_bypass;
        }
        info!(
            "Stats: Incoming: {} bytes, Dropped: {} bytes, Packets Dropped: {}, Verified: {}, Syn: {}, Bypass: {}",
            total.incoming_bytes,
            total.dropped_bytes,
            total.dropped_packets,
            total.verified,
            total.syn,
            total.tcp_bypass
        );

        // Reset stats
        let zeros = vec![Statistics::default(); values.len()];
        let new_values = PerCpuValues::try_from(zeros)?;
        stats.set(0, new_values, 0)?;


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
    connection_throttle_ref: Arc<Mutex<HashMap<MapData, u32, u32>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) =
                connection_throttle_clear(running.clone(), condvar.clone(), connection_throttle_ref)
            {
                error!("Failed to clear connection throttles: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

fn connection_throttle_clear(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    connection_throttle_ref: Arc<Mutex<HashMap<MapData, u32, u32>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    while running.load(Ordering::SeqCst) {
        let mut map = connection_throttle_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;
        let all = map
            .iter()
            .filter_map(|res| {
                match res {
                    Ok((key, _)) => Some(key),
                    Err(_) => None, // skip errors
                }
            })
            .collect::<Vec<u32>>();
        all.iter().for_each(|key| {
            map.remove(key).ok();
        });
        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(THROTTLE_CLEAR_CYCLE))
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
    while running.load(Ordering::SeqCst) {
        let now = uptime_nanos()?;
        debug!("Checking for old connections... {:?}", now);
        let mut amount = 0;
        let mut map = player_connection_map_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;

        let to_remove = map
            .iter()
            .filter_map(|res| {
                amount += 1;
                match res {
                    Ok((key, last_update)) => {
                        if last_update + (OLD_CONNECTION_TIMEOUT * SECOND_TO_NANOS) < now {
                            Some(key)
                        } else {
                            None
                        }
                    }
                    Err(_) => None, // skip errors
                }
            })
            .collect::<Vec<Ipv4FlowKey>>();

        debug!("Map had {} entries now {} will be removed... {:?}", amount, to_remove.len(), now);


        to_remove.iter().for_each(|key| {
            let result = map.remove(key);
            if result.is_err() {
                error!(
                    "Failed to remove connection for key {}: {:?}",
                    common::flow_key_to_string(key),
                    result.err()
                );
            } else {
                debug!("Removed old connection: {}", common::flow_key_to_string(key));
            }
        });

        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(OLD_CONNECTION_TIMEOUT))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

fn spawn_block_clear(
    name: &'static str,
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    blocked_ips_ref: Arc<Mutex<HashMap<MapData, u32, u64>>>,
) -> Result<thread::JoinHandle<()>, anyhow::Error> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) = block_clear(running.clone(), condvar.clone(), blocked_ips_ref) {
                error!("Failed to clear blocked IPs: {:?}", e);
                shutdown(running, condvar);
            }
        })
        .map_err(|e| e.into())
}

fn block_clear(
    running: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    blocked_ips_ref: Arc<Mutex<HashMap<MapData, u32, u64>>>,
) -> Result<(), anyhow::Error> {
    let dummy_mutex = Mutex::new(());
    while running.load(Ordering::SeqCst) {
        let now = uptime_nanos()?;
        let mut map = blocked_ips_ref
            .lock()
            .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;
        let to_remove = map
            .iter()
            .filter_map(|res| {
                match res {
                    Ok((key, block_time)) => {
                        if block_time + (BLOCKED_IP_TIMEOUT * SECOND_TO_NANOS) < now {
                            Some(key)
                        } else {
                            None
                        }
                    }
                    Err(_) => None, // skip errors
                }
            })
            .collect::<Vec<u32>>();
        to_remove.iter().for_each(|key| {
            let result = map.remove(key);
            if result.is_err() {
                error!(
                    "Failed to remove blocked IP {}: {:?}",
                    common::network_address_to_string(*key),
                    result.err()
                );
            } else {
                info!("Unblocked IP: {}", common::network_address_to_string(*key));
            }
        });
        let guard = dummy_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Dummy Mutex poisoned: {}", e))?;
        let _ = condvar
            .wait_timeout(guard, Duration::from_secs(BLOCKED_IP_TIMEOUT))
            .map_err(|e| anyhow::anyhow!("condvar wait_timeout poisoned: {}", e))?;
    }
    Ok(())
}

fn uptime_nanos() -> Result<u64, anyhow::Error> {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let res = unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts) };
    if res == 0 {
        Ok((ts.tv_sec as u64) * SECOND_TO_NANOS + (ts.tv_nsec as u64))
    } else {
        Err(anyhow::anyhow!("Failed to get uptime"))
    }
}
