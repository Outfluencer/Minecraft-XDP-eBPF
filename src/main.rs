mod config;
mod ebpf;
mod logging;
mod metrics;
mod shutdown;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info};

use config::Config;
use shutdown::Shutdown;

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

fn main() {
    let args = Args::parse();

    if args.license {
        println!(include_str!("../LICENSE"));
        return;
    }

    logging::init().expect("Failed to setup logger");
    info!("Loading minecraft xdp filter v3 by Outfluencer...");

    let shutdown = Arc::new(Shutdown::new());
    shutdown::trigger_on_termination_signal(shutdown.clone());

    if let Err(e) = run(&args, &shutdown) {
        error!("{e:#}");
    }

    shutdown.trigger();
    info!("Good bye!");
}

/// Loads the configuration, attaches the XDP filter and keeps it alive until
/// shutdown is triggered. Dropping the `Ebpf` handle on return detaches the
/// filter again.
fn run(args: &Args, shutdown: &Arc<Shutdown>) -> Result<()> {
    let interface = args
        .interface
        .as_deref()
        .context("interface is required unless --license is specified")?;

    let config = Config::load(Path::new(&args.config))
        .with_context(|| format!("failed to load config '{}'", args.config))?;
    info!("Loaded configuration: {config:?}");

    // keep the handle alive until the end of this function: dropping it
    // detaches the XDP program
    let mut ebpf = ebpf::load_and_attach(interface, &config)?;
    let stats_thread = metrics::start(&mut ebpf, &config, shutdown)?;

    shutdown.wait();

    if let Some(handle) = stats_thread {
        handle
            .join()
            .map_err(|e| anyhow::anyhow!("track-stats thread panicked: {e:?}"))?;
    }
    Ok(())
}
