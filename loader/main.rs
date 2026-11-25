mod config;
mod ebpf;
mod logging;
mod metrics;
mod shutdown;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{error, info};

use config::Config;
use shutdown::Shutdown;

const USAGE: &str = "\
Usage: xdp-loader [OPTIONS] <INTERFACE>

Arguments:
  <INTERFACE>  Network interface to attach to (not needed with --check)

Options:
  -c, --config <FILE>  Path to the TOML configuration file, created with
                       defaults if missing [default: config.toml]
      --check          Load the filter with this configuration into the
                       kernel to see whether the verifier accepts it, then
                       exit without attaching anything
      --license        Print license information
  -h, --help           Print help
  -V, --version        Print version";

#[derive(Debug)]
struct Args {
    /// Network interface to attach to, required unless --license or --check
    /// is given.
    interface: Option<String>,
    /// Path to the TOML configuration file.
    config: String,
    /// Print license information instead of running.
    license: bool,
    /// Only check that the kernel accepts the program, attach nothing.
    check: bool,
}

/// Hand-rolled argument parsing (a CLI library would double the binary size
/// for three options). Prints help/version/errors and exits where appropriate.
fn parse_args() -> Args {
    let mut args = Args {
        interface: None,
        config: "config.toml".into(),
        license: false,
        check: false,
    };

    let mut argv = std::env::args().skip(1);
    let invalid = |message: String| -> ! {
        eprintln!("error: {message}\n\n{USAGE}");
        std::process::exit(2);
    };
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("xdp-loader {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--license" => args.license = true,
            "--check" => args.check = true,
            "-c" | "--config" => match argv.next() {
                Some(value) => args.config = value,
                None => invalid(format!("missing value for '{arg} <FILE>'")),
            },
            _ => match arg.strip_prefix("--config=") {
                Some(value) => args.config = value.into(),
                None if arg.starts_with('-') => invalid(format!("unexpected option '{arg}'")),
                None if args.interface.is_none() => args.interface = Some(arg),
                None => invalid(format!("unexpected argument '{arg}'")),
            },
        }
    }

    if args.interface.is_none() && !args.license && !args.check {
        invalid("missing required argument <INTERFACE>".into());
    }
    args
}

fn main() {
    let args = parse_args();

    if args.license {
        println!(include_str!("../LICENSE"));
        return;
    }

    // the log level lives in the config, so it must be loaded before logging
    // is up; until then errors can only go to stderr directly
    let config = match Config::load(Path::new(&args.config)) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("failed to load config '{}': {e:#}", args.config);
            std::process::exit(1);
        }
    };

    logging::init(&config.logging).expect("Failed to setup logger");
    info!(
        "Loading minecraft xdp filter v{} by Outfluencer...",
        env!("CARGO_PKG_VERSION")
    );
    info!("Loaded configuration: {config:?}");

    let shutdown = Arc::new(Shutdown::new());
    shutdown::trigger_on_termination_signal(shutdown.clone());

    let result = run(&args, &config, &shutdown);
    if let Err(e) = &result {
        error!("{e:#}");
    }

    shutdown.trigger();
    info!("Good bye!");

    // a failed run must be visible to service managers (systemd
    // Restart=on-failure) and scripts, not only in the log
    if result.is_err() {
        std::process::exit(1);
    }
}

/// Attaches the XDP filter and keeps it alive until shutdown is triggered.
/// Dropping the `Ebpf` handle on return detaches the filter again.
fn run(args: &Args, config: &Config, shutdown: &Arc<Shutdown>) -> Result<()> {
    if args.check {
        ebpf::check(config)?;
        info!("The kernel accepted the filter with this configuration");
        return Ok(());
    }

    let interface = args
        .interface
        .as_deref()
        .context("interface is required unless --license or --check is specified")?;

    // keep the handle alive until the end of this function: dropping it
    // detaches the XDP program
    let mut ebpf = ebpf::load_and_attach(interface, config)?;
    let stats_thread = metrics::start(&mut ebpf, config, shutdown)?;

    shutdown.wait();

    if let Some(handle) = stats_thread {
        handle
            .join()
            .map_err(|e| anyhow::anyhow!("track-stats thread panicked: {e:?}"))?;
    }
    Ok(())
}
