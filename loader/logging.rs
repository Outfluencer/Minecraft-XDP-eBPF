use anyhow::Result;
use colored::Colorize;
use fern::colors::{Color, ColoredLevelConfig};
use file_rotate::compression::Compression;
use file_rotate::suffix::AppendCount;
use file_rotate::{ContentLimit, FileRotate};
use log::LevelFilter;

use crate::config::LoggingConfig;

const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
const LOG_FILE: &str = "xdp-loader.log";
const LOG_FILES_KEPT: usize = 5;

/// The configured level, overridable at runtime via `RUST_LOG`.
fn level_filter(config: &LoggingConfig) -> LevelFilter {
    match std::env::var("RUST_LOG") {
        Ok(var) => match var.to_lowercase().as_str() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => config.level.into(),
        },
        Err(_) => config.level.into(),
    }
}

/// Initializes logging to stdout (colored) and to a rotating log file, with
/// level and rotation size taken from `[logging]` in the config.
pub fn init(config: &LoggingConfig) -> Result<()> {
    let colors = ColoredLevelConfig::new()
        .debug(Color::Magenta)
        .info(Color::Green)
        .warn(Color::Yellow)
        .error(Color::Red);

    let console = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} {}{}{} {}",
                chrono::Local::now()
                    .format(TIMESTAMP_FORMAT)
                    .to_string()
                    .white(),
                "[".bright_black(),
                colors.color(record.level()),
                "]".bright_black(),
                message
            ))
        })
        .chain(std::io::stdout());

    let file = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                chrono::Local::now().format(TIMESTAMP_FORMAT),
                record.level(),
                message
            ))
        })
        .chain(Box::new(FileRotate::new(
            LOG_FILE,
            AppendCount::new(LOG_FILES_KEPT),
            ContentLimit::Bytes(config.file_max_mb as usize * 1024 * 1024),
            Compression::None,
            #[cfg(unix)]
            None,
        )) as Box<dyn std::io::Write + Send>);

    fern::Dispatch::new()
        .level(level_filter(config))
        .chain(console)
        .chain(file)
        .apply()?;

    Ok(())
}
