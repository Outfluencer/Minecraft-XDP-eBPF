use anyhow::Result;
use colored::Colorize;
use fern::colors::{Color, ColoredLevelConfig};
use file_rotate::compression::Compression;
use file_rotate::suffix::AppendCount;
use file_rotate::{ContentLimit, FileRotate};
use log::LevelFilter;

const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
const LOG_FILE: &str = "xdp-loader.log";
const LOG_FILE_BYTES: usize = 100 * 1024 * 1024; // rotate after 100 MB
const LOG_FILES_KEPT: usize = 5;

/// Log level used when `RUST_LOG` is not set.
const DEFAULT_LEVEL: LevelFilter = if cfg!(debug_assertions) {
    LevelFilter::Debug
} else {
    LevelFilter::Info
};

fn level_filter() -> LevelFilter {
    match std::env::var("RUST_LOG") {
        Ok(var) => match var.to_lowercase().as_str() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        },
        Err(_) => DEFAULT_LEVEL,
    }
}

/// Initializes logging to stdout (colored) and to a rotating log file.
pub fn init() -> Result<()> {
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
            ContentLimit::Bytes(LOG_FILE_BYTES),
            Compression::None,
            #[cfg(unix)]
            None,
        )) as Box<dyn std::io::Write + Send>);

    fern::Dispatch::new()
        .level(level_filter())
        .chain(console)
        .chain(file)
        .apply()?;

    Ok(())
}
