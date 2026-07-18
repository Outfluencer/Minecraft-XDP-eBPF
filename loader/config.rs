use anyhow::{Context, Result, bail};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Default configuration file written on first run, with documentation for
/// every option. Mirrors [`Config::default`].
pub const DEFAULT_CONFIG_TOML: &str = r#"# Minecraft XDP filter configuration.
# This file is applied at load time; restart the loader after editing.
# Every option is listed with its default value.

[filter]
# Inclusive TCP destination port range to protect.
# Use the same value for both to protect a single port.
start_port = 25565
end_port = 25565

# SYN connection throttle: max new connections (SYNs) per source IP within
# each throttle window (see hit_count_reset_secs). Set to 0 to disable
# throttling.
hit_count = 10

# Length of the throttle window in seconds, enforced inside the eBPF program:
# each source IP gets its own window starting at its first SYN, and the counter
# resets in-kernel once the window expires. e.g. hit_count = 10 with
# hit_count_reset_secs = 3 allows 10 new connections per source IP every
# 3 seconds. Must be between 1 and 86400 (one day).
hit_count_reset_secs = 3

# Idle timeout for verified player connections in seconds, enforced inside the
# eBPF program: a connection's entry is removed after one to two timeout
# intervals without packets, so a returning client has to redo the handshake.
# Must be between 1 and 86400 (one day).
player_idle_timeout_secs = 60

# Enforce online-mode username rules during login inspection.
# true  -> usernames are limited to 16 characters (Mojang online mode).
# false -> allow the protocol maximum (offline / cracked servers).
online_names = true

[xdp]
# How the filter attaches to the network interface.
# "auto"   -> native driver mode if the NIC supports XDP, with automatic
#             fallback to generic mode otherwise. Recommended.
# "driver" -> force native driver mode: fastest, but fails on NICs without
#             XDP support (including most virtual machines).
# "skb"    -> force generic (skb) mode: works on any interface but is
#             slower; use it when the driver misbehaves in native mode.
mode = "auto"

# Sizes of the in-kernel connection tables below. The maps are preallocated,
# so higher limits cost kernel memory up front, not per connection.

# Connections that have not finished the Minecraft handshake yet. The
# least-recently-used entry is evicted when the table is full, bounding how
# many half-open connections an attacker can keep alive at once.
max_pending_connections = 16384

# Verified player connections. New connections cannot be verified while this
# table is full, so keep it well above the expected player count.
max_player_connections = 65535

# Source IPs tracked by the SYN throttle. When the table is full, new SYNs
# are dropped (fail closed) until expired windows are reclaimed in-kernel.
max_throttled_ips = 65535

[metrics]
# Collect packet statistics inside the eBPF program. Required for any metrics
# output. Adds a small per-packet cost, so it is disabled by default.
enabled = false

# Address to expose Prometheus metrics on (only used when enabled = true).
# Leave commented out to collect stats without starting the HTTP server.
# The endpoint has no authentication, so only bind to a public address
# (e.g. "0.0.0.0:1999") if you really want it reachable from outside.
# addr = "127.0.0.1:1999"

# How often the in-kernel statistics are read and published, in seconds.
poll_secs = 10

[logging]
# Verbosity of console and file logging:
# "off", "error", "warn", "info", "debug" or "trace".
# The RUST_LOG environment variable overrides this setting at runtime.
level = "info"

# The log file (xdp-loader.log) is rotated once it grows past this many
# megabytes; the 5 most recent rotated files are kept.
file_max_mb = 100
"#;

/// Runtime configuration for the XDP filter, grouped like the TOML file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub filter: FilterConfig,
    pub xdp: XdpConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
}

/// `[filter]` — which traffic is filtered and how strictly.
///
/// These fields are pushed into the eBPF program's `volatile const` globals at
/// load time; see `load_and_attach` in `loader/ebpf.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterConfig {
    /// First port of the inclusive filtered range. Maps to `START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive filtered range. Maps to `END_PORT`.
    pub end_port: u16,
    /// Max SYNs per source IP per throttle window (0 = disabled). Maps to `HIT_COUNT`.
    pub hit_count: u32,
    /// Throttle window length in seconds; each IP's SYN counter resets in-kernel
    /// once its window expires. Maps to `HIT_COUNT_RESET_NS` (converted to ns).
    pub hit_count_reset_secs: u64,
    /// Idle timeout for verified connections in seconds; an entry is removed
    /// in-kernel after one to two intervals without packets. Maps to
    /// `PLAYER_IDLE_NS` (converted to ns).
    pub player_idle_timeout_secs: u64,
    /// Enforce online-mode (<= 16 char) usernames. Maps to `ONLINE_NAMES`.
    pub online_names: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            start_port: 25565,
            end_port: 25565,
            hit_count: 10,
            hit_count_reset_secs: 3,
            player_idle_timeout_secs: 60,
            online_names: true,
        }
    }
}

/// `[xdp]` — how the program attaches and the capacity of its maps.
///
/// The capacities override the placeholder `max_entries` of the corresponding
/// map in `xdp/minecraft_filter.c` at load time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XdpConfig {
    /// XDP attach mode.
    pub mode: ConfigXdpMode,
    /// Capacity of `conntrack_map`: concurrent unverified (mid-handshake)
    /// connections, oldest evicted when full.
    pub max_pending_connections: u32,
    /// Capacity of `player_connection_map`: concurrent verified connections.
    pub max_player_connections: u32,
    /// Capacity of `connection_throttle`: source IPs with an active throttle
    /// window.
    pub max_throttled_ips: u32,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            mode: ConfigXdpMode::Auto,
            max_pending_connections: 16384,
            max_player_connections: 65535,
            max_throttled_ips: 65535,
        }
    }
}

/// XDP attach mode, the `mode` option in `[xdp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigXdpMode {
    /// Native driver mode when the NIC supports it, automatic fallback to
    /// generic mode otherwise.
    Auto,
    /// Force native driver mode, fail when unsupported.
    Driver,
    /// Force generic (skb) mode.
    Skb,
}

impl fmt::Display for ConfigXdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConfigXdpMode::Auto => "auto",
            ConfigXdpMode::Driver => "driver",
            ConfigXdpMode::Skb => "skb",
        })
    }
}

/// `[metrics]` — statistics collection and the Prometheus endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Collect statistics inside the eBPF program. Maps to `PROMETHEUS`.
    pub enabled: bool,
    /// Optional address for the Prometheus HTTP endpoint (e.g. `127.0.0.1:1999`).
    pub addr: Option<String>,
    /// Seconds between reads of the in-kernel statistics map.
    pub poll_secs: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: None,
            poll_secs: 10,
        }
    }
}

/// `[logging]` — console/file log verbosity and rotation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log verbosity, overridable at runtime via the `RUST_LOG` env variable.
    pub level: LogLevel,
    /// Rotate the log file once it grows past this size in megabytes.
    pub file_max_mb: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file_max_mb: 100,
        }
    }
}

/// Log verbosity, the `level` option in `[logging]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

impl Config {
    /// Load the configuration from `path`, creating a documented default file if
    /// it does not exist yet.
    ///
    /// Runs before logging is initialized (the log level lives in here), so the
    /// "wrote defaults" notice goes to stderr directly.
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            eprintln!(
                "Config file '{}' not found, writing documented defaults",
                path.display()
            );
            std::fs::write(path, DEFAULT_CONFIG_TOML).with_context(|| {
                format!("failed to write default config to '{}'", path.display())
            })?;
        }

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file '{}'", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Reject values the eBPF program or loader cannot represent sensibly.
    fn validate(&self) -> Result<()> {
        self.filter.validate()?;
        self.xdp.validate()?;
        self.metrics.validate()?;
        self.logging.validate()
    }
}

/// Bail with a uniform message unless `min <= value <= max`.
fn check_range(option: &str, value: u64, min: u64, max: u64) -> Result<()> {
    if value < min || value > max {
        bail!("{option} must be between {min} and {max} (got {value})");
    }
    Ok(())
}

impl FilterConfig {
    fn validate(&self) -> Result<()> {
        if self.start_port == 0 {
            bail!("[filter] start_port must be >= 1");
        }
        if self.start_port > self.end_port {
            bail!(
                "[filter] start_port ({}) must be <= end_port ({})",
                self.start_port,
                self.end_port
            );
        }
        check_range(
            "[filter] hit_count_reset_secs",
            self.hit_count_reset_secs,
            1,
            86_400,
        )?;
        check_range(
            "[filter] player_idle_timeout_secs",
            self.player_idle_timeout_secs,
            1,
            86_400,
        )
    }
}

impl XdpConfig {
    fn validate(&self) -> Result<()> {
        const MAX_ENTRIES: u64 = 1 << 20;
        check_range(
            "[xdp] max_pending_connections",
            self.max_pending_connections as u64,
            1,
            MAX_ENTRIES,
        )?;
        check_range(
            "[xdp] max_player_connections",
            self.max_player_connections as u64,
            1,
            MAX_ENTRIES,
        )?;
        check_range(
            "[xdp] max_throttled_ips",
            self.max_throttled_ips as u64,
            1,
            MAX_ENTRIES,
        )
    }
}

impl MetricsConfig {
    fn validate(&self) -> Result<()> {
        check_range("[metrics] poll_secs", self.poll_secs, 1, 3_600)
    }
}

impl LoggingConfig {
    fn validate(&self) -> Result<()> {
        check_range("[logging] file_max_mb", self.file_max_mb, 1, 10_240)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_matches_struct_default() {
        // The documented template shipped to users must parse and agree with
        // Config::default (metrics addr is commented out -> None).
        let parsed: Config = toml::from_str(DEFAULT_CONFIG_TOML).expect("default toml parses");
        assert_eq!(parsed, Config::default());
        parsed.validate().expect("default config is valid");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("nonsense_key = 1").unwrap_err();
        assert!(err.to_string().contains("nonsense_key"));
        // also inside a section
        assert!(toml::from_str::<Config>("[filter]\nnonsense_key = 1").is_err());
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let cfg: Config =
            toml::from_str("[filter]\nhit_count = 0\n\n[metrics]\nenabled = true").unwrap();
        assert_eq!(cfg.filter.hit_count, 0); // throttle disabled
        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.filter.start_port, 25565); // default preserved
        assert_eq!(cfg.xdp.mode, ConfigXdpMode::Auto); // untouched section defaulted
    }

    #[test]
    fn rejects_inverted_port_range() {
        let cfg: Config = toml::from_str("[filter]\nstart_port = 30000\nend_port = 25565").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_start_port() {
        let cfg: Config = toml::from_str("[filter]\nstart_port = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_reset_window() {
        let cfg: Config = toml::from_str("[filter]\nhit_count_reset_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_reset_window() {
        let cfg: Config = toml::from_str("[filter]\nhit_count_reset_secs = 86401").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_idle_timeout() {
        let cfg: Config = toml::from_str("[filter]\nplayer_idle_timeout_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_idle_timeout() {
        let cfg: Config = toml::from_str("[filter]\nplayer_idle_timeout_secs = 86401").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_xdp_mode() {
        let err = toml::from_str::<Config>("[xdp]\nmode = \"hardware\"").unwrap_err();
        assert!(err.to_string().contains("hardware"));
    }

    #[test]
    fn rejects_zero_map_capacity() {
        for option in [
            "max_pending_connections",
            "max_player_connections",
            "max_throttled_ips",
        ] {
            let cfg: Config = toml::from_str(&format!("[xdp]\n{option} = 0")).unwrap();
            assert!(cfg.validate().is_err(), "{option} = 0 must be rejected");
        }
    }

    #[test]
    fn rejects_zero_poll_interval() {
        let cfg: Config = toml::from_str("[metrics]\npoll_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_log_level() {
        let err = toml::from_str::<Config>("[logging]\nlevel = \"verbose\"").unwrap_err();
        assert!(err.to_string().contains("verbose"));
    }
}
