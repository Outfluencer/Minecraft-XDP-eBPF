use anyhow::{Context, Result, bail};
use log::info;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Default configuration file written on first run, with documentation for
/// every option. Mirrors [`Config::default`].
pub const DEFAULT_CONFIG_TOML: &str = r#"# Minecraft XDP filter configuration.
# This file is applied to the eBPF program at load time (via .rodata globals).
# Restart the loader after editing.

# Inclusive TCP destination port range to filter.
# Use the same value for both to filter a single port.
start_port = 25565
end_port = 25565

# SYN connection throttle: max new connections (SYNs) per source IP within each
# throttle window (see hit_count_reset_secs). Set to 0 to disable throttling.
hit_count = 10

# Length of the throttle window in seconds, enforced inside the eBPF program:
# each source IP gets its own window starting at its first SYN, and the counter
# resets in-kernel once the window expires. e.g. hit_count = 10 with
# hit_count_reset_secs = 3 allows 10 new connections per source IP every
# 3 seconds. Must be between 1 and 86400 (one day).
hit_count_reset_secs = 3

# Enforce online-mode username rules during login inspection.
# true  -> usernames are limited to 16 characters (Mojang online mode).
# false -> allow the protocol maximum (offline / cracked servers).
online_names = true

# Collect packet statistics inside the eBPF program. Required for any metrics
# output. Adds a small per-packet cost, so it is disabled by default.
prometheus = false

# Address to expose Prometheus metrics on (only used when prometheus = true).
# Leave commented out to collect stats without starting the HTTP server.
# metrics_addr = "0.0.0.0:1999"
"#;

/// Runtime configuration for the XDP filter.
///
/// The numeric/boolean fields are pushed into the eBPF program's `volatile const`
/// globals at load time; see `load_and_attach` in `src/ebpf.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// First port of the inclusive filtered range. Maps to `START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive filtered range. Maps to `END_PORT`.
    pub end_port: u16,
    /// Max SYNs per source IP per throttle window (0 = disabled). Maps to `HIT_COUNT`.
    pub hit_count: u32,
    /// Throttle window length in seconds; each IP's SYN counter resets in-kernel
    /// once its window expires. Maps to `HIT_COUNT_RESET_NS` (converted to ns).
    pub hit_count_reset_secs: u64,
    /// Enforce online-mode (<= 16 char) usernames. Maps to `ONLINE_NAMES`.
    pub online_names: bool,
    /// Collect statistics inside the eBPF program. Maps to `PROMETHEUS`.
    pub prometheus: bool,
    /// Optional address for the Prometheus HTTP endpoint (e.g. `0.0.0.0:1999`).
    pub metrics_addr: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            start_port: 25565,
            end_port: 25565,
            hit_count: 10,
            hit_count_reset_secs: 3,
            online_names: true,
            prometheus: false,
            metrics_addr: None,
        }
    }
}

impl Config {
    /// Load the configuration from `path`, creating a documented default file if
    /// it does not exist yet.
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            info!(
                "Config file '{}' not found, writing defaults",
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

    /// Reject combinations that the eBPF program cannot represent sensibly.
    fn validate(&self) -> Result<()> {
        if self.start_port == 0 {
            bail!("start_port must be >= 1");
        }
        if self.start_port > self.end_port {
            bail!(
                "start_port ({}) must be <= end_port ({})",
                self.start_port,
                self.end_port
            );
        }
        if self.hit_count_reset_secs == 0 {
            bail!("hit_count_reset_secs must be >= 1");
        }
        if self.hit_count_reset_secs > 86_400 {
            bail!("hit_count_reset_secs must be <= 86400 (one day)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_matches_struct_default() {
        // The documented template shipped to users must parse and agree with
        // Config::default (metrics_addr is commented out -> None).
        let parsed: Config = toml::from_str(DEFAULT_CONFIG_TOML).expect("default toml parses");
        let default = Config::default();
        assert_eq!(parsed.start_port, default.start_port);
        assert_eq!(parsed.end_port, default.end_port);
        assert_eq!(parsed.hit_count, default.hit_count);
        assert_eq!(parsed.hit_count_reset_secs, default.hit_count_reset_secs);
        assert_eq!(parsed.online_names, default.online_names);
        assert_eq!(parsed.prometheus, default.prometheus);
        assert_eq!(parsed.metrics_addr, None);
        parsed.validate().expect("default config is valid");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("nonsense_key = 1").unwrap_err();
        assert!(err.to_string().contains("nonsense_key"));
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let cfg: Config = toml::from_str("hit_count = 0\nprometheus = true").unwrap();
        assert_eq!(cfg.hit_count, 0); // throttle disabled
        assert!(cfg.prometheus);
        assert_eq!(cfg.start_port, 25565); // default preserved
    }

    #[test]
    fn rejects_inverted_port_range() {
        let cfg: Config = toml::from_str("start_port = 30000\nend_port = 25565").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_start_port() {
        let cfg: Config = toml::from_str("start_port = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_reset_window() {
        let cfg: Config = toml::from_str("hit_count_reset_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_reset_window() {
        let cfg: Config = toml::from_str("hit_count_reset_secs = 86401").unwrap();
        assert!(cfg.validate().is_err());
    }
}
