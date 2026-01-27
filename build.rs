use std::env;
use std::process::Command;

/// Reads an environment variable or returns the default value
fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    // Configuration via environment variables at build time
    // Example: ONLY_ASCII_NAMES=1 START_PORT=25565 cargo build    
    let config = [
        ("ONLY_ASCII_NAMES", env_or("ONLY_ASCII_NAMES", "1")),
        ("CONNECTION_THROTTLE", env_or("CONNECTION_THROTTLE", "1")),
        ("START_PORT", env_or("START_PORT", "25565")),
        ("END_PORT", env_or("END_PORT", "25565")),
        ("PROMETHEUS_METRICS", env_or("PROMETHEUS_METRICS", "1")),
        ("IP_AND_PORT_PER_CPU", env_or("IP_AND_PORT_PER_CPU", "0")),
        ("IP_PER_CPU", env_or("IP_PER_CPU", "0")),
        ("HIT_COUNT", env_or("IP_PER_CPU", "10")),
    ];

    // Register custom cfg options to avoid warnings
    for (key, _) in &config {
        println!("cargo:rustc-check-cfg=cfg({})", key.to_lowercase());
    }

    // 1. Export variables for Rust (access via env! macro, e.g. env!("START_PORT"))
    for (key, value) in &config {
        println!("cargo:rustc-env={}={}", key, value);
        // Enable #[cfg(key)] if value is "1"
        if value == "1" {
            println!("cargo:rustc-cfg={}", key.to_lowercase());
        }
        // Rerun if this env var changes
        println!("cargo:rerun-if-env-changed={}", key);
    }

    // clang -Wall -Wextra -Wno-language-extension-token -O2 -g -target bpf -mcpu=v3 -c minecraft_filter.c -o minecraft_filter.o
    // 2. Compile the C code using clang directly
    let mut command = Command::new("clang");

    // Add config as -D define flags
    for (key, value) in &config {
        command.arg(format!("-D{}={}", key, value));
    }

    // Add compilation flags
    command.args([
        "-Wall",
        "-Wextra",
        "-Wno-language-extension-token",
        "-O2",
        "-g",
        "-target", "bpf",
        "-mcpu=v3",
        "-c", "minecraft_filter.c",
        "-o", "minecraft_filter.o",
    ]);

    // execute command in "c" directory
    command.current_dir("c");

    println!("cargo:warning=Compiling eBPF program...");
    match command.output() {
        Ok(output) => {
            if !output.status.success() {
                panic!(
                    "clang compilation failed:\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => panic!("Failed to execute clang: {}", e),
    }

    // 3. Re-run if relevant files change
    println!("cargo:rerun-if-changed=c/minecraft_filter.c");
    println!("cargo:rerun-if-changed=c/common.h");
    println!("cargo:rerun-if-changed=c/minecraft_networking.c");
    println!("cargo:rerun-if-changed=c/stats.h");
    println!("cargo:rerun-if-changed=build.rs");
}
