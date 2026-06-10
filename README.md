# Minecraft XDP Filter using eBPF – L7 DDoS Protection

This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft Java Edition servers.  
It effectively mitigates L7 DDoS attacks by filtering malicious packets at the kernel level (before they reach the network stack).  
Currently, the filter is available for IPv4 and supports Minecraft versions 1.8 - 26.2    
The default filtered port is 25565.

## Features
- **Protocol Analysis**: Analyzes Minecraft handshakes, status, ping, and login requests.
- **Deep Packet Inspection**: Drops invalid packets, bad VarInts, and protocol violations.
- **Connection Throttle**: Integrated SYN rate limiting (default: 10 SYNs per 3 seconds per IP).
- **Zero-Copy Dropping**: Malicious traffic is dropped at the driver level (XDP_DROP) for maximum performance.

## Installation (Linux)

### Generate your filter binary

Generate here: https://xdp.outfluencer.dev/   
And then just run the executable.   

### Prerequisites
- Rust toolchain (stable)
- **System Dependencies**:
  ```bash
  sudo apt update
  sudo apt install -y gcc-multilib wget gnupg software-properties-common git libbpf-dev
  ```
  If software-properties-common was not found remove it from the command.
- **LLVM/Clang Toolchain**:
  The build requires a recent LLVM version (CI uses LLVM 21).
  ```bash
  wget https://apt.llvm.org/llvm.sh
  chmod +x llvm.sh
  sudo ./llvm.sh 21 all
  ```

### Build & Run
1.  **Build the project**:
    ```bash
    ./build.sh
    ```
    The compiled binary will be at `target/release/xdp-loader`.

2.  **Run the firewall**:
    ```bash
    sudo ./target/release/xdp-loader <network_interface>
    # Example:
    sudo ./target/release/xdp-loader eth0
    ```

    To enable Prometheus metrics export, set `prometheus = true` and a
    `metrics_addr` in `config.toml` (see [Configuration](#configuration)), then
    run the loader normally. Metrics are then available at: `http://host:1999/metrics`

**Note:** This project uses a persistent XDP loader. The userspace program must stay running to keep the filter attached; all map state (throttle windows, verified connections) is managed in-kernel via `bpf_timer`. Stopping the loader will unload the firewall. Requires Linux kernel 5.15 or newer.

## Configuration

Runtime behavior is controlled by a `config.toml` file next to the binary.
On first run it is created automatically with documented defaults; edit it and
restart the loader. Use `--config <path>` to point at a different file.

| Option         | Type   | Default | Description |
|----------------|--------|---------|-------------|
| `start_port`   | int    | 25565   | First port of the inclusive filtered range. |
| `end_port`     | int    | 25565   | Last port of the inclusive filtered range. |
| `hit_count`    | int    | 10      | Max SYNs per source IP per throttle window (`0` disables throttling). |
| `hit_count_reset_secs` | int | 3   | Throttle window length in seconds; each IP's SYN counter resets in-kernel once its window expires. |
| `online_names` | bool   | true    | Enforce online-mode usernames (≤16 chars). |
| `prometheus`   | bool   | false   | Collect packet statistics inside the eBPF program. |
| `metrics_addr` | string | (unset) | Address for the Prometheus HTTP endpoint (requires `prometheus = true`). |

These values are pushed into the eBPF program at load time (via `.rodata`
globals), so changing them only requires a restart — **not a rebuild**.

## Project Layout

| Path | Purpose |
|------|---------|
| `c/minecraft_filter.c` | XDP entry point, BPF maps, conntrack state machine |
| `c/protocol.h` | Minecraft packet inspection (handshake, status, ping, login) |
| `c/varint.h` | Bounded VarInt reader |
| `c/common.h` | Bounds-check macros, flow key, connection states |
| `c/config.h` | Runtime configuration globals (patched by the loader) |
| `c/stats.h` | Statistics counters |
| `src/main.rs` | CLI entry point and process lifecycle |
| `src/ebpf.rs` | Loads, configures and attaches the eBPF program |
| `src/config.rs` | TOML configuration |
| `src/metrics.rs` | Statistics polling and Prometheus endpoint |
| `src/logging.rs` | Console + rotating file logging |
| `src/shutdown.rs` | Signal handling and shutdown coordination |

The eBPF program is compiled by `build.rs` and embedded into the loader
binary, so the released executable is fully self-contained.

## Troubleshooting

### Non-root / Permission Errors
Please always check if you are running as root if any error occurred. If you are not, try again with `sudo`.  

### Maps Issue
If you change map configurations (e.g., enabling Per-CPU maps), you might get map creation errors on restart.
Clear the generic BPF filesystem:
```bash
sudo rm -r /sys/fs/bpf
```
⭐ **Don't forget to star the project on GitHub!**  
