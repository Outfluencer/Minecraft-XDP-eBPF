# Minecraft XDP Filter using eBPF – L7 DDoS Protection

This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft Java Edition servers.  
It effectively mitigates L7 DDoS attacks by filtering malicious packets at the kernel level (before they reach the network stack).  
Currently, the filter is available for IPv4 and supports Minecraft versions 1.8 - 1.21.x.  
The default filtered port is 25565.

## Features
- **Protocol Analysis**: Analyzes Minecraft handshakes, status, ping, and login requests.
- **Deep Packet Inspection**: Drops invalid packets, bad VarInts, and protocol violations.
- **Connection Throttle**: Integrated SYN rate limiting (default: 10 SYNs per 3 seconds per IP).
- **Zero-Copy Dropping**: Malicious traffic is dropped at the driver level (XDP_DROP) for maximum performance.

## Installation (Linux)

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

    To enable Prometheus metrics export:
    ```bash
    sudo ./target/release/xdp-loader eth0 --metrics-addr 0.0.0.0:1999
    ```
    Metrics available at: `http://host:1999/metrics`

**Note:** This project uses a persistent XDP loader. Usage of `XDP` programs requires the userspace program to stay running to manage maps. Stopping the loader will unload the firewall.

## Configuration

You can configure ports, features, and throttling behavior in the `build.rs` file.

**After changing `build.rs`, you must recompile the project.**

## Troubleshooting

### None root
Please always check if you are root if any error occourd, if you are not try again with sudo.  

### Maps Issue
If you change map configurations (e.g., enabling Per-CPU maps), you might get map creation errors on restart.
Clear the generic BPF filesystem:
```bash
sudo rm -r /sys/fs/bpf
```

## Related Projects
- **BungeeCord Filter Addon**: Plugin to sync bans between this XDP filter and BungeeCord.
  [https://github.com/Outfluencer/Minecraft-XDP-eBPF-Server-Addon/](https://github.com/Outfluencer/Minecraft-XDP-eBPF-Server-Addon/)

---
⭐ **Don't forget to star the project on GitHub!**  
[Watch Setup Tutorial](https://youtu.be/Tq8QHJAMhRc)
