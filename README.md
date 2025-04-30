Minecraft-XDP-eBPF
==========
This is the first free and public available Minecraft XDP Filter

Currently the filter is only available for ipv4.

# What does the filter do
The filter analyses Minecraft handshakes, status, ping and login requests. And drops invalid connections if detected.
If a connection is dropped, the ip will also be blacklisted for 60 seconds, so all new syn's will be dropped.

# Compilation requirements
`sudo apt update && sudo apt install -y clang xxd gcc-multilib libbpf-dev libxdp-dev`

⭐ Don't forget to star the project!
