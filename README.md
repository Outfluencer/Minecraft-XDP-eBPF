Minecraft-XDP-eBPF
==========
This is the first free and public available Minecraft Java Edition XDP filter written in pure c.

Currently the filter is only available for ipv4.

The default port for filtering is 25565.

# What does the filter do
The filter analyses Minecraft handshakes, status, ping and login requests, and drops invalid connections if detected.
If a connection is dropped, the ip will also be blacklisted for 60 seconds, so all new syn's will be dropped.

# How to install
Download the latest release from the release tab or compile the xdp_loader yourself. And run the `./xdp_loader`. You can also run it in a screen.
Note: if you exit the xdp loader, the xdp programm will be unloaded, as the loader is needed to manage connection state maps.

# Compilation requirements
`sudo apt update && sudo apt install -y clang xxd gcc-multilib libbpf-dev libxdp-dev`

# Compilation
```
git clone https://github.com/Outfluencer/Minecraft-XDP-eBPF.git
cd Minecraft-XDP-eBPF
chmod 777 build.sh
./build.sh
```

⭐ Don't forget to star the project!
