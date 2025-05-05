Minecraft-XDP-eBPF
==========
This is the first free and public available Minecraft Java Edition XDP filter written in pure c.

Currently the filter is only available for ipv4.

The default port for filtering is 25565.

Supported Minecraft Versions: 1.8.0 - 1.21.5

# What does the filter do
The filter analyses Minecraft handshakes, status, ping and login requests, and drops invalid connections.
If a connection is dropped, the ip will also be blacklisted for 60 seconds, so all new tcp packets will be dropped.

# Install (Debian / Ubuntu)
The following will install all dependecies (clang-16 xxd gcc-multilib libbpf-dev git) if not already installed and will then compile the xdp loader: 
```
curl -sSL https://outfluencer.dev/install-xdp.sh | bash
```
After that the xdp_loader file should be in the Minecraft-XDP-eBPF directory

You can also install the libs on your own und just run `./build.sh`
After this you can run the loader with `./xdp_loader <network interface>`
Note: if you exit the xdp loader, the xdp programm will be unloaded, as the loader is needed to manage connection state maps.

Test server with the filter: dev.outfluencer.dev

Thats how it looks like: https://youtu.be/Tq8QHJAMhRc

⭐ Don't forget to star the project!
