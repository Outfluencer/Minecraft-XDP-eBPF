Minecraft XDP Filter using eBPF – L7 DDoS Protection
==========
This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft Java Edition servers. It effectively mitigates L7 DDoS attacks by filtering malicious packets before they reach the server.

Currently the filter is only available for ipv4 and supports 1.8 - 1.21.5 and 1.7 motd.

The default port for filtering is 25565.

# What does the filter do
The filter analyses Minecraft handshakes, status, ping and login requests, and drops invalid connections.
If a connection is dropped, the ip will also be blacklisted for 60 seconds, so all new connections of that ip will be dropped.
The filter also has a intigrated connection throttle, with maximum of 10 syn's per 3 seconds

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

⭐ Don't forget to star the project!
