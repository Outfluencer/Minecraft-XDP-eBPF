Minecraft XDP Filter using eBPF – L7 DDoS Protection
==========
This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft Java Edition servers.  
It effectively mitigates L7 DDoS attacks by filtering malicious packets before they reach the server.  
Currently the filter is only available for ipv4 and supports 1.8 - 1.21.5 and 1.7 motd.  
The default port for filtering is 25565.  

# What does the filter do
The filter analyzes Minecraft handshakes, status, ping, and login requests, and drops invalid connections.  
If a connection is dropped, the IP is blacklisted for 60 seconds — all new connections from that IP will be dropped.  
The filter also has an integrated connection throttle: max 10 SYNs per 3 seconds.  

# Install (Linux)
You can use the precompiled exceutable from the releases.  
Or you install the libs on your own and just run `./build.sh`  
After that the xdp_loader file should be in the `Minecraft-XDP-eBPF/target/release` directory  
Then you can run the loader with `./xdp_loader <network interface>`  
Note: This project uses a persistent XDP userspace loader to maintain connection state and manage eBPF maps. Exiting the loader will unload the firewall.  

Test server with the filter: dev.outfluencer.dev  

⭐ Don't forget to star the project!

https://youtu.be/Tq8QHJAMhRc
