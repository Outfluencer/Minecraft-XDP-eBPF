Minecraft XDP Filter using eBPF – L7 DDoS Protection
==========
This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft Java Edition servers.  
It effectively mitigates L7 DDoS attacks by filtering malicious packets before they reach the server.  
Currently the filter is only available for ipv4 and supports 1.8 - 1.21.8 and 1.7 motd.  
The default ports for filtering are 25000-26000.  

# What does the filter do
The filter analyzes Minecraft handshakes, status, ping, and login requests, and drops invalid connections.  
If a connection is dropped, the IP is blacklisted for 60 seconds — all new connections from that IP will be dropped.  
The filter also has an integrated connection throttle: max 10 SYNs per 3 seconds per ip address.  

# Install (Linux)
You can use the precompiled exceutable from the releases.  
Or you install the libs on your own and just run `./build.sh`  
After that the xdp_loader file should be in the `Minecraft-XDP-eBPF/target/release` directory  
Then you can run the loader with `./xdp_loader <network interface>`  
Note: This project uses a persistent XDP userspace loader to maintain connection state and manage eBPF maps. Exiting the loader will unload the firewall.  

⭐ Don't forget to star the project!

https://youtu.be/Tq8QHJAMhRc

# Configuration
The default protected ports are 25000 to 26000, if you want to change that,  
fully remove the arguments from the `/c/build.sh` file or change them to the port range you need.  
Then recompile the project. The xdp filter will now filter on the specified port range or on 25565 if nothing is specified.  

# More
BungeeCord plugin that utilizes this filter to block ips that are causing exceptions
https://github.com/Outfluencer/Minecraft-XDP-eBPF-Server-Addon/
