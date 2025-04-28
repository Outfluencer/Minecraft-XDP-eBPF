# Minecraft XDP BPF Filter

This is the first free and public available Minecraft XDP Filter

# Why

Minecraft servers are frequent targets of distributed denial-of-service (DDoS) attacks,
ranging from high-volume packet floods to application-layer attacks targeting handshake and login mechanisms.
Traditional mitigation approaches, such as iptables or userspace firewalls,
often introduce significant latency and consume excessive CPU resources, degrading server performance.

XDP (eXpress Data Path) combined with eBPF (extended Berkeley Packet Filter) offers a highly effective,
low-latency solution for DDoS protection at the kernel level, mitigating attacks before they can impact
application performance. 
