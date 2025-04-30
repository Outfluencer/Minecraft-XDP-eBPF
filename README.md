Minecraft-XDP-eBPF
==========
This is the first free and public available Minecraft XDP Filter
Currently the filter is only available for ipv4.

# What does the filter do
The filter analyses Minecraft handshakes, status, ping and login requests. And drops invalid connections if detected.
If a connection is dropped, the ip will also be blacklisted for 60 seconds, so all new syn's will be dropped.

# Pull Request
Any kind of pull request that improves the filter is very welcome.

# ⭐ Don't forget to star the project! ⭐

# Compilation requirements
sudo apt update
sudo apt install clang -y
sudo apt install xxd -y
sudo apt install gcc-multilib -y
sudo apt install libbpf-dev -y
sudo apt install libxdp-dev -y
