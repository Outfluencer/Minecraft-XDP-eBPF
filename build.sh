rm -f "minecraft_filter.o"
rm -f "embedded_data.h"

clang -Wall -O3 -g -target bpf -mcpu=v3 -c "minecraft_filter.c" -o "minecraft_filter.o"
xxd -i "minecraft_filter.o" > "embedded_data.h"
clang -Wall -O3 "xdp_loader.c" "license_include.S" -o xdp_loader -ldl
