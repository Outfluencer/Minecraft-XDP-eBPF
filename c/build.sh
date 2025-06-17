#!/bin/bash
set -e
cd "$(dirname "$0")"
clang -DSTART_PORT=25000 -DEND_PORT=26000 -Wall -Wextra -Wno-language-extension-token -O3 -g -target bpf -mcpu=v3 -c "minecraft_filter.c" -o "minecraft_filter.o"
