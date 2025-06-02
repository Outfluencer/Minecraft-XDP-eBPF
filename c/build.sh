#!/bin/bash
set -e
cd "$(dirname "$0")"
clang -Wall -Wextra -Wno-language-extension-token -O3 -g -target bpf -mcpu=v3 -c "minecraft_filter.c" -o "minecraft_filter.o"
