#!/bin/bash
set -e
cd "$(dirname "$0")"
chmod +x ./c/build.sh
./c/build.sh
cargo build --verbose --release
