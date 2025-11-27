#!/bin/bash
chmod +x ./c/build.sh
./c/build.sh
cargo build --verbose --release