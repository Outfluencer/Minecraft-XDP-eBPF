use std::process::Command;

/// Compiles the eBPF program to `xdp/minecraft_filter.o`, which `loader/ebpf.rs`
/// embeds into the loader binary at compile time.
fn main() {
    // explicit file list on purpose: watching the whole xdp/ directory would
    // also watch the generated .o and recompile on every build
    for source in [
        "xdp/minecraft_filter.c",
        "xdp/common.h",
        "xdp/config.h",
        "xdp/protocol.h",
        "xdp/stats.h",
        "xdp/varint.h",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }

    let output = Command::new("clang")
        .args([
            "-Wall",
            "-Wextra",
            "-Wno-language-extension-token",
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-mcpu=v3",
            "-c",
            "minecraft_filter.c",
            "-o",
            "minecraft_filter.o",
        ])
        .current_dir("xdp")
        .output()
        .expect("failed to run clang, is LLVM/clang installed?");

    if !output.status.success() {
        panic!(
            "clang compilation failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
