use std::process::Command;

/// Compiles the eBPF program to `c/minecraft_filter.o`, which `src/ebpf.rs`
/// embeds into the loader binary at compile time.
fn main() {
    // explicit file list on purpose: watching the whole c/ directory would
    // also watch the generated .o and recompile on every build
    for source in [
        "c/minecraft_filter.c",
        "c/common.h",
        "c/config.h",
        "c/protocol.h",
        "c/stats.h",
        "c/varint.h",
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
        .current_dir("c")
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
