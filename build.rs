use std::process::Command;

fn main() {
    let mut command = Command::new("clang");

    command.args([
        "-Wall",
        "-Wextra",
        "-Wno-language-extension-token",
        "-O2",
        "-g",
        "-target", "bpf",
        "-mcpu=v3",
        "-c", "minecraft_filter.c",
        "-o", "minecraft_filter.o",
    ]);

    command.current_dir("c");
    println!("cargo:warning=Compiling eBPF program...");
    match command.output() {
        Ok(output) => {
            if !output.status.success() {
                panic!(
                    "clang compilation failed:\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => panic!("Failed to execute clang: {}", e),
    }
}
