use std::path::Path;
use std::process::Command;

/// Compiles `xdp/tests/protocol_test.c` natively and runs it.
///
/// This exercises the exact parsing code the eBPF program is built from
/// (varint reader, packet inspectors, bounds-check macros) in userspace,
/// where it can be sanitized. clang is already required to build the
/// project at all, so this adds no new dependency.
#[test]
fn c_parser_unit_tests() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join("protocol_test");
    let binary = binary.to_str().expect("tmpdir path is valid utf-8");

    // ASan catches reads past the exact-size test buffers; the alignment
    // check is disabled because the parser does unaligned reads on purpose
    // (network data), like the kernel does.
    let sanitizer_flags = [
        "-fsanitize=address,undefined",
        "-fno-sanitize=alignment",
        "-fno-sanitize-recover=all",
    ];
    let base_flags = [
        "-Wall",
        "-Wextra",
        "-O2",
        "-g",
        "-fno-strict-aliasing",
        "xdp/tests/protocol_test.c",
        "-o",
        binary,
    ];

    let compile = |with_sanitizers: bool| {
        let mut cmd = Command::new("clang");
        cmd.current_dir(manifest_dir);
        if with_sanitizers {
            cmd.args(sanitizer_flags);
        }
        cmd.args(base_flags);
        cmd.output().expect("failed to run clang")
    };

    // fall back to a plain build where the sanitizer runtime is unavailable
    let mut output = compile(true);
    if !output.status.success() {
        println!("note: sanitizer build failed, retrying without sanitizers");
        output = compile(false);
    }
    assert!(
        output.status.success(),
        "clang failed to compile the C unit tests:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let run = Command::new(binary)
        .output()
        .expect("failed to run the C unit test binary");
    println!("{}", String::from_utf8_lossy(&run.stdout));
    eprintln!("{}", String::from_utf8_lossy(&run.stderr));
    assert!(run.status.success(), "C unit tests reported failures");
}
