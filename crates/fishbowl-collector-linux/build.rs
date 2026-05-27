use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/execve.bpf.c";

fn main() {
    let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    out.push("execve.skel.rs");

    // Ubuntu/Debian put arch-specific kernel headers (asm/types.h, etc.) in a
    // multi-arch path that clang with `-target bpf` doesn't auto-search. Add
    // both common locations; clang will silently ignore the one that doesn't
    // apply on the build host.
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include/aarch64-linux-gnu",
        ])
        .build_and_generate(&out)
        .expect("BPF skeleton build failed");
    println!("cargo:rerun-if-changed={SRC}");
}
