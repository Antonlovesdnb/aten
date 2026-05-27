// On non-Linux hosts the BPF source isn't built. The crate compiles as an
// empty library so the workspace builds cleanly on Windows. The actual
// libbpf-cargo invocation lives behind a target_os=linux cfg.

#[cfg(target_os = "linux")]
mod linux_build {
    use libbpf_cargo::SkeletonBuilder;
    use std::env;
    use std::path::PathBuf;

    const SOURCES: &[(&str, &str)] = &[
        ("src/bpf/execve.bpf.c", "execve.skel.rs"),
        ("src/bpf/credacc.bpf.c", "credacc.skel.rs"),
        ("src/bpf/connect.bpf.c", "connect.skel.rs"),
    ];

    pub fn run() {
        let out_root = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
        // Ubuntu/Debian put arch-specific kernel headers (asm/types.h, etc.)
        // in a multi-arch path that clang with `-target bpf` doesn't auto-
        // search. Both common locations; clang ignores the one that doesn't
        // apply on the build host.
        let clang_args = [
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include/aarch64-linux-gnu",
        ];

        for (src, skel_name) in SOURCES {
            let mut out = out_root.clone();
            out.push(skel_name);
            SkeletonBuilder::new()
                .source(src)
                .clang_args(clang_args)
                .build_and_generate(&out)
                .unwrap_or_else(|e| panic!("BPF skeleton build failed for {src}: {e}"));
            println!("cargo:rerun-if-changed={src}");
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux_build::run();
}
