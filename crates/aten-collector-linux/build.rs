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
        ("src/bpf/dns.bpf.c", "dns.skel.rs"),
    ];

    pub fn run() {
        let out_root = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
        // Ubuntu/Debian put arch-specific kernel headers (asm/types.h, etc.)
        // in a multi-arch path that clang with `-target bpf` doesn't auto-
        // search. Both common locations; clang ignores the one that doesn't
        // apply on the build host.
        // dns.bpf.c hand-defines struct pt_regs per arch to read the uprobe's
        // first arg; tell it which arch we're targeting. Any other arch makes
        // the DNS probe a no-op rather than reading the wrong register.
        let arch_def = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("x86_64") => "-D__TARGET_ARCH_x86_64",
            Ok("aarch64") => "-D__TARGET_ARCH_arm64",
            _ => "-D__TARGET_ARCH_unknown",
        };
        let clang_args = [
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include/aarch64-linux-gnu",
            arch_def,
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
