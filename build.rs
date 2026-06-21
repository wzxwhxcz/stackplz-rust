//! Build script: compile the dev-branch eBPF C programs to `ebpf/bpf/*.o`,
//! mirroring the upstream `Makefile` `ebpf_*` targets.
//!
//! The dev eBPF tree lives under `ebpf/` (copied verbatim from the Go repo's
//! `src/`). It is self-contained: it vendors `bpf/bpf_helpers.h`,
//! `bpf/bpf_helper_defs.h`, `bpf_tracing.h` and `vmlinux_510.h`, so the only
//! external header dependency is `libbpf/src` (cloned via `build_env.sh`).
//!
//! Three objects are produced (matching the Makefile), each with its own module
//! define so `MAX_OP_COUNT` in `point_args_t` is sized correctly:
//!   - `stack.o`      <- `stack.c`      with `-D__MODULE_STACK`   (MAX_OP_COUNT=64)
//!   - `syscall.o`    <- `syscall.c`    with `-D__MODULE_SYSCALL` (MAX_OP_COUNT=256)
//!   - `perf_mmap.o`  <- `perf_mmap.c`  (default MAX_OP_COUNT=512)
//!
//! Behavior:
//! - Looks for `clang` on PATH. If absent, the build is skipped with a notice.
//! - Looks for `libbpf/src/bpf_helpers.h` (cloned via `build_env.sh`). If
//!   missing, the eBPF compile is skipped with a notice. Either way the crate
//!   still builds (the `embedded_bpf` feature is off by default).

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// `(source file, output stem, optional -D__MODULE_* define)`.
const EBPF_TARGETS: &[(&str, &str, Option<&str>)] = &[
    ("stack.c", "stack", Some("__MODULE_STACK")),
    ("syscall.c", "syscall", Some("__MODULE_SYSCALL")),
    ("perf_mmap.c", "perf_mmap", None),
];

/// C sources (other than the targets themselves) whose change should retrigger.
const EBPF_HEADERS: &[&str] = &[
    "maps.h",
    "memory.h",
    "types.h",
    "utils.h",
    "vmlinux_510.h",
    "bpf/bpf_helpers.h",
    "bpf/bpf_helper_defs.h",
    "bpf/bpf_tracing.h",
    "common/arch.h",
    "common/arguments.h",
    "common/buffer.h",
    "common/common.h",
    "common/consts.h",
    "common/context.h",
    "common/filtering.h",
    "common/task.h",
];

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Re-run whenever any eBPF source/header changes.
    for tgt in EBPF_TARGETS {
        println!("cargo:rerun-if-changed=ebpf/{}", tgt.0);
    }
    for hdr in EBPF_HEADERS {
        println!("cargo:rerun-if-changed=ebpf/{}", hdr);
    }

    // Write .o artifacts to the in-tree `ebpf/bpf/` dir so `include_bytes!`
    // (which needs a fixed relative path) resolves them. This dir also holds
    // the vendored libbpf headers; `.o` and `.h` names never collide.
    let bpf_out = manifest.join("ebpf/bpf");
    std::fs::create_dir_all(&bpf_out).unwrap();

    // Locate clang.
    let clang = which("clang").or_else(|| which("clang-15").or_else(|| which("clang-14")));

    // Locate the libbpf headers (cloned by build_env.sh).
    let libbpf_src = manifest.join("libbpf/src");
    let have_libbpf = libbpf_src.join("bpf_helpers.h").is_file();

    // Sanity: the eBPF sources must exist.
    let have_sources = EBPF_TARGETS
        .iter()
        .all(|t| manifest.join("ebpf").join(t.0).is_file());

    let clang = match (clang, have_libbpf, have_sources) {
        (Some(c), true, true) => c,
        (None, _, _) => {
            println!(
                "cargo:warning=clang not found; skipping eBPF compile. \
                 Provide ebpf/bpf/*.o manually or install clang + run build_env.sh."
            );
            return;
        }
        (_, false, _) => {
            println!(
                "cargo:warning=libbpf headers not found under libbpf/src; \
                 skipping eBPF compile. Run build_env.sh first."
            );
            return;
        }
        (_, _, false) => {
            println!("cargo:warning=eBPF C sources missing under ebpf/; skipping compile.");
            return;
        }
    };

    let mut ok = true;
    for &(src, stem, module_define) in EBPF_TARGETS {
        let src_path = manifest.join("ebpf").join(src);
        let obj = bpf_out.join(format!("{}.o", stem));
        let mut cmd = Command::new(&clang);
        cmd.arg("-D__TARGET_ARCH_arm64")
            .args(module_define.map(d))
            .arg("--target=bpf")
            .arg("-c")
            .arg("-nostdlibinc")
            .arg("-no-canonical-prefixes")
            .arg("-O2")
            .arg("-g")
            .arg(format!("-I{}", libbpf_src.display()))
            .arg(format!("-I{}", manifest.join("ebpf").display()));
        if cfg!(feature = "debug_print") {
            cmd.arg("-DDEBUG_PRINT");
        }
        cmd.arg(&src_path).arg("-o").arg(&obj);
        match cmd.status() {
            Ok(s) if s.success() => {
                println!("cargo:warning=built eBPF object: {}", obj.display());
            }
            _ => {
                println!("cargo:warning=failed to compile {}", src);
                ok = false;
            }
        }
    }

    if ok {
        for &(src, stem, _) in EBPF_TARGETS {
            let _ = src; // silence unused binding in some toolchains
            println!("cargo:rerun-if-changed=ebpf/bpf/{}.o", stem);
        }
        println!(
            "cargo:warning=eBPF objects built (stack.o, syscall.o, perf_mmap.o). \
             Build with --features embedded_bpf to embed them."
        );
    }
}

fn d(name: &str) -> String {
    format!("-D{}", name)
}

fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        let exe = dir.join(format!("{}.exe", name));
        if exe.is_file() {
            return Some(exe);
        }
    }
    None
}
