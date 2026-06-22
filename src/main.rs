//! stackplz-rs entry point. Mirrors `main.go`.
//!
//! Flow:
//!   1. `ebpf::is_enable_bpf()` — read `/proc/config.gz`, assert BPF/uprobe
//!      configs are enabled (`CONFIG_BPF`, `CONFIG_UPROBES`,
//!      `CONFIG_ARCH_SUPPORTS_UPROBES`). Fatal on failure.
//!   2. `cli::start()` — parse args, run persistent pre-run, dispatch.

use stackplz::cli;

fn main() {
    // On non-Linux hosts (e.g. Windows dev), the BPF capability check can't
    // run. We skip it there so unit-test-style invocations still work; the real
    // device build (Linux/Android) always performs the check.
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = stackplz::ebpf::is_enable_bpf() {
            eprintln!("BPF capability check failed: {}", e);
            std::process::exit(1);
        }
    }

    let code = cli::start();
    std::process::exit(code);
}
