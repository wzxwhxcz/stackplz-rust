//! eBPF module layer. Mirrors package `module` (`user/module/*.go`).
//!
//! Two concrete modules, mirroring the dev-branch Go tree:
//! - `stack_probe.rs`           => `stack.go`        (uprobe, stack.o)
//! - `syscall_tracepoint.rs`    => `syscall.go`      (tracepoint)
//!
//! Master-era names for the same modules were `probe_stack.go` /
//! `tracepoint_raw_syscalls.go`.
//!
//! The shared lifecycle (load, write filter_map, spawn perf reader, dispatch
//! events) lives in `Module` here, mirroring `imodule.go`.
//!
//! Report W10 (dead modules): `brk.rs`, `perf_mmap.rs` (and the crate-root
//! `rpc.rs` / `dump.rs` / `config/perf_mmap.rs`) were deleted rather than left
//! looking wired-up. In upstream `dev` they are scheduled from `root.go`, but
//! this crate has no scheduler for them: nothing constructed the modules, so
//! they could never run. Brief item 4 accepts either "connect" or "delete";
//! deletion is the chosen option (see DONE.md). The corresponding global CLI
//! flags (`--brk*`, `--rpc*`, `--dump`, `--parse`) are removed by the CLI
//! rewrite in the same round.

pub mod stack_probe;
pub mod syscall_tracepoint;

pub use stack_probe::StackProbeModule;
pub use syscall_tracepoint::SyscallTracepointModule;

/// Module name constants. Mirrors `user/module/const.go`.
pub const MODULE_NAME_STACK: &str = "StackMod";
pub const MODULE_NAME_SYSCALL: &str = "SyscallMod";

/// Perf ring-buffer size in 4 KiB pages from the `-b/--buffer` MiB value.
///
/// 1 MiB == 256 pages (dev `GlobalConfig.Buffer`). Rejects 0 — a zero-page ring
/// is unusable — and clamps the upper end so a bogus `-b` cannot over-allocate.
pub fn perf_pages(buffer_mb: u32) -> anyhow::Result<usize> {
    if buffer_mb == 0 {
        anyhow::bail!("buffer size must be at least 1 MiB");
    }
    // 4096 MiB == 1 GiB of ring, far above any sane value.
    Ok(buffer_mb.min(4096) as usize * 256)
}

#[cfg(test)]
mod tests {
    #[test]
    fn perf_pages_rejects_zero_and_clamps() {
        assert!(super::perf_pages(0).is_err());
        assert_eq!(super::perf_pages(1).unwrap(), 256);
        assert_eq!(super::perf_pages(16).unwrap(), 4096);
        assert_eq!(super::perf_pages(u32::MAX).unwrap(), 4096 * 256);
    }
}
