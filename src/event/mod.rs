//! Event decoding pipeline. Mirrors package `event` (`user/event/*.go`).
//!
//! - `ievent.rs`   => `ievent.go` (CommonEvent, LibArg, UnwindBuf, RegsBuf)
//! - `context.rs`  => `event_context.go` (ContextEvent: common header decode)
//! - `hook.rs`     => `event_stack.go` (HookDataEvent: uprobe event String())
//! - `syscall_event.rs` => `event_raw_syscalls.go` (SyscallDataEvent)
//! - `unwind_ffi.rs` => `chelper.go` + `load_so.c` (dlopen libstackplz.so)

pub mod context;
pub mod hook;
pub mod ievent;
pub mod syscall_event;
pub mod unwind_ffi;

pub use context::ContextEvent;
pub use hook::HookDataEvent;
pub use ievent::{CommonEvent, LibArg, RegsBuf, UnwindBuf};
pub use syscall_event::SyscallDataEvent;
pub use unwind_ffi::parse_stack;

/// Read `/proc/<pid>/maps` for the unwinder, returning an empty string on
/// failure (the unwinder degrades gracefully). Mirrors the inline
/// `ReadMapsByPid` call in the Go dispatcher path.
pub fn parse_maps_for_pid(pid: u32) -> String {
    crate::util::read_maps_by_pid(pid).unwrap_or_default()
}

/// Number of arm64 registers in the perf sample (x0..x29 + lr + sp + pc).
/// Mirrors the `[33]uint64` arrays in `ievent.go`.
pub const REG_COUNT: usize = 33;

/// Comm field length. Mirrors `TASK_COMM_LEN` (`common.h`).
pub const COMM_LEN: usize = 16;
