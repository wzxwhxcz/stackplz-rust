//! Event decoding pipeline. Mirrors package `event` (`user/event/*.go`).
//!
//! - `ievent.rs`   => `ievent.go` (CommonEvent, UnwindBuf, RegsBuf, UnwindOption)
//! - `render.rs`   => the dev-format `String()` output of `event_raw_syscalls.go`
//!   and `event_uprobe.go`, rebuilt on the `argtype` parse layer (report W7).
//! - `unwind_ffi.rs` => `chelper.go` + `load_so.c` (dlopen libstackplz.so, call
//!   its exported `StackPlz`)
//!
//! The old master-layout event layer (master's 36-byte header decoder — the
//! deleted `context.rs` — and its `event_stack.go` / `event_raw_syscalls.go`
//! formatters) is gone: nothing in the dev pipeline decodes that header, and an
//! unused decoder is a trap (report W21).

pub mod ievent;
pub mod render;
pub mod unwind_ffi;

pub use ievent::{CommonEvent, RegsBuf, UnwindBuf, UnwindOption};
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

/// Comm field length. Mirrors `TASK_COMM_LEN` (`src/common/consts.h:4`).
pub const COMM_LEN: usize = 16;
