//! eBPF module layer. Mirrors package `module` (`user/module/*.go`).
//!
//! Two concrete modules, mirroring the Go tree:
//! - `stack_probe.rs`           => `probe_stack.go`        (uprobe, stack.o)
//! - `syscall_tracepoint.rs`    => `tracepoint_raw_syscalls.go` (tracepoint)
//!
//! The shared lifecycle (load, write filter_map, spawn perf reader, dispatch
//! events) lives in `Module` here, mirroring `imodule.go`.

pub mod stack_probe;
pub mod syscall_tracepoint;

pub use stack_probe::StackProbeModule;
pub use syscall_tracepoint::SyscallTracepointModule;

/// Module name constants. Mirrors `user/module/const.go`.
pub const MODULE_NAME_STACK: &str = "StackMod";
pub const MODULE_NAME_SYSCALL: &str = "SyscallMod";
pub const PROBE_TYPE_UPROBE: &str = "uprobe";
pub const PROBE_TYPE_TRACEPOINT: &str = "tracepoint";
