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

/// Block until SIGINT/SIGTERM arrives. Used by module run loops.
#[cfg(unix)]
pub fn wait_for_signal() {
    use std::os::raw::c_int;
    extern "C" {
        fn signal(signum: c_int, handler: usize) -> usize;
    }
    static CAUGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    extern "C" fn handler(_sig: c_int) {
        CAUGHT.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;
    unsafe {
        signal(SIGINT, handler as *const () as usize);
        signal(SIGTERM, handler as *const () as usize);
    }
    while !CAUGHT.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(not(unix))]
pub fn wait_for_signal() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
