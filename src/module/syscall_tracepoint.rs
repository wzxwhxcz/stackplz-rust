//! Syscall tracepoint module. Mirrors `MRawSyscallsTracepoint`
//! (`user/module/tracepoint_raw_syscalls.go`).
//!
//! The previous master-era implementation (attach `raw_syscalls_sys_enter` as a
//! `tracepoint/raw_syscalls/sys_enter`, read the `syscall_events` perf map,
//! fixed-layout `SyscallDataEvent` decode) is **incompatible with the dev-branch
//! eBPF contract**:
//!   - dev attaches `raw_tracepoint/sys_enter` + `raw_tracepoint/sys_exit` (raw
//!     tracepoints, not `tracepoint/raw_syscalls/...`)
//!   - dev emits a single `events` perf map (not `syscall_events`)
//!   - dev's payload is a variable-length TLV blob decoded by `contract::decode`,
//!     not the fixed-layout `SyscallDataEvent`
//!
//! The runtime is therefore rewritten in **Phase 3**. Until then `run()` returns
//! a pending error on every platform, keeping the crate compiling without
//! depending on libbpf-rs perf APIs that drift between versions.

use crate::config::SyscallConfig;
use crate::logger::Logger;
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// Module name. Mirrors `MODULE_NAME_SYSCALL` (`const.go`).
pub const NAME: &str = super::MODULE_NAME_SYSCALL;

pub struct SyscallTracepointModule {
    pub conf: SyscallConfig,
    pub lib_path: String,
}

impl SyscallTracepointModule {
    pub fn new(conf: SyscallConfig, lib_path: String) -> Self {
        SyscallTracepointModule { conf, lib_path }
    }

    /// Run the module until cancelled / an error occurs.
    ///
    /// TODO(phase-3): implement the dev-branch syscall runtime — open
    /// `syscall.o`, attach `raw_tracepoint/sys_enter` + `sys_exit` +
    /// `sched_process_fork`, write the dev `common_filter` /
    /// `sysenter_point_args` / `sysexit_point_args` maps, and poll the unified
    /// `events` perf map with TLV decoding against `contract::decode`.
    pub fn run(self, _logger: Arc<Logger>) -> Result<()> {
        Err(anyhow!(
            "{}: dev-branch syscall runtime not yet implemented (Phase 3)",
            NAME
        ))
    }
}
