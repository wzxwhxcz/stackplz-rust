//! Uprobe (stack) module. Mirrors `MStackProbe` (`user/module/probe_stack.go`).
//!
//! The previous master-era implementation (attach `probe_stack`, read the
//! `stack_events` perf map, fixed-layout `ContextEvent` decode) is **incompatible
//! with the dev-branch eBPF contract**:
//!   - dev attaches a `probe_stack_0..5` family, not a single `probe_stack`
//!   - dev emits a single `events` perf map (not `stack_events`)
//!   - dev's payload is a variable-length TLV blob, not the fixed-layout header
//!
//! The runtime (perf loop + event decode + uprobe attach) is therefore rewritten
//! in **Phase 3** (`module` runtime layer). Until then, `run()` returns a
//! pending error on every platform. This keeps the crate compiling without
//! depending on libbpf-rs perf APIs that drift between versions, and avoids
//! maintaining dead code that would never run correctly against dev.

use crate::config::ProbeConfig;
use crate::logger::Logger;
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// Module name. Mirrors `MODULE_NAME_STACK` (`const.go`).
pub const NAME: &str = super::MODULE_NAME_STACK;

pub struct StackProbeModule {
    pub probe: ProbeConfig,
    pub lib_path: String,
}

impl StackProbeModule {
    pub fn new(probe: ProbeConfig, lib_path: String) -> Self {
        StackProbeModule { probe, lib_path }
    }

    /// Run the module until cancelled / an error occurs.
    ///
    /// TODO(phase-3): implement the dev-branch uprobe runtime — open `stack.o`,
    /// attach the `probe_stack_N` family, write the dev `common_filter` /
    /// `uprobe_point_args` maps, and poll the unified `events` perf map with
    /// TLV decoding against `contract::decode`.
    pub fn run(self, _logger: Arc<Logger>) -> Result<()> {
        Err(anyhow!(
            "{}: dev-branch uprobe runtime not yet implemented (Phase 3)",
            NAME
        ))
    }
}
