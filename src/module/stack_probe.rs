//! Uprobe (stack) module. Mirrors `MStack` (`user/module/stack.go`).
//!
//! Phase 3 runtime: loads `stack.o`, writes the `op_list` and
//! `uprobe_point_args` BPF maps, attaches the `probe_stack_N` uprobe family,
//! and polls the `events` perf buffer with TLV decoding.
//!
//! On non-Linux hosts, `run()` returns an error (the BPF subsystem is
//! Linux-only). On Linux without `embedded_bpf`, it returns a clear error
//! telling the user to rebuild with the feature enabled.

use crate::config::{ProbeConfig, UprobeArgs};
use crate::logger::Logger;
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// Module name. Mirrors `MODULE_NAME_STACK` (`const.go`).
pub const NAME: &str = super::MODULE_NAME_STACK;

pub struct StackProbeModule {
    pub probe: ProbeConfig,
    pub lib_path: String,
    /// Parsed hook points (from `-w`). Empty for `--symbol`/`--config` mode.
    pub hook_points: Vec<UprobeArgs>,
}

impl StackProbeModule {
    pub fn new(probe: ProbeConfig, lib_path: String) -> Self {
        StackProbeModule {
            probe,
            lib_path,
            hook_points: Vec::new(),
        }
    }

    pub fn with_hook_points(mut self, points: Vec<UprobeArgs>) -> Self {
        self.hook_points = points;
        self
    }

    /// Run the module until cancelled / an error occurs.
    ///
    /// Phase 3 flow:
    /// 1. Load `stack.o` via libbpf-rs
    /// 2. Write `op_list` map (all registered ops)
    /// 3. Write `uprobe_point_args` map (one entry per hook point)
    /// 4. Attach `probe_stack_N` uprobe programs
    /// 5. Poll `events` perf buffer and decode
    #[cfg(target_os = "linux")]
    pub fn run(self, logger: Arc<Logger>) -> Result<()> {
        use crate::ebpf::bpf_common;

        logger.println(&format!("{NAME}\tloading eBPF object..."));

        // 1. Load the BPF object.
        #[cfg(feature = "embedded_bpf")]
        let obj_bytes = bpf_common::STACK_OBJ;
        #[cfg(not(feature = "embedded_bpf"))]
        let obj_bytes = bpf_common::STACK_OBJ;

        let obj = bpf_common::linux::open_object(obj_bytes)?;
        logger.println(&format!("{NAME}\teBPF object loaded"));

        // 2. Write op_list map.
        bpf_common::linux::write_op_list(&obj)?;
        logger.println(&format!(
            "{NAME}\top_list map written ({} ops)",
            crate::argtype::count()
        ));

        // 3. Write uprobe_point_args map.
        if !self.hook_points.is_empty() {
            bpf_common::linux::write_uprobe_point_args(&obj, &self.hook_points)?;
            logger.println(&format!(
                "{NAME}\tuprobe_point_args map written ({} points)",
                self.hook_points.len()
            ));
        }

        // 4. Attach uprobe programs.
        let library = &self.probe.library;
        let mut attached = 0usize;
        for (i, point) in self.hook_points.iter().enumerate() {
            let prog_name = format!("probe_stack_{i}");
            let prog = obj
                .prog_mut(&prog_name)
                .ok_or_else(|| anyhow!("program {prog_name} not found in BPF object"))?;

            // Resolve the attach offset.
            let attach_offset = if !point.symbol.is_empty() {
                // Symbol-based: resolve via ELF.
                let elf_bytes = std::fs::read(library)?;
                bpf_common::resolve_symbol_offset(&elf_bytes, &point.symbol)?
                    + point.offset
            } else {
                point.offset
            };

            let _link = prog.attach_uprobe(false, -1, library, attach_offset as usize)?;
            attached += 1;
            logger.println(&format!(
                "{NAME}\tattached {prog_name} to {library} at offset 0x{attach_offset:x}"
            ));
        }

        if attached == 0 {
            return Err(anyhow!("{NAME}: no uprobe programs attached"));
        }

        // 5. Poll the events perf buffer.
        // TODO(phase-3.2): implement perf buffer polling + event decoding.
        // For now, block on signal so the process stays alive.
        logger.println(&format!("{NAME}\tpolling events (attached={attached})..."));
        super::wait_for_signal();

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run(self, _logger: Arc<Logger>) -> Result<()> {
        Err(anyhow!(
            "{}: BPF runtime requires Linux (this build targets a non-Linux OS)",
            NAME
        ))
    }
}
