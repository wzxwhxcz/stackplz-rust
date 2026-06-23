//! Uprobe (stack) module. Mirrors `MStack` (`user/module/stack.go`).
//!
//! Phase 3 runtime: loads `stack.o`, writes the `op_list` and
//! `uprobe_point_args` BPF maps, attaches the `probe_stack_N` uprobe family,
//! and polls the `events` perf buffer with TLV decoding.

use crate::config::{ProbeConfig, UprobeArgs};
use crate::logger::Logger;
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// Module name. Mirrors `MODULE_NAME_STACK`.
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
    #[cfg(target_os = "linux")]
    pub fn run(self, logger: Arc<Logger>) -> Result<()> {
        use crate::ebpf::bpf_common;

        logger.println(&format!("{NAME}\tloading eBPF object..."));

        // 1. Load the BPF object.
        let obj_bytes = bpf_common::STACK_OBJ;
        let mut obj = bpf_common::linux::open_object(obj_bytes)?;
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

            let attach_offset = if !point.symbol.is_empty() {
                let elf_bytes = std::fs::read(library)?;
                bpf_common::resolve_symbol_offset(&elf_bytes, &point.symbol)? + point.offset
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
        logger.println(&format!("{NAME}\tpolling events (attached={attached})..."));

        // The perf buffer callback needs access to hook_points for rendering.
        // We share them via Arc so the closure can read them.
        let hook_points = Arc::new(self.hook_points);
        let render_logger = logger.clone();

        let events_map = obj
            .map("events")
            .ok_or_else(|| anyhow!("cannot find events map"))?;

        let mut pb = libbpf_rs::PerfBufferBuilder::new(events_map)
            .pages(256)
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                let rendered = render_uprobe_event(data, &hook_points);
                match rendered {
                    Ok(line) => render_logger.println(&line),
                    Err(e) => eprintln!("{NAME}\tdecode error: {e}"),
                }
            })
            .lost_cb(|_cpu: i32, count: u64| {
                eprintln!("{NAME}\tlost {count} samples on CPU {_cpu}");
            })
            .build()?;

        loop {
            pb.poll(std::time::Duration::from_millis(100))?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run(self, _logger: Arc<Logger>) -> Result<()> {
        Err(anyhow!(
            "{}: BPF runtime requires Linux (this build targets a non-Linux OS)",
            NAME
        ))
    }
}

/// Render a raw perf record as a human-readable uprobe event line.
///
/// Mirrors `UprobeEvent.ParseContext` + `String()` in Go.
#[cfg(target_os = "linux")]
fn render_uprobe_event(raw: &[u8], hook_points: &[UprobeArgs]) -> Result<String> {
    use crate::contract::decode::{decode_perf_record, PerfRecord};

    let rec = decode_perf_record(raw)?;
    match rec {
        PerfRecord::UprobeEnter(e) => {
            let ctx = &e.context;
            let comm = {
                let s = std::str::from_utf8(&ctx.comm)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .trim_end_matches(' ');
                s.to_string()
            };
            let uuid = format!("[{}|{}|{comm}]", ctx.pid, ctx.tid);

            let point_idx = e.point_key as usize;
            let point = hook_points
                .get(point_idx)
                .ok_or_else(|| anyhow!("point_key {point_idx} out of range"))?;

            // Build arg string from the TLV cursor.
            let mut arg_parts = Vec::new();
            let mut cursor = e.args;
            for pa in &point.point_args {
                // Each arg starts with an Arg_reg: [u8 index][u64 address]
                let (idx, reg_bytes) = cursor.next_raw_borrow(9)?;
                let _ = idx;
                if reg_bytes.len() >= 9 {
                    let addr = u64::from_le_bytes([
                        reg_bytes[1],
                        reg_bytes[2],
                        reg_bytes[3],
                        reg_bytes[4],
                        reg_bytes[5],
                        reg_bytes[6],
                        reg_bytes[7],
                        reg_bytes[8],
                    ]);
                    arg_parts.push(format!("{}=0x{addr:x}", pa.name));
                }
            }

            let arg_str = if arg_parts.is_empty() {
                String::new()
            } else {
                format!("({})", arg_parts.join(", "))
            };

            Ok(format!(
                "{uuid} {}{arg_str} LR:0x{:x} PC:0x{:x} SP:0x{:x}",
                point.name, e.lr, e.pc, e.sp
            ))
        }
        _ => Ok(format!("non-uprobe event ({} bytes)", raw.len())),
    }
}
