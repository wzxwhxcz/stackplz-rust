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
    /// Signal to send on uprobe hit (from --kill), 0 = none.
    pub kill_signal: u32,
    /// Signal to send to thread on uprobe hit (from --tkill), 0 = none.
    pub tkill_signal: u32,
    /// Auto-resume after SIGSTOP (from --auto).
    pub auto_resume: bool,
}

impl StackProbeModule {
    pub fn new(probe: ProbeConfig, lib_path: String) -> Self {
        StackProbeModule {
            probe,
            lib_path,
            hook_points: Vec::new(),
            kill_signal: 0,
            tkill_signal: 0,
            auto_resume: false,
        }
    }

    pub fn with_hook_points(mut self, points: Vec<UprobeArgs>) -> Self {
        self.hook_points = points;
        self
    }

    pub fn with_signals(mut self, kill: u32, tkill: u32, auto_resume: bool) -> Self {
        self.kill_signal = kill;
        self.tkill_signal = tkill;
        self.auto_resume = auto_resume;
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

        // 2b. Write base_config (stackplz's own PID for self-filtering).
        let self_pid = std::process::id();
        bpf_common::linux::write_base_config(&obj, self_pid)?;
        logger.println(&format!("{NAME}\tbase_config written (pid={self_pid})"));

        // 2c. Write common_filter (trace_mode=ALL, uid_group covers all).
        use crate::contract::consts::{TRACE_ALL, TRACE_COMMON};
        let _ = TRACE_COMMON;
        bpf_common::linux::write_common_filter(
            &obj,
            false,
            TRACE_ALL,
            0xFF,
            self.kill_signal,
            self.tkill_signal,
        )?;

        // 2d. Write uid whitelist (the target uid).
        if self.probe.sconfig.uid != 0 {
            bpf_common::linux::write_common_list(
                &obj,
                &[self.probe.sconfig.uid as u32],
                crate::contract::consts::UID_WHITELIST_START,
            )?;
            logger.println(&format!(
                "{NAME}\tuid whitelist: {}",
                self.probe.sconfig.uid
            ));
        }

        // 2e. Write pid whitelist if specified.
        if self.probe.sconfig.pid != 0 {
            bpf_common::linux::write_common_list(
                &obj,
                &[self.probe.sconfig.pid as u32],
                crate::contract::consts::PID_WHITELIST_START,
            )?;
        }

        // 2f. Write tid blacklist if specified.
        if self.probe.sconfig.tid_blacklist_mask != 0 {
            bpf_common::linux::write_common_list(
                &obj,
                &self.probe.sconfig.tid_blacklist,
                crate::contract::consts::TID_BLACKLIST_START,
            )?;
        }

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

        let pb = libbpf_rs::PerfBufferBuilder::new(events_map)
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
                // Each arg starts with an Arg_reg: [u8 index][u64 address/value]
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

                    // Look up the arg type to determine how to render.
                    let at = crate::argtype::get_arg_type(pa.type_index);

                    // For simple numeric/pointer types, the reg value IS the data.
                    // For string/buffer/struct types, additional TLV payload follows.
                    let rendered = match at.base_type {
                        crate::argtype::consts::TYPE_INT
                        | crate::argtype::consts::TYPE_INT8
                        | crate::argtype::consts::TYPE_INT16
                        | crate::argtype::consts::TYPE_INT32
                        | crate::argtype::consts::TYPE_INT64
                        | crate::argtype::consts::TYPE_UINT
                        | crate::argtype::consts::TYPE_UINT8
                        | crate::argtype::consts::TYPE_UINT16
                        | crate::argtype::consts::TYPE_UINT32
                        | crate::argtype::consts::TYPE_UINT64
                        | crate::argtype::consts::TYPE_POINTER => {
                            crate::argtype::render::format_num(
                                addr,
                                at.format_type,
                                matches!(
                                    at.base_type,
                                    crate::argtype::consts::TYPE_INT
                                        | crate::argtype::consts::TYPE_INT8
                                        | crate::argtype::consts::TYPE_INT16
                                        | crate::argtype::consts::TYPE_INT32
                                        | crate::argtype::consts::TYPE_INT64
                                ),
                                at.size,
                            )
                        }
                        _ => {
                            // String/buffer/struct: try to read the payload
                            // ([u8 index][u32 len][bytes...]).
                            if let Ok((_, _, payload_bytes)) =
                                cursor.next_length_prefixed()
                            {
                                crate::argtype::render::render_arg_value(
                                    at.base_type,
                                    at.size,
                                    at.format_type,
                                    &payload_bytes,
                                    at.dump_hex,
                                )
                            } else {
                                format!("0x{addr:x}")
                            }
                        }
                    };
                    arg_parts.push(format!("{}={rendered}", pa.name));
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

/// Parse a signal name (e.g. "SIGSTOP", "SIGABRT") to its numeric value.
/// Returns 0 for empty/unrecognized strings.
/// Mirrors Go's `util.ParseSignal(name)` usage.
pub fn parse_signal_name(name: &str) -> u32 {
    if name.is_empty() {
        return 0;
    }
    let upper = name.to_uppercase();
    let upper = upper.strip_prefix("SIG").unwrap_or(&upper);
    match upper {
        "STOP" => 19,
        "ABRT" => 6,
        "TRAP" => 5,
        "KILL" => 9,
        "INT" => 2,
        "TERM" => 15,
        "CONT" => 18,
        "USR1" => 10,
        "USR2" => 12,
        "SEGV" => 11,
        "BUS" => 7,
        "FPE" => 8,
        "ALRM" => 14,
        "HUP" => 1,
        "PIPE" => 13,
        _ => {
            // Try parsing as a raw number.
            name.parse::<u32>().unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signal_names() {
        assert_eq!(parse_signal_name("SIGSTOP"), 19);
        assert_eq!(parse_signal_name("SIGABRT"), 6);
        assert_eq!(parse_signal_name("SIGTRAP"), 5);
        assert_eq!(parse_signal_name("sigstop"), 19); // case-insensitive
        assert_eq!(parse_signal_name(""), 0);
        assert_eq!(parse_signal_name("SIGUNKNOWN"), 0);
        assert_eq!(parse_signal_name("42"), 42); // raw number
    }
}
