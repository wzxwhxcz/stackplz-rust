//! Uprobe (stack) module. Mirrors `MStack` (`user/module/stack.go`).
//!
//! Phase 3 runtime: loads `stack.o`, writes exactly the maps upstream
//! `MStack.updateFilter()` writes (`stack.go:381-390`): `base_config`,
//! `common_filter`, `common_list` (six segments), `child_parent_map`,
//! `thread_filter`, `uprobe_point_args`, `arg_filter` and `op_list`. Then it
//! attaches the `probe_stack_N` uprobe family and polls the `events` perf
//! buffer with TLV decoding.

use crate::config::{ProbeConfig, SConfig, StackConfig, UprobeArgs};
use crate::logger::Logger;
use anyhow::{anyhow, Result};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use libbpf_rs::MapCore;

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
    /// Filter carrier built from the global CLI flags by the caller. When it is
    /// `None` the module falls back to the legacy `ProbeConfig::sconfig`
    /// uid/pid/tid-blacklist fields, so existing callers keep working.
    pub stack_config: Option<StackConfig>,
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
            stack_config: None,
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

    /// Attach the dev-style filter carrier (report W17). Every map that
    /// `MStack.updateFilter()` writes is derived from it.
    ///
    /// `--kill`/`--tkill` are taken from `conf` when non-zero and otherwise
    /// fall back to the values given to [`Self::with_signals`], so the two
    /// builders can be called in either order.
    pub fn with_stack_config(mut self, conf: StackConfig) -> Self {
        if conf.kill_signal != 0 {
            self.kill_signal = conf.kill_signal;
        }
        if conf.tkill_signal != 0 {
            self.tkill_signal = conf.tkill_signal;
        }
        self.stack_config = Some(conf);
        self
    }

    /// Effective `--kill` signal: config value wins, `with_signals` otherwise.
    pub fn effective_kill_signal(&self) -> u32 {
        match &self.stack_config {
            Some(conf) if conf.kill_signal != 0 => conf.kill_signal,
            _ => self.kill_signal,
        }
    }

    /// Effective `--tkill` signal: config value wins, `with_signals` otherwise.
    pub fn effective_tkill_signal(&self) -> u32 {
        match &self.stack_config {
            Some(conf) if conf.tkill_signal != 0 => conf.tkill_signal,
            _ => self.tkill_signal,
        }
    }

    /// The filter carrier actually written to the BPF maps. With no explicit
    /// [`Self::with_stack_config`] this rebuilds one from the legacy
    /// `ProbeConfig::sconfig` fields (uid/pid whitelists + masked tid
    /// blacklist), preserving the pre-W17 behaviour for old callers.
    pub fn effective_stack_config(&self) -> StackConfig {
        self.stack_config
            .clone()
            .unwrap_or_else(|| legacy_stack_config(&self.probe.sconfig))
    }

    /// Run the module until cancelled / an error occurs.
    #[cfg(target_os = "linux")]
    pub fn run(self, logger: Arc<Logger>) -> Result<()> {
        use crate::ebpf::bpf_common;

        let conf = self.effective_stack_config();
        let kill_signal = self.effective_kill_signal();
        let tkill_signal = self.effective_tkill_signal();

        logger.println(&format!("{NAME}\tloading eBPF object..."));

        // 1. Load the BPF object.
        let obj_bytes = bpf_common::STACK_OBJ;
        let obj = bpf_common::linux::open_object(obj_bytes)?;
        logger.println(&format!("{NAME}\teBPF object loaded"));

        // 2. `base_config` (key 0): stackplz's own PID for self-filtering, plus
        //    "a thread whitelist is active". Mirrors `update_base_config()`.
        let self_pid = std::process::id();
        bpf_common::linux::write_base_config(&obj, self_pid, !conf.tname_whitelist.is_empty())?;
        logger.println(&format!(
            "{NAME}\tbase_config written (pid={self_pid}, thread_whitelist={})",
            u8::from(!conf.tname_whitelist.is_empty())
        ));

        // 3. `common_filter` (key 0): trace mode, `-n` uid groups, kill signals.
        //    Report W17: `trace_uid_group` is the configured value (0 by
        //    default), no longer a hard-coded 0xFF.
        bpf_common::linux::write_common_filter(
            &obj,
            false,
            conf.trace_mode,
            conf.trace_uid_group,
            kill_signal,
            tkill_signal,
        )?;
        logger.println(&format!(
            "{NAME}\tcommon_filter written (trace_mode={}, trace_uid_group=0x{:x}, signal={kill_signal}, tsignal={tkill_signal})",
            conf.trace_mode, conf.trace_uid_group
        ));

        // 4. `common_list`: all six uid/pid/tid white+blacklist segments, in
        //    dev order. Mirrors the `update_common_list()` calls in
        //    `update_common_filter()` (`stack.go:245-259`).
        bpf_common::linux::write_common_lists(&obj, &conf.common_list_segments())?;
        logger.println(&format!(
            "{NAME}\tcommon_list written (uid whitelist:[{}] blacklist:[{}]; pid whitelist:[{}] blacklist:[{}]; tid whitelist:[{}] blacklist:[{}])",
            join_ids(&conf.uid_whitelist),
            join_ids(&conf.uid_blacklist),
            join_ids(&conf.pid_whitelist),
            join_ids(&conf.pid_blacklist),
            join_ids(&conf.tid_whitelist),
            join_ids(&conf.tid_blacklist)
        ));

        // 5. `child_parent_map`: seed every pid whitelist entry so children
        //    forked by the C handler stay traced. Mirrors `update_child_parent()`.
        bpf_common::linux::write_child_parent_map(&obj, &conf.pid_whitelist)?;
        logger.println(&format!(
            "{NAME}\tchild_parent_map seeded ({} pids)",
            conf.pid_whitelist.len()
        ));

        // 6. `thread_filter`: default blacklist + `--tname`/`--no-tname`.
        //    Mirrors `update_thread_filter()` (`stack.go:269-317`); names over
        //    16 bytes are rejected before touching the map.
        let thread_entries = conf.thread_filter_entries()?;
        bpf_common::linux::write_thread_filter(&obj, &thread_entries)?;
        logger.println(&format!(
            "{NAME}\tthread_filter written ({} entries)",
            thread_entries.len()
        ));

        // 7. Write `uprobe_point_args` map.
        if !self.hook_points.is_empty() {
            bpf_common::linux::write_uprobe_point_args(&obj, &self.hook_points)?;
            logger.println(&format!(
                "{NAME}\tuprobe_point_args map written ({} points)",
                self.hook_points.len()
            ));
        }

        // 8. `arg_filter`: every `-f/--filter` entry registered in userspace.
        //    Mirrors `update_arg_filter()` (`stack.go:318-339`); report W9.
        let filters = crate::config::get_filters();
        bpf_common::linux::write_arg_filter(&obj, &filters)?;
        logger.println(&format!(
            "{NAME}\targ_filter written ({} filters)",
            filters.len()
        ));

        // 9. `op_list` map from the argtype subsystem.
        bpf_common::linux::write_op_list(&obj)?;
        logger.println(&format!(
            "{NAME}\top_list map written ({} ops)",
            crate::argtype::count()
        ));

        // 10. Attach uprobe programs.
        let library = &self.probe.library;
        let mut attached = 0usize;
        for (i, point) in self.hook_points.iter().enumerate() {
            let prog_name = format!("probe_stack_{i}");
            let prog = obj
                .progs_mut()
                .find(|p| p.name() == prog_name.as_str())
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
            .maps()
            .find(|m| m.name() == "events")
            .ok_or_else(|| anyhow!("cannot find events map"))?;

        // `-b/--buffer` in MiB → 4 KiB pages (dev `GlobalConfig.Buffer`).
        let pages = conf.buffer_mb as usize * 256;
        let pb = libbpf_rs::PerfBufferBuilder::new(&events_map)
            .pages(pages)
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

/// Build a [`StackConfig`] from the legacy [`SConfig`] fields, used when a
/// caller does not attach one through [`StackProbeModule::with_stack_config`].
///
/// This preserves the pre-W17 contract (`SConfig::uid` / `pid` scalar, 5-entry
/// masked `tid_blacklist`) without keeping the old hard-coded 0xFF uid-group or
/// the missing `child_parent_map` / `thread_filter` / `arg_filter` writes: the
/// scalar uid/pid become one-element whitelists, and the masked tid blacklist
/// becomes the tid blacklist list. Values equal to 0 mean "not given" in the
/// legacy SConfig carrier and are therefore not written (the new CLI uses the
/// dev-style lists instead, where `-u 0` is meaningful).
pub fn legacy_stack_config(sconfig: &SConfig) -> StackConfig {
    let mut conf = StackConfig::default();
    if sconfig.uid != 0 {
        conf.uid_whitelist.push(sconfig.uid as u32);
    }
    if sconfig.pid != 0 {
        conf.pid_whitelist.push(sconfig.pid as u32);
    }
    for (i, tid) in sconfig.tid_blacklist.iter().enumerate() {
        if sconfig.tid_blacklist_mask & (1u32 << i) != 0 {
            conf.tid_blacklist.push(*tid);
        }
    }
    conf
}

/// `1,2,3` rendering of an id list, mirroring `MStack.list2string()`.
/// Only used by the Linux run loop's log line.
#[cfg(target_os = "linux")]
fn join_ids(ids: &[u32]) -> String {
    ids.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Render a raw perf record as a human-readable uprobe event line.
///
/// Mirrors `UprobeEvent.ParseContext` + `String()` in Go.
#[cfg(target_os = "linux")]
fn render_uprobe_event(raw: &[u8], hook_points: &[UprobeArgs]) -> Result<String> {
    use crate::contract::decode::{decode_perf_record, PerfRecord};

    let rec = decode_perf_record(raw)?;
    match rec {
        PerfRecord::UprobeEnter(mut e) => {
            let point = hook_points
                .get(e.point_key as usize)
                .ok_or_else(|| anyhow!("point_key {} out of range", e.point_key))?;
            crate::event::render::render_uprobe_event(&mut e, point)
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

    fn dummy_probe(sconfig: SConfig) -> ProbeConfig {
        ProbeConfig {
            sconfig,
            lib_name: String::new(),
            library: String::new(),
            symbol: "open".into(),
            offset: 0,
        }
    }

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

    /// Without `with_stack_config` the module keeps working from the legacy
    /// `SConfig` carrier: non-zero uid/pid become one-element whitelists and the
    /// masked tid blacklist becomes the tid blacklist.
    #[test]
    fn legacy_sconfig_is_converted_to_the_dev_lists() {
        let sconfig = SConfig {
            uid: 1000,
            pid: 4242,
            tid_blacklist_mask: 0b101,
            tid_blacklist: [11, 22, 33, 0, 0],
            ..Default::default()
        };
        let conf = legacy_stack_config(&sconfig);
        assert_eq!(conf.uid_whitelist, vec![1000]);
        assert_eq!(conf.pid_whitelist, vec![4242]);
        // Only the masked-in entries (indices 0 and 2) are written.
        assert_eq!(conf.tid_blacklist, vec![11, 33]);
        assert!(conf.uid_blacklist.is_empty());
        assert!(conf.pid_blacklist.is_empty());
        assert!(conf.tid_whitelist.is_empty());
        // W17: no hard-coded 0xFF uid group, no fabricated thread whitelist.
        assert_eq!(conf.trace_uid_group, 0);
        assert_eq!(conf.trace_mode, crate::contract::consts::TRACE_COMMON);
        assert!(!conf.full_tname);
    }

    /// All-zero SConfig means "nothing configured" (legacy 0 sentinel).
    #[test]
    fn legacy_sconfig_zero_sentinels_write_nothing() {
        let conf = legacy_stack_config(&SConfig::default());
        assert!(conf.uid_whitelist.is_empty());
        assert!(conf.pid_whitelist.is_empty());
        assert!(conf.tid_blacklist.is_empty());
        assert!(conf.child_parent_pairs().is_empty());
    }

    #[test]
    fn effective_stack_config_prefers_with_stack_config() {
        let probe = dummy_probe(SConfig {
            uid: 1000,
            ..Default::default()
        });
        let module = StackProbeModule::new(probe, String::new());
        assert_eq!(module.effective_stack_config().uid_whitelist, vec![1000]);

        let conf = StackConfig {
            uid_whitelist: vec![2000],
            full_tname: true,
            ..Default::default()
        };
        let module = module.with_stack_config(conf);
        let effective = module.effective_stack_config();
        assert_eq!(effective.uid_whitelist, vec![2000]);
        assert!(effective.full_tname);
    }

    /// `--kill/--tkill` resolve from the config when set, from `with_signals`
    /// otherwise, regardless of builder order.
    #[test]
    fn kill_signals_fall_back_to_with_signals() {
        let module = StackProbeModule::new(dummy_probe(SConfig::default()), String::new());
        assert_eq!(module.effective_kill_signal(), 0);
        assert_eq!(module.effective_tkill_signal(), 0);

        // with_signals only.
        let module = module.with_signals(19, 6, false);
        assert_eq!(module.effective_kill_signal(), 19);
        assert_eq!(module.effective_tkill_signal(), 6);

        // Config values win when non-zero.
        let module = module.with_stack_config(StackConfig {
            kill_signal: 11,
            tkill_signal: 0,
            ..Default::default()
        });
        assert_eq!(module.effective_kill_signal(), 11);
        assert_eq!(module.effective_tkill_signal(), 6, "0 in config falls back");

        // Config first, then with_signals: config still wins.
        let module = StackProbeModule::new(dummy_probe(SConfig::default()), String::new())
            .with_stack_config(StackConfig {
                kill_signal: 11,
                tkill_signal: 6,
                ..Default::default()
            })
            .with_signals(19, 19, true);
        assert_eq!(module.effective_kill_signal(), 11);
        assert_eq!(module.effective_tkill_signal(), 6);
        assert!(module.auto_resume);
    }

    /// The map values the stack module writes come from the carrier, not from
    /// hard-coded constants (report W17/W8/W13 regression lock).
    #[test]
    fn written_map_values_come_from_the_stack_config() {
        let conf = StackConfig {
            uid_whitelist: vec![1000],
            pid_whitelist: vec![42],
            tid_blacklist: vec![7],
            tname_whitelist: vec!["Target".into()],
            full_tname: true,
            trace_uid_group: 0,
            kill_signal: 19,
            tkill_signal: 6,
            ..Default::default()
        };
        let module = StackProbeModule::new(dummy_probe(SConfig::default()), String::new())
            .with_stack_config(conf.clone());

        let effective = module.effective_stack_config();
        assert_eq!(
            effective.base_config(1234),
            crate::contract::types::ConfigEntry {
                stackplz_pid: 1234,
                thread_whitelist: 1,
            }
        );
        assert_eq!(
            effective.common_filter(false, 19, 6),
            crate::contract::types::CommonFilter {
                is_32bit: 0,
                trace_mode: crate::contract::consts::TRACE_COMMON,
                trace_uid_group: 0,
                signal: 19,
                tsignal: 6,
                no_filter_allow: 0,
            }
        );
        assert_eq!(
            effective.common_list_segments()[2],
            (crate::contract::consts::PID_WHITELIST_START, &[42u32][..])
        );
        assert_eq!(effective.child_parent_pairs(), vec![(42, 42)]);
        // `full_tname` is honoured end-to-end: only the user whitelist remains.
        let entries = effective.thread_filter_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, crate::contract::consts::THREAD_NAME_WHITELIST);
    }
}
