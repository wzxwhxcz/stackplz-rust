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
use crate::module::syscall_tracepoint::{account_lost, poll_until_stop};
use crate::signal::{
    auto_resume_after_event, record_stopped_after_event, ConsoleResume, SignalManager,
};
use anyhow::{anyhow, bail, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
    pub fn run(self, logger: Arc<Logger>, resume: Arc<ConsoleResume>) -> Result<()> {
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
        //
        //    Default-deny safety: `write_common_filter` always writes
        //    `no_filter_allow = 0` (`src/ebpf/bpf_common.rs:300`), so
        //    `should_trace()` keeps the whitelist-style default deny. That is
        //    safe only because this module runs when the user explicitly
        //    configured filters: `src/cli/mod.rs` starts the stack module only
        //    when it sees uprobe hook points (-w/-c), and `StackConfig`'s
        //    uid/pid/tid/tname lists always come from explicit CLI filters
        //    (`uid_whitelist` etc.), never from defaults. If the user configured
        //    no filter at all, they should use the syscall module instead: its
        //    `to_common_filter_bytes()` writes `no_filter_allow = 1` when
        //    `has_no_user_filter()` (`src/config/syscall.rs:226-229`).
        //    See `ebpf/common/filtering.h:109-115`: only
        //    `no_filter_allow == 1` falls back to master's "0 = no filtering";
        //    writing 0 here means no fallback → default deny.
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
        // Keep every link alive until the poll loop ends: `Link::drop` calls
        // `bpf_link__destroy`, so a per-iteration local would detach the uprobe
        // immediately. A Vec (not mem::forget) also detaches them on `?` unwind.
        let mut links = Vec::with_capacity(self.hook_points.len());
        for (i, point) in self.hook_points.iter().enumerate() {
            // `ebpf/stack.c` defines `probe_stack_<i>` only for `i < 6`, so a
            // point beyond that has no program to attach.
            if i >= crate::config::stack::MAX_UPROBE_PROGRAMS {
                return Err(anyhow!(
                    "{NAME}: {} hook points exceed the {} uprobe programs in the BPF object",
                    self.hook_points.len(),
                    crate::config::stack::MAX_UPROBE_PROGRAMS
                ));
            }
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

            links.push(prog.attach_uprobe(false, -1, library, attach_offset as usize)?);
            logger.println(&format!(
                "{NAME}\tattached {prog_name} to {library} at offset 0x{attach_offset:x}"
            ));
        }

        let attached = links.len();
        if attached == 0 {
            return Err(anyhow!("{NAME}: no uprobe programs attached"));
        }

        // 5. Poll the events perf buffer.
        logger.println(&format!("{NAME}\tpolling events (attached={attached})..."));

        // The perf buffer callback needs access to hook_points for rendering.
        // We share them via Arc so the closure can read them.
        let hook_points = Arc::new(self.hook_points);
        let render_logger = logger.clone();
        // Round 11 / Q1: the global `--dumphex` flag, copied out so the
        // `move` callback below can carry it without moving `conf`.
        let dump_hex = conf.dump_hex;

        let events_map = obj
            .maps()
            .find(|m| m.name() == "events")
            .ok_or_else(|| anyhow!("cannot find events map"))?;

        // `-b/--buffer` in MiB → 4 KiB pages (dev `GlobalConfig.Buffer`).
        let pages = super::perf_pages(conf.buffer_mb)?;
        let lost_logger = logger.clone();
        let lost_total = Arc::new(AtomicU64::new(0));
        let lost_total_cb = Arc::clone(&lost_total);
        // Round 7 / F4 / G3: before `--auto` resumes the event pid, record it
        // as stopped when the kill signal is SIGSTOP (Go `event_uprobe.go:58-60`
        // records, `:77-78` resumes). Round 9 / H24: the manager is shared
        // (`Arc<Mutex<…>>`) between this perf callback and the stdin `c`
        // resume thread spawned below.
        let auto_resume = self.auto_resume;
        let sig_mgr = Arc::new(Mutex::new(SignalManager::new()));
        let sig_mgr_cb = Arc::clone(&sig_mgr);
        let sig_mgr_resume = Arc::clone(&sig_mgr_cb);
        let pb = libbpf_rs::PerfBufferBuilder::new(&events_map)
            .pages(pages)
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                match render_uprobe_event(data, &hook_points, dump_hex) {
                    Ok((line, pid)) => {
                        render_logger.println(&line);
                        {
                            let mut g = sig_mgr_cb.lock().unwrap_or_else(|p| p.into_inner());
                            record_stopped_after_event(&mut g, kill_signal, pid);
                        }
                        auto_resume_after_event(
                            &mut |pid| {
                                // resume_one prints its own diagnostics;
                                // nothing to propagate from a perf callback.
                                let mut g =
                                    sig_mgr_resume.lock().unwrap_or_else(|p| p.into_inner());
                                let _ = g.resume_one(pid);
                            },
                            auto_resume,
                            pid,
                        );
                    }
                    Err(e) => render_logger.println(&format!("{NAME}\t{e}")),
                }
            })
            .lost_cb(move |cpu: i32, count: u64| {
                account_lost(&lost_total_cb, &lost_logger, NAME, cpu, count);
            })
            .build()?;

        // Round 9 / H24: stdin `c` resumes stopped pids (Go `root.go:429`).
        // Round 11 / R11-5: the console-resume thread moved up to `run_modules`
        // — one shared reader for all modules, so one `c` resumes every
        // module. Register this module's manager with that shared reader.
        resume.register(Arc::clone(&sig_mgr));

        // Round 10 / K1: a poll error only stops this reader — Go logs it
        // and shuts down normally (`imodule.go:250-258`); it never fails the
        // run, so the summary below still prints. (Round 9 / H1 had this as
        // `?`, which turned one transient read error into a dead session.)
        poll_until_stop(
            NAME,
            || pb.poll(std::time::Duration::from_millis(100)),
            &logger,
            crate::cli::interrupted,
        );
        logger.println(&format!("{NAME}\tshutting down"));
        logger.println(&format!(
            "TotalLost => {}",
            lost_total.load(Ordering::Relaxed)
        ));
        drop(links);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run(self, _logger: Arc<Logger>, _resume: Arc<ConsoleResume>) -> Result<()> {
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

/// Render a raw perf record as a human-readable uprobe event line, plus the
/// event pid (`EventContext.pid`) for `--auto` resume (round 7 / F4).
/// Non-uprobe records carry pid 0, which never resumes.
///
/// `dump_hex` is the global `--dumphex` flag from `StackConfig` (round 11 /
/// Q1); the caller reads it off `self.effective_stack_config()`.
///
/// Mirrors `UprobeEvent.ParseContext` + `String()` in Go.
#[cfg(target_os = "linux")]
fn render_uprobe_event(
    raw: &[u8],
    hook_points: &[UprobeArgs],
    dump_hex: bool,
) -> Result<(String, u32)> {
    use crate::contract::decode::{decode_perf_record, PerfRecord};

    let rec = decode_perf_record(raw)?;
    match rec {
        PerfRecord::UprobeEnter(mut e) => {
            let pid = e.context.pid;
            let point = hook_points
                .get(e.point_key as usize)
                .ok_or_else(|| anyhow!("point_key {} out of range", e.point_key))?;
            let line = crate::event::render::render_uprobe_event(&mut e, point, dump_hex)?;
            Ok((line, pid))
        }
        _ => bail!(
            "non-uprobe event in the uprobe stream ({} bytes)",
            raw.len()
        ),
    }
}

/// Full signal-name table (Go's `util.ParseSignal(name)` lookup map: all 35
/// names, sorted by signal number; synonyms share one entry — CHLD=CLD,
/// IO=POLL, IOT=ABRT, SYS=UNUSED). Shared by the lenient [`parse_signal_name`]
/// and the strict dev-config [`parse_signal_name_strict`].
pub const SIGNAL_TABLE: [(&str, u32); 35] = [
    ("HUP", 1),
    ("INT", 2),
    ("QUIT", 3),
    ("ILL", 4),
    ("TRAP", 5),
    ("ABRT", 6),
    ("IOT", 6),
    ("BUS", 7),
    ("FPE", 8),
    ("KILL", 9),
    ("USR1", 10),
    ("SEGV", 11),
    ("USR2", 12),
    ("PIPE", 13),
    ("ALRM", 14),
    ("TERM", 15),
    ("STKFLT", 16),
    ("CHLD", 17),
    ("CLD", 17),
    ("CONT", 18),
    ("STOP", 19),
    ("TSTP", 20),
    ("TTIN", 21),
    ("TTOU", 22),
    ("URG", 23),
    ("XCPU", 24),
    ("XFSZ", 25),
    ("VTALRM", 26),
    ("PROF", 27),
    ("WINCH", 28),
    ("IO", 29),
    ("POLL", 29),
    ("PWR", 30),
    ("SYS", 31),
    ("UNUSED", 31),
];

/// Look up a normalized (uppercase, `SIG` prefix stripped) signal name.
fn signal_from_name(normalized: &str) -> Option<u32> {
    SIGNAL_TABLE
        .iter()
        .find(|(name, _)| *name == normalized)
        .map(|(_, num)| *num)
}

/// Parse a signal name (e.g. "SIGSTOP", "SIGABRT") to its numeric value.
/// Returns 0 for empty/unrecognized strings.
/// Mirrors Go's `util.ParseSignal(name)`. Unknown names still return 0,
/// exactly like Go (map lookup miss yields the zero value) — documented
/// upstream behaviour, not an error.
pub fn parse_signal_name(name: &str) -> u32 {
    if name.is_empty() {
        return 0;
    }
    let upper = name.to_uppercase();
    let upper = upper.strip_prefix("SIG").unwrap_or(&upper);
    match signal_from_name(upper) {
        Some(num) => num,
        None => {
            // Try parsing as a raw number.
            name.parse::<u32>().unwrap_or(0)
        }
    }
}

/// Strict variant for the dev `-c` config (`dev_point_to_uprobe_args`): an
/// unknown name bails instead of silently meaning no-signal (0). The numeric
/// fallback and lowercase acceptance are kept (documented extension vs Go).
pub fn parse_signal_name_strict(name: &str) -> Result<u32> {
    if name.is_empty() {
        return Ok(0);
    }
    let upper = name.to_uppercase();
    let upper = upper.strip_prefix("SIG").unwrap_or(&upper);
    if let Some(num) = signal_from_name(upper) {
        return Ok(num);
    }
    if let Ok(num) = name.parse::<u32>() {
        return Ok(num);
    }
    bail!("unknown signal: {name}");
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
        // Go `util.ParseSignal` full table: all 35 names, one assertion each.
        for (name, num) in [
            ("HUP", 1),
            ("INT", 2),
            ("QUIT", 3),
            ("ILL", 4),
            ("TRAP", 5),
            ("ABRT", 6),
            ("IOT", 6),
            ("BUS", 7),
            ("FPE", 8),
            ("KILL", 9),
            ("USR1", 10),
            ("SEGV", 11),
            ("USR2", 12),
            ("PIPE", 13),
            ("ALRM", 14),
            ("TERM", 15),
            ("STKFLT", 16),
            ("CHLD", 17),
            ("CLD", 17),
            ("CONT", 18),
            ("STOP", 19),
            ("TSTP", 20),
            ("TTIN", 21),
            ("TTOU", 22),
            ("URG", 23),
            ("XCPU", 24),
            ("XFSZ", 25),
            ("VTALRM", 26),
            ("PROF", 27),
            ("WINCH", 28),
            ("IO", 29),
            ("POLL", 29),
            ("PWR", 30),
            ("SYS", 31),
            ("UNUSED", 31),
        ] {
            assert_eq!(parse_signal_name(name), num, "{name}");
            assert_eq!(parse_signal_name(&format!("SIG{name}")), num, "SIG{name}");
        }
        assert_eq!(parse_signal_name("sigstop"), 19); // case-insensitive
        assert_eq!(parse_signal_name("quit"), 3); // no SIG prefix
        assert_eq!(parse_signal_name(""), 0);
        assert_eq!(parse_signal_name("SIGUNKNOWN"), 0); // Go's silent 0
        assert_eq!(parse_signal_name("42"), 42); // raw number
    }

    /// R11-1: the strict dev-config variant shares the same table but bails on
    /// unknown names instead of returning 0 (CLI `--kill`/`--tkill` keep the
    /// lenient parse).
    #[test]
    fn signal_table_covers_all_35_names_and_strict_rejects_unknown() {
        assert_eq!(SIGNAL_TABLE.len(), 35);
        let mut seen = std::collections::HashSet::new();
        for (name, _) in SIGNAL_TABLE {
            assert!(seen.insert(name), "duplicate name {name}");
        }
        // Strict keeps the lowercase / SIG-prefix / numeric conveniences.
        assert_eq!(parse_signal_name_strict("sigstop").unwrap(), 19);
        assert_eq!(parse_signal_name_strict("SIGSTOP").unwrap(), 19);
        assert_eq!(parse_signal_name_strict("19").unwrap(), 19);
        assert_eq!(parse_signal_name_strict("").unwrap(), 0);
        // Unknown name -> loud error, not silent 0.
        let err = parse_signal_name_strict("SIGBOGUS").unwrap_err();
        assert!(format!("{err}").contains("unknown signal"), "{err}");
        // The lenient path is unchanged.
        assert_eq!(parse_signal_name("SIGBOGUS"), 0);
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

    /// Round 9 / H4 helpers: a minimal raw perf record (`EventContext` +
    /// fixed-prefix TLVs) for one event id.
    #[cfg(target_os = "linux")]
    fn foreign_raw_record(eventid: u32, first_u32: u32) -> Vec<u8> {
        use crate::contract::types::EventContext;
        fn tlv_u32(raw: &mut Vec<u8>, idx: u8, v: u32) {
            raw.push(idx);
            raw.extend_from_slice(&v.to_le_bytes());
        }
        fn tlv_u64(raw: &mut Vec<u8>, idx: u8, v: u64) {
            raw.push(idx);
            raw.extend_from_slice(&v.to_le_bytes());
        }
        let ctx = EventContext {
            ts: 0x1000,
            eventid,
            host_tid: 1,
            host_pid: 2,
            tid: 3,
            pid: 4,
            uid: 5,
            comm: [0u8; 16],
            argnum: 0,
            padding: [0; 7],
        };
        let mut raw = bytemuck::bytes_of(&ctx).to_vec();
        tlv_u32(&mut raw, 0, first_u32);
        tlv_u64(&mut raw, 1, 0xa);
        tlv_u64(&mut raw, 2, 0xb);
        tlv_u64(&mut raw, 3, 0xc);
        raw
    }

    /// Round 9 / H4: a syscall record in the uprobe stream fails (bails),
    /// exactly like an uprobe record fails in the syscall stream — a crossed
    /// stream is a failure on both sides, never a benign log line.
    #[test]
    #[cfg(target_os = "linux")]
    fn foreign_syscall_record_fails_in_uprobe_stream() {
        let raw = foreign_raw_record(456, 63); // SYSCALL_ENTER, sysno 63
        let err = render_uprobe_event(&raw, &[], false).unwrap_err();
        assert!(format!("{err:#}").contains("non-uprobe event"), "{err:#}");
    }

    /// Round 9 / H4 (syscall side of the pair): an uprobe record in the
    /// syscall stream fails too. `render.rs` itself is untouched; this test
    /// locks the pair from the stack side.
    #[test]
    #[cfg(target_os = "linux")]
    fn foreign_uprobe_record_fails_in_syscall_stream() {
        let raw = foreign_raw_record(458, 1); // UPROBE_ENTER, point_key 1
        let mut rec = crate::contract::decode::decode_perf_record(&raw).unwrap();
        let table = crate::config::SyscallPointTable::empty();
        let err = crate::event::render::render_syscall_event(&table, &mut rec, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("uprobe event in the syscall stream"),
            "{err:#}"
        );
    }
}
