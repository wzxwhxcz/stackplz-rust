//! `syscall` subcommand config. Mirrors `ModuleConfig` + `SyscallConfig` (`config_module.go`).

use super::syscall_points::SyscallPointTable;
use crate::contract::consts::{TRACE_ALL, TRACE_COMMON};
use anyhow::{bail, Result};

/// Syscall tracepoint module configuration. Mirrors `ModuleConfig` + `SyscallConfig`.
#[derive(Debug, Clone)]
pub struct SyscallConfig {
    /// The syscall point table (embedded `config_syscall_*.json` or a `-c`
    /// override). This is what `update_sysenter_point_args` /
    /// `update_sysexit_point_args` write into the BPF maps — the field whose
    /// absence made the module emit zero events (report W1/F1).
    pub point_table: SyscallPointTable,
    /// `common_filter_t.trace_mode`, decided by `-s`/`--no-syscall`
    /// (`TRACE_COMMON` gates on the sysno whitelist, `TRACE_ALL` does not).
    pub trace_mode: u32,
    /// Explicit override for [`SyscallConfig::trace_mode`]; `None` derives the
    /// mode from whether a whitelist is present (hand-built configs/tests).
    pub trace_mode_override: Option<u32>,
    /// `common_filter_t.trace_uid_group`: uid-group mask from `-n`.
    pub trace_uid_group: u32,
    /// `-b/--buffer`: perf ring buffer size in MiB (dev `GlobalConfig.Buffer`).
    pub buffer_mb: u32,
    /// `common_filter_t.signal` / `tsignal` from `--kill` / `--tkill`.
    pub kill_signal: u32,
    pub tkill_signal: u32,
    pub auto_resume: bool,

    // Filter lists (mirrors ModuleConfig fields)
    pub debug: bool,
    pub uid_whitelist: Vec<u32>,
    pub uid_blacklist: Vec<u32>,
    pub pid_whitelist: Vec<u32>,
    pub pid_blacklist: Vec<u32>,
    pub tid_whitelist: Vec<u32>,
    pub tid_blacklist: Vec<u32>,
    pub tname_whitelist: Vec<String>,
    pub tname_blacklist: Vec<String>,
    /// `--full-tname`: disable the 18-entry default thread blacklist.
    pub full_tname: bool,

    // Syscall-specific config (mirrors SyscallConfig fields)
    pub sys_whitelist: Vec<u32>,
    pub sys_blacklist: Vec<u32>,
    pub dump_hex: bool,
}

impl SyscallConfig {
    /// Round 11 / P2: reject a config whose `buffer_mb` was never set (0) —
    /// the `StackConfig::validate` twin (K2, round 10). Without it, syscall
    /// `-b 0` walks all the way to `run()` and fails there with `perf_pages`'
    /// generic "buffer size must be at least 1 MiB", far from the
    /// construction point and without saying the buffer was never set.
    pub fn validate(&self) -> Result<()> {
        if self.buffer_mb == 0 {
            bail!("buffer size is not set: pass -b/--buffer (MiB, default 8)");
        }
        Ok(())
    }

    pub fn new() -> Self {
        Self::with_table(SyscallPointTable::empty())
    }

    /// Build a config around a point table (the normal path: the table is the
    /// embedded dev table, or a `-c/--config` override).
    pub fn with_table(point_table: SyscallPointTable) -> Self {
        SyscallConfig {
            point_table,
            trace_mode: TRACE_ALL,
            trace_mode_override: None,
            trace_uid_group: 0,
            buffer_mb: 8,
            kill_signal: 0,
            tkill_signal: 0,
            auto_resume: false,
            debug: false,
            uid_whitelist: Vec::new(),
            uid_blacklist: Vec::new(),
            pid_whitelist: Vec::new(),
            pid_blacklist: Vec::new(),
            tid_whitelist: Vec::new(),
            tid_blacklist: Vec::new(),
            tname_whitelist: Vec::new(),
            tname_blacklist: Vec::new(),
            full_tname: false,
            sys_whitelist: Vec::new(),
            sys_blacklist: Vec::new(),
            dump_hex: false,
        }
    }

    /// Human-readable hook label, used for log lines.
    /// Mirrors `SyscallConfig.Info()` (`config_module.go:738-750`), which lists
    /// the whitelist/blacklist by name.
    pub fn info(&self) -> String {
        let name_of = |nr: u32| {
            self.point_table
                .by_nr(nr)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| nr.to_string())
        };
        let whitelist: Vec<String> = self.sys_whitelist.iter().map(|nr| name_of(*nr)).collect();
        let blacklist: Vec<String> = self.sys_blacklist.iter().map(|nr| name_of(*nr)).collect();
        format!(
            "whitelist:[{}];blacklist:[{}]",
            whitelist.join(","),
            blacklist.join(",")
        )
    }

    /// Convert to base_config map value (C struct bytes).
    /// Mirrors `config_entry_t` in `src/types.h`:
    /// ```c
    /// typedef struct config_entry {
    ///     u32 stackplz_pid;
    ///     u32 thread_whitelist;
    /// } config_entry_t;
    /// ```
    pub fn to_base_config_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        // stackplz_pid: current process ID
        bytes.extend_from_slice(&std::process::id().to_ne_bytes());
        // thread_whitelist: 1 if whitelist mode is enabled, 0 otherwise
        let thread_whitelist: u32 = if !self.tname_whitelist.is_empty() {
            1
        } else {
            0
        };
        bytes.extend_from_slice(&thread_whitelist.to_ne_bytes());
        bytes
    }

    /// True when the user asked for no uid/pid/tid/thread filtering at all, i.e.
    /// every inclusion *and* exclusion list is empty and no uid group is traced.
    ///
    /// Used to restore master's "0 = no filtering" semantics on the eBPF side:
    /// `should_trace()` ends in an unconditional `return 0` (default deny), so
    /// without this fallback a run with no filter flags produces zero events
    /// while master traced everything (report §4.2 / §6.2).
    ///
    /// `default_thread_blacklist()` entries are deliberately NOT counted: they
    /// are applied unconditionally by the user side and are not a user choice.
    ///
    /// Keep the field set in sync with `StackConfig::has_no_user_filter`
    /// (`src/config/stack.rs:218`) — the two predicates are mirrors
    /// (round 14 / R14-4); adding a field to one side without the other turns
    /// the twin predicate-matrix tests red.
    pub fn has_no_user_filter(&self) -> bool {
        self.uid_whitelist.is_empty()
            && self.uid_blacklist.is_empty()
            && self.pid_whitelist.is_empty()
            && self.pid_blacklist.is_empty()
            && self.tid_whitelist.is_empty()
            && self.tid_blacklist.is_empty()
            && self.tname_whitelist.is_empty()
            && self.tname_blacklist.is_empty()
            // trace_uid_group is written as 0 by this config (see below).
            && self.trace_uid_group() == 0
    }

    /// `common_filter_t.trace_uid_group` for this config: the `-n` uid-group
    /// mask (dev `ModuleConfig.GetCommonFilter`, `config_module.go:991-993`).
    /// `-n root` sets `TraceGroup::Root`, and `should_trace()` then admits that
    /// group (`ebpf/common/filtering.h:91-105`).
    pub fn trace_uid_group(&self) -> u32 {
        self.trace_uid_group
    }

    /// `common_filter_t.trace_mode` for this config.
    ///
    /// Mirrors `SyscallConfig.TraceMode` (dev `config_module.go:441`),
    /// but with the values the C side actually compares against
    /// (`ebpf/common/consts.h`): `TRACE_COMMON(0)` makes `ebpf/syscall.c:93,212`
    /// gate on the per-sysno whitelist in `common_list`, `TRACE_ALL(1)` skips
    /// that gate.
    ///
    /// A non-empty `sys_whitelist` is exactly the case where the user asked for
    /// a syscall subset (`-s <nr>,...`), so it is the only case that may switch
    /// the gate on. `-s all` — and no `-s` at all — leave `sys_whitelist` empty
    /// and therefore trace every syscall (`--no-syscall` keeps working because
    /// the blacklist is checked in both modes).
    pub fn trace_mode(&self) -> u32 {
        // The explicit value is what `-s`/`--no-syscall` decided (dev computes
        // it in `Parse_Syscall`); the derivation below is the fallback for
        // configs built by hand (tests, stack module).
        if let Some(explicit) = self.trace_mode_override {
            return explicit;
        }
        if self.sys_whitelist.is_empty() {
            TRACE_ALL
        } else {
            TRACE_COMMON
        }
    }

    /// Convert to common_filter map value (C struct bytes).
    /// Mirrors `common_filter_t` in `ebpf/types.h`:
    /// ```c
    /// typedef struct common_filter {
    ///     u32 is_32bit;
    ///     u32 trace_mode;
    ///     u32 trace_uid_group;
    ///     u32 signal;
    ///     u32 tsignal;
    ///     u32 no_filter_allow;
    /// } common_filter_t;
    /// ```
    pub fn to_common_filter_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);

        // is_32bit: 0 for 64-bit (ARM64/x86_64)
        bytes.extend_from_slice(&0u32.to_ne_bytes());

        // trace_mode: `TRACE_ALL` (1) unless a sysno whitelist is present, in
        // which case `TRACE_COMMON` (0) makes `ebpf/syscall.c` enforce it.
        // See `trace_mode()`; the C side compares against `TRACE_COMMON` only.
        let trace_mode: u32 = self.trace_mode();
        bytes.extend_from_slice(&trace_mode.to_ne_bytes());

        // trace_uid_group: UID filtering flags (not used in current implementation)
        bytes.extend_from_slice(&self.trace_uid_group().to_ne_bytes());

        // signal: signal sent on a hook hit (`--kill`); 0 = none
        bytes.extend_from_slice(&self.kill_signal.to_ne_bytes());

        // tsignal: signal sent to the thread (`--tkill`); 0 = none
        bytes.extend_from_slice(&self.tkill_signal.to_ne_bytes());

        // no_filter_allow: 1 when no filter was configured, so should_trace()
        // falls back to master's "0 = no filtering" behaviour.
        let no_filter_allow: u32 = if self.has_no_user_filter() { 1 } else { 0 };
        bytes.extend_from_slice(&no_filter_allow.to_ne_bytes());

        bytes
    }

    /// Default thread name blacklist. Mirrors `DefaultThreadBlacklist()`
    /// (`config_module.go:809-836`): 18 entries, empty when `--full-tname`.
    pub fn default_thread_blacklist(&self) -> &'static [&'static str] {
        crate::config::default_thread_blacklist(self.full_tname)
    }
}

impl Default for SyscallConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading back a u32 written with `to_ne_bytes`.
    fn u32_at(bytes: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap())
    }

    /// Round 14 / R14-4: `has_no_user_filter` is a 9-field predicate mirrored
    /// between `SyscallConfig` and `StackConfig` (see `src/config/stack.rs`).
    /// Every field must count; a future field added on one side only turns the
    /// twin stack-side matrix red. The byte-level `no_filter_allow`
    /// consequence is covered by `common_filter_bytes_keep_legacy_offsets`
    /// and the CLI tests in `src/cli/syscall_cmd.rs`.
    #[test]
    fn has_no_user_filter_predicate_matrix() {
        // All-empty → true (no filter flags, R13-5 fallback).
        assert!(SyscallConfig::new().has_no_user_filter());

        let mutators: Vec<fn(&mut SyscallConfig)> = vec![
            |c| c.uid_whitelist.push(1000),
            |c| c.uid_blacklist.push(0),
            |c| c.pid_whitelist.push(1234),
            |c| c.pid_blacklist.push(1),
            |c| c.tid_whitelist.push(4321),
            |c| c.tid_blacklist.push(2),
            |c| c.tname_whitelist.push("RenderThread".to_string()),
            |c| c.tname_blacklist.push("android.bg".to_string()),
            |c| c.trace_uid_group = 0b10010,
        ];

        for mutate in mutators {
            let mut conf = SyscallConfig::new();
            mutate(&mut conf);
            assert!(
                !conf.has_no_user_filter(),
                "a configured filter must disable the permissive fallback"
            );
        }
    }

    /// The default thread blacklist is applied unconditionally by the user side
    /// and is not a user filter, so it must not disable the fallback.
    #[test]
    fn default_thread_blacklist_does_not_count_as_a_filter() {
        let conf = SyscallConfig::new();
        assert!(!conf.default_thread_blacklist().is_empty());
        assert!(conf.has_no_user_filter());
    }

    /// Byte layout contract with `common_filter_t` in ebpf/types.h: the five
    /// legacy fields keep their offsets and the new flag is appended at 20.
    #[test]
    fn common_filter_bytes_keep_legacy_offsets() {
        let conf = SyscallConfig::new();
        let bytes = conf.to_common_filter_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(u32_at(&bytes, 0), 0, "is_32bit");
        assert_eq!(u32_at(&bytes, 4), TRACE_ALL, "trace_mode");
        assert_eq!(u32_at(&bytes, 8), 0, "trace_uid_group");
        assert_eq!(u32_at(&bytes, 12), 0, "signal");
        assert_eq!(u32_at(&bytes, 16), 0, "tsignal");
        assert_eq!(u32_at(&bytes, 20), 1, "no_filter_allow");
        assert_eq!(conf.trace_uid_group(), u32_at(&bytes, 8));
    }

    /// Regression test for report §5.1: `trace_mode` must be one of the two
    /// contract values `TRACE_COMMON(0)`/`TRACE_ALL(1)` understood by
    /// `ebpf/syscall.c:93,212`, never the old ad-hoc `1`/`2`. With `-s 63` the
    /// sysno whitelist gate must switch on, i.e. exactly `TRACE_COMMON == 0`
    /// (the old code wrote 1 or 2 here, so the gate never fired).
    #[test]
    fn sys_whitelist_writes_trace_common() {
        let mut conf = SyscallConfig::new();
        conf.sys_whitelist.push(63);

        assert_eq!(
            TRACE_COMMON, 0,
            "ebpf/syscall.c gates on `trace_mode == TRACE_COMMON`"
        );
        assert_eq!(conf.trace_mode(), TRACE_COMMON);

        let written = u32_at(&conf.to_common_filter_bytes(), 4);
        assert_eq!(written, TRACE_COMMON, "trace_mode for `-s 63`");
        // The values that used to be written (1 = "whitelist", 2 = "blacklist")
        // are not part of the contract: 1 is TRACE_ALL, 2 means nothing.
        assert_ne!(written, TRACE_ALL, "1 means TRACE_ALL, the opposite gate");
        assert_ne!(written, 2, "2 is not part of the trace_mode contract");
        assert!([TRACE_COMMON, TRACE_ALL].contains(&written));
    }

    /// `-s all` (and no `-s` at all) leave `sys_whitelist` empty, so the eBPF
    /// side must not gate syscalls: `TRACE_ALL`. `--no-syscall` still applies
    /// because the C side checks the blacklist in both modes.
    #[test]
    fn empty_sys_whitelist_writes_trace_all() {
        let conf = SyscallConfig::new();
        assert!(conf.sys_whitelist.is_empty());
        assert_eq!(conf.trace_mode(), TRACE_ALL);

        let written = u32_at(&conf.to_common_filter_bytes(), 4);
        assert_eq!(written, TRACE_ALL, "trace_mode without a sysno whitelist");
        assert!([TRACE_COMMON, TRACE_ALL].contains(&written));
    }

    /// A blacklist-only config must not accidentally switch the whitelist gate
    /// on, otherwise every syscall would be denied before the blacklist runs.
    #[test]
    fn sys_blacklist_alone_does_not_enable_the_whitelist_gate() {
        let mut conf = SyscallConfig::new();
        conf.sys_blacklist.push(63);
        assert_eq!(conf.trace_mode(), TRACE_ALL);
        assert_eq!(u32_at(&conf.to_common_filter_bytes(), 4), TRACE_ALL);
    }
}
