//! `stack` subcommand config and single-hook probe config.
//! Master-era `StackConfig` (`origin/master:user/config/config_stack.go:3-11`)
//! and `ProbeConfig` (`origin/master:user/config/config_hook.go:10-16`); dev's
//! carriers are `StackUprobeConfig` (`config_module.go:23`) and `UprobeArgs`
//! (`config_uprobe.go:9`).

use super::sconfig::{stack_filter_from, HookConfig, SConfig, StackFilter};
use crate::contract::consts::{
    PID_BLACKLIST_START, PID_WHITELIST_START, THREAD_NAME_BLACKLIST, THREAD_NAME_WHITELIST,
    TID_BLACKLIST_START, TID_WHITELIST_START, UID_BLACKLIST_START, UID_WHITELIST_START,
};
use anyhow::{bail, Result};

/// Flags for the `stack` subcommand. Master-era `StackConfig`
/// (`origin/master:user/config/config_stack.go`)
/// combined with the filter half of `ModuleConfig` (`config_module.go:750-800`).
///
/// Report W17: the stack module used to ignore `-t/--no-uid/--no-pid/--tname*/`
/// `--full-tname/-f` and hard-wrote `trace_uid_group = 0xFF`. All of those
/// filters now live here, and [`crate::module::StackProbeModule`] writes exactly
/// the maps upstream `MStack.updateFilter()` (`stack.go:381-390`) writes.
#[derive(Debug, Clone, Default)]
pub struct StackConfig {
    pub unwind_stack: bool,
    pub show_regs: bool,
    pub library: String,
    pub symbol: String,
    pub offset: u64,
    pub reg_name: String,
    pub config: String,
    /// `-w/--point` hook configs, e.g. `write[int,buf:128,int]`.
    pub hook_points: Vec<String>,

    // ---- filter lists (mirrors `ModuleConfig`, dev `config_module.go`) ----
    /// `-u/--uid` whitelist. Dev semantics: a list, so `-u 0` means "root only".
    pub uid_whitelist: Vec<u32>,
    /// `--no-uid` blacklist.
    pub uid_blacklist: Vec<u32>,
    /// `-p/--pid` whitelist. Also seeds `child_parent_map`.
    pub pid_whitelist: Vec<u32>,
    /// `--no-pid` blacklist.
    pub pid_blacklist: Vec<u32>,
    /// `-t/--tid` whitelist.
    pub tid_whitelist: Vec<u32>,
    /// `--no-tid` blacklist.
    pub tid_blacklist: Vec<u32>,
    /// `-t/--tname` whitelist (16-byte keys, exactly matched by the kernel).
    pub tname_whitelist: Vec<String>,
    /// `--no-tname` blacklist.
    pub tname_blacklist: Vec<String>,
    /// `--full-tname`: disable the built-in 18-entry default thread blacklist.
    pub full_tname: bool,

    /// `common_filter_t.trace_uid_group`. Bitmask of
    /// [`crate::contract::TraceGroup`] values set by `-n root/system/shell/`
    /// `app/iso`. `0` means "no group": in `ebpf/common/filtering.h` no
    /// `GROUP_*` branch matches, which is observably the same as dev's default
    /// `TraceGroup = GROUP_NONE`. (The old hard-coded `0xFF` traced every group
    /// and was report W17.)
    pub trace_uid_group: u32,
    /// `-b/--buffer`: perf ring buffer size in MiB (dev `GlobalConfig.Buffer`).
    pub buffer_mb: u32,
    /// `common_filter_t.trace_mode`. Dev's `ModuleConfig.GetCommonFilter()`
    /// (`config_module.go:983-996`) copies `SysCallConf.TraceMode`; a run that
    /// only starts the stack module has an empty `SyscallConfig`, so the value
    /// is `TRACE_COMMON(0)`. Kept as a field (instead of a hard-coded constant)
    /// so a caller that also runs the syscall module can pass `TRACE_ALL`.
    /// `stack.c` itself never reads this field.
    pub trace_mode: u32,
    /// `--kill` signal written into `common_filter_t.signal`.
    pub kill_signal: u32,
    /// `--tkill` signal written into `common_filter_t.tsignal`.
    pub tkill_signal: u32,
}

impl StackConfig {
    /// The default thread blacklist for this run.
    /// Mirrors `ModuleConfig.DefaultThreadBlacklist()`
    /// (`config_module.go:809-836`): the 18 dev entries (including the
    /// duplicated `"FinalizerDaemon"`) unless `--full-tname` is set, in which
    /// case the list is empty.
    pub fn default_thread_blacklist(&self) -> &'static [&'static str] {
        crate::config::thread_blacklist::default_thread_blacklist(self.full_tname)
    }

    /// Build the `thread_filter` map entries, matching
    /// `MStack.update_thread_filter()` (`stack.go:269-317`) order and values:
    ///
    /// 1. every default blacklist entry → `THREAD_NAME_BLACKLIST`
    /// 2. every `--no-tname` entry → `THREAD_NAME_BLACKLIST`
    /// 3. every `--tname` entry → `THREAD_NAME_WHITELIST`
    ///
    /// Keys are the fixed 16-byte `thread_name_t` (zero padded). Names longer
    /// than 16 bytes are rejected (upstream panics with
    /// `"[%s] thread name max len is 16"`; here it is a recoverable error).
    pub fn thread_filter_entries(&self) -> Result<Vec<(crate::contract::types::ThreadName, u32)>> {
        use crate::config::thread_blacklist::thread_filter_key;
        use crate::contract::types::ThreadName;

        let default_blacklist = self.default_thread_blacklist();
        let total =
            default_blacklist.len() + self.tname_blacklist.len() + self.tname_whitelist.len();
        let mut entries = Vec::with_capacity(total);
        for name in default_blacklist {
            entries.push((
                ThreadName {
                    name: thread_filter_key(name)?,
                },
                THREAD_NAME_BLACKLIST,
            ));
        }
        for name in &self.tname_blacklist {
            entries.push((
                ThreadName {
                    name: thread_filter_key(name)?,
                },
                THREAD_NAME_BLACKLIST,
            ));
        }
        for name in &self.tname_whitelist {
            entries.push((
                ThreadName {
                    name: thread_filter_key(name)?,
                },
                THREAD_NAME_WHITELIST,
            ));
        }
        Ok(entries)
    }

    /// The six `common_list` segments written by
    /// `MStack.update_common_filter()` (`stack.go:245-259`), in dev order:
    /// uid whitelist/blacklist, pid whitelist/blacklist, tid whitelist/
    /// blacklist.
    pub fn common_list_segments(&self) -> [(u32, &[u32]); 6] {
        [
            (UID_WHITELIST_START, &self.uid_whitelist),
            (UID_BLACKLIST_START, &self.uid_blacklist),
            (PID_WHITELIST_START, &self.pid_whitelist),
            (PID_BLACKLIST_START, &self.pid_blacklist),
            (TID_WHITELIST_START, &self.tid_whitelist),
            (TID_BLACKLIST_START, &self.tid_blacklist),
        ]
    }

    /// `child_parent_map` seed pairs (`key = pid`, `value = pid`) for the pid
    /// whitelist. Mirrors `MStack.update_child_parent()` (`stack.go:261-267`).
    pub fn child_parent_pairs(&self) -> Vec<(u32, u32)> {
        self.pid_whitelist.iter().map(|&pid| (pid, pid)).collect()
    }

    /// `base_config` value for this run. Mirrors `ModuleConfig.GetConfigMap()`
    /// (`config_module.go:999-1010`): `thread_whitelist = 1` **iff** a thread
    /// name was whitelisted. The default blacklist does not count (it is not a
    /// whitelist and it is applied unconditionally).
    pub fn base_config(&self, stackplz_pid: u32) -> crate::contract::types::ConfigEntry {
        crate::contract::types::ConfigEntry {
            stackplz_pid,
            thread_whitelist: if self.tname_whitelist.is_empty() {
                0
            } else {
                1
            },
        }
    }

    /// `common_filter` value for this run. Mirrors
    /// `ModuleConfig.GetCommonFilter()` (`config_module.go:983-996`):
    /// `trace_mode` from the config, `trace_uid_group` from the `-n` groups,
    /// `signal`/`tsignal` from `--kill`/`--tkill`.
    ///
    /// `no_filter_allow` stays `0`: the stack module always has an explicit
    /// uid-group mask / thread filter, so `should_trace()` must keep dev's
    /// whitelist-style default deny (see `bpf_common::write_common_filter`).
    /// `is_32bit` is the legacy `common_filter_t` field; the C side now decides
    /// register width per target task (`is_current_task_compat32()`), so this
    /// stays `0` (intentional, report §6.2).
    pub fn common_filter(
        &self,
        is_32bit: bool,
        signal: u32,
        tsignal: u32,
    ) -> crate::contract::types::CommonFilter {
        crate::contract::types::CommonFilter {
            is_32bit: if is_32bit { 1 } else { 0 },
            trace_mode: self.trace_mode,
            trace_uid_group: self.trace_uid_group,
            signal,
            tsignal,
            no_filter_allow: 0,
        }
    }
}

/// A single uprobe hook point. Master-era `ProbeConfig`
/// (`origin/master:user/config/config_hook.go`); dev's carrier is `UprobeArgs`
/// (`config_uprobe.go:9`).
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub sconfig: SConfig,
    /// Library display name from config (informational).
    pub lib_name: String,
    /// Resolved full library path on disk.
    pub library: String,
    /// Target symbol name (may be a synthetic random string when only an
    /// offset is supplied, because ebpfmanager requires a non-empty
    /// `AttachToFuncName`).
    pub symbol: String,
    /// Target file offset (0 if hooking by symbol).
    pub offset: u64,
}

impl ProbeConfig {
    /// Validate the hook point. Master-era `ProbeConfig.Check()` in
    /// `origin/master:user/config/config_hook.go:32-56`.
    ///
    /// Rules:
    /// - Library must exist on disk.
    /// - Exactly one of symbol / offset must be set (not both, not neither).
    /// - When only an offset is provided, fill `symbol` with a random 8-char
    ///   string (the manager still needs a non-empty `AttachToFuncName`).
    pub fn check(&mut self) -> Result<()> {
        if self.library.is_empty() {
            bail!("library path is empty");
        }
        if !std::path::Path::new(&self.library).exists() {
            bail!("library not found: {}", self.library);
        }
        let has_symbol = !self.symbol.is_empty();
        let has_offset = self.offset != 0;
        if !has_symbol && !has_offset {
            bail!("must set symbol or offset");
        }
        if has_symbol && has_offset {
            bail!("set symbol or offset, not both");
        }
        if !has_symbol {
            // ebpfmanager requires AttachToFuncName non-empty even when an
            // offset is used. Fill with a random 8-char ASCII lowercase name.
            use rand::distr::{Distribution, Uniform};
            let between = Uniform::new_inclusive(b'a', b'z').unwrap();
            let mut rng = rand::rng();
            let chars: String = (0..8).map(|_| between.sample(&mut rng) as char).collect();
            self.symbol = chars;
        }
        Ok(())
    }

    /// Produce the on-wire `StackFilter` for `filter_map`.
    /// Master-era `ProbeConfig.GetFilter()` (`origin/master:user/config/config_hook.go:58-66`).
    pub fn get_filter(&self) -> StackFilter {
        stack_filter_from(&self.sconfig)
    }

    /// Human-readable hook label, used for log lines.
    /// Master-era `ProbeConfig.Info()` (`origin/master:user/config/config_hook.go`).
    pub fn info(&self) -> String {
        if self.offset != 0 && !self.lib_name.is_empty() {
            format!("{} {}+0x{:x}", self.lib_name, self.symbol, self.offset)
        } else if self.offset != 0 {
            format!("0x{:x}", self.offset)
        } else {
            self.symbol.clone()
        }
    }
}

impl HookConfig for ProbeConfig {
    fn sconfig(&self) -> &SConfig {
        &self.sconfig
    }
    fn sconfig_mut(&mut self) -> &mut SConfig {
        &mut self.sconfig
    }
    fn info(&self) -> String {
        ProbeConfig::info(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::consts::TRACE_COMMON;

    fn tmp_lib() -> String {
        // Use the cargo manifest path as a stand-in existing file.
        env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml"
    }

    #[test]
    fn check_requires_symbol_or_offset() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: String::new(),
            offset: 0,
        };
        assert!(p.check().is_err());
    }

    #[test]
    fn check_rejects_both_symbol_and_offset() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: "open".into(),
            offset: 0x1000,
        };
        assert!(p.check().is_err());
    }

    #[test]
    fn check_fills_random_symbol_when_offset_only() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: String::new(),
            offset: 0x1000,
        };
        assert!(p.check().is_ok());
        assert_eq!(p.symbol.len(), 8);
        assert!(p.symbol.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn check_symbol_only_passes() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: "open".into(),
            offset: 0,
        };
        assert!(p.check().is_ok());
        assert_eq!(p.symbol, "open");
    }

    #[test]
    fn get_filter_produces_expected_bytes() {
        let p = ProbeConfig {
            sconfig: SConfig {
                uid: 5,
                pid: 7,
                tid_blacklist_mask: 0b1,
                tid_blacklist: [42, 0, 0, 0, 0],
                ..Default::default()
            },
            lib_name: String::new(),
            library: String::new(),
            symbol: "x".into(),
            offset: 0,
        };
        let f = p.get_filter();
        assert_eq!(f.uid, 5);
        assert_eq!(f.pid, 7);
        assert_eq!(f.tid_blacklist_mask, 0b1);
        assert_eq!(f.tid_blacklist[0], 42);
    }

    /// Report W8/W13/W17: by default the stack module writes exactly the 18 dev
    /// default blacklist entries (17 distinct; `FinalizerDaemon` is duplicated),
    /// all as `THREAD_NAME_BLACKLIST`, as 16-byte zero-padded keys.
    #[test]
    fn thread_filter_entries_use_the_eighteen_dev_defaults() {
        let conf = StackConfig::default();
        let entries = conf.thread_filter_entries().unwrap();
        assert_eq!(entries.len(), 18);
        assert!(entries.iter().all(|(_, v)| *v == THREAD_NAME_BLACKLIST));

        // Key layout matches `thread_name_t` (16 bytes, zero padded, no NUL
        // requirement) and equals the shared helper's key.
        let expected = crate::config::thread_blacklist::thread_filter_key("Profile Saver").unwrap();
        assert_eq!(entries[0].0.name, expected);
        assert_eq!(&entries[0].0.name[..13], b"Profile Saver");
        assert!(entries[0].0.name[13..].iter().all(|b| *b == 0));

        // The old 10-entry list's prefix entries are NOT written any more: the
        // kernel matches 16 bytes exactly (`filtering.h`), so they never fired.
        for (key, _) in &entries {
            assert_ne!(&key.name[..5], b"pool-");
            assert_ne!(&key.name[..6], b"Binder");
        }
        // Duplicate preserved for a pure diff against dev.
        let finalizer_keys = entries
            .iter()
            .filter(|(k, _)| &k.name[..11] == b"FinalizerDa")
            .count();
        assert_eq!(finalizer_keys, 2, "FinalizerDaemon appears twice in dev");
    }

    /// `--full-tname` (report W13) empties the default blacklist, but
    /// user-supplied `--no-tname` names are still written.
    #[test]
    fn full_tname_disables_defaults_but_keeps_user_names() {
        let conf = StackConfig {
            full_tname: true,
            ..Default::default()
        };
        assert!(conf.thread_filter_entries().unwrap().is_empty());

        let conf = StackConfig {
            full_tname: true,
            tname_blacklist: vec!["mali-event-hand".into()],
            ..Default::default()
        };
        let entries = conf.thread_filter_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, THREAD_NAME_BLACKLIST);
        assert_eq!(&entries[0].0.name[..15], b"mali-event-hand");
    }

    /// `--tname` → `THREAD_NAME_WHITELIST`, `--no-tname` →
    /// `THREAD_NAME_BLACKLIST`; dev order is defaults, blacklist, whitelist
    /// (`stack.go:277-317`).
    #[test]
    fn user_tname_lists_follow_dev_order_and_values() {
        let conf = StackConfig {
            tname_whitelist: vec!["TargetThread".into()],
            tname_blacklist: vec!["NoisyThread".into()],
            ..Default::default()
        };
        let entries = conf.thread_filter_entries().unwrap();
        assert_eq!(entries.len(), 20); // 18 defaults + 1 black + 1 white

        let black = &entries[18];
        assert_eq!(black.1, THREAD_NAME_BLACKLIST);
        assert_eq!(&black.0.name[..11], b"NoisyThread");

        let white = &entries[19];
        assert_eq!(white.1, THREAD_NAME_WHITELIST);
        assert_eq!(&white.0.name[..12], b"TargetThread");
    }

    /// Thread names longer than the 16-byte key are rejected instead of being
    /// silently truncated (the kernel compares all 16 bytes).
    #[test]
    fn overlong_thread_names_are_rejected() {
        let conf = StackConfig {
            tname_whitelist: vec!["0123456789abcdefg".into()],
            ..Default::default()
        };
        let err = conf.thread_filter_entries().unwrap_err();
        assert!(err.to_string().contains("max len is 16"), "{err}");
    }

    /// `base_config.thread_whitelist` is 1 iff a thread name was whitelisted
    /// (`config_module.go:1002-1004`); the default blacklist does not count.
    #[test]
    fn base_config_sets_thread_whitelist_only_for_tname_whitelist() {
        let pid = 4242;
        let plain = StackConfig::default();
        assert_eq!(plain.base_config(pid).stackplz_pid, pid);
        assert_eq!(plain.base_config(pid).thread_whitelist, 0);

        let black_only = StackConfig {
            tname_blacklist: vec!["Noisy".into()],
            ..Default::default()
        };
        assert_eq!(black_only.base_config(pid).thread_whitelist, 0);

        let white = StackConfig {
            tname_whitelist: vec!["Target".into()],
            ..Default::default()
        };
        assert_eq!(white.base_config(pid).thread_whitelist, 1);

        // `--full-tname` does not create a whitelist either.
        let full = StackConfig {
            full_tname: true,
            ..Default::default()
        };
        assert_eq!(full.base_config(pid).thread_whitelist, 0);
    }

    /// Report W17: `trace_uid_group` comes from the config (0 = no `-n` group),
    /// never the old hard-coded `0xFF`; `trace_mode` defaults to `TRACE_COMMON`
    /// (dev's stack-only run) and `signal`/`tsignal` come from `--kill/--tkill`.
    #[test]
    fn common_filter_carries_configured_groups_and_signals() {
        let conf = StackConfig::default();
        let f = conf.common_filter(false, 0, 0);
        assert_eq!(f.trace_uid_group, 0, "must not hard-code 0xFF (W17)");
        assert_eq!(f.trace_mode, TRACE_COMMON);
        assert_eq!(f.signal, 0);
        assert_eq!(f.tsignal, 0);
        assert_eq!(f.no_filter_allow, 0, "stack keeps dev default-deny");
        assert_eq!(f.is_32bit, 0);

        let conf = StackConfig {
            trace_uid_group: (crate::contract::TraceGroup::Root as u32)
                | (crate::contract::TraceGroup::App as u32),
            trace_mode: crate::contract::consts::TRACE_ALL,
            kill_signal: 19,
            tkill_signal: 6,
            ..Default::default()
        };
        let f = conf.common_filter(false, 19, 6);
        assert_eq!(f.trace_uid_group, 0b10010);
        assert_eq!(f.trace_mode, crate::contract::consts::TRACE_ALL);
        assert_eq!(f.signal, 19);
        assert_eq!(f.tsignal, 6);
    }

    /// The six `common_list` segments keep dev's offsets and order
    /// (`config_module.go` `START_OFFSETS` / `stack.go:245-259`).
    #[test]
    fn common_list_segments_match_dev_offsets_and_lists() {
        let conf = StackConfig {
            uid_whitelist: vec![1000],
            uid_blacklist: vec![1001],
            pid_whitelist: vec![2000],
            pid_blacklist: vec![2001],
            tid_whitelist: vec![3000],
            tid_blacklist: vec![3001],
            ..Default::default()
        };
        let segments = conf.common_list_segments();
        assert_eq!(segments[0], (UID_WHITELIST_START, &[1000u32][..]));
        assert_eq!(segments[1], (UID_BLACKLIST_START, &[1001u32][..]));
        assert_eq!(segments[2], (PID_WHITELIST_START, &[2000u32][..]));
        assert_eq!(segments[3], (PID_BLACKLIST_START, &[2001u32][..]));
        assert_eq!(segments[4], (TID_WHITELIST_START, &[3000u32][..]));
        assert_eq!(segments[5], (TID_BLACKLIST_START, &[3001u32][..]));
    }

    /// `child_parent_map` seeds every pid whitelist member as its own parent
    /// (`stack.go:261-267`); the C fork handler expands descendants.
    #[test]
    fn child_parent_pairs_seed_the_pid_whitelist() {
        assert!(StackConfig::default().child_parent_pairs().is_empty());
        let conf = StackConfig {
            pid_whitelist: vec![11, 22],
            pid_blacklist: vec![33],
            ..Default::default()
        };
        assert_eq!(conf.child_parent_pairs(), vec![(11, 11), (22, 22)]);
    }
}
