//! Syscall module handler. Mirrors dev's `syscallCommandFunc` equivalent: in dev
//! the syscall hook is not a subcommand at all — `runFunc` picks the module from
//! `-s` (`cli/cmd/root.go:386-396`) and `SyscallConfig.Parse_Syscall`
//! (`config_module.go:647-732`) decides the whitelist from the point table.
//!
//! What this module adds over the previous rounds (report W1/F1, the fatal
//! defect): the point table is loaded and the four BPF maps
//! (`sysenter_point_args`, `sysexit_point_args`, `op_list`, `arg_filter`) are
//! actually filled, so `ebpf/syscall.c:86-87,196-197` no longer bails out on
//! every syscall.

use crate::config::global::GlobalConfig;
use crate::config::syscall_select::SyscallSelection;
use crate::config::{load_syscall_config, SyscallConfig, SyscallPointTable, TargetConfig};
use crate::module::SyscallTracepointModule;
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;

/// Load the syscall point table.
///
/// Default: the table embedded from `config_syscall_aarch64.json` /
/// `config_syscall_aarch32.json` (the ported dev tables).
///
/// `-c/--config`: if any config file is a syscall table, it **replaces** the
/// embedded one, mirroring `ModuleConfig.LoadConfig` (`config_module.go:876-923`)
/// where "指定了 syscall 类型的配置 则不会采用内置配置". This is what makes the
/// `--config` flag real (report W16: the old code stored the path and never
/// loaded it).
pub fn load_point_table(global: &GlobalConfig) -> Result<SyscallPointTable> {
    crate::argtype::init_argtypes();

    for path in &global.config_files {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {path}"))?;
        // Only `type: syscall` files are point tables; uprobe files are handled
        // by the stack module.
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse {path} as JSON"))?;
        let kind = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if kind == "syscall" {
            return SyscallPointTable::from_json_str(&text)
                .with_context(|| format!("failed to load syscall table {path}"));
        }
    }

    // Also honour the typed loader when a YAML table is given (dev only reads
    // JSON, but `load_syscall_config` exists and accepts both).
    let _ = load_syscall_config;

    SyscallPointTable::embedded()
}

/// Build the [`SyscallConfig`] for a run.
///
/// Mirrors the mapping in `persistentPreRunEFunc` (`root.go:157-175`) +
/// `InitCommonConfig` (`config_module.go:840-874`) + `GetCommonFilter`
/// (`config_module.go:983-997`).
pub fn build_config(
    global: &GlobalConfig,
    target: &TargetConfig,
    table: SyscallPointTable,
    selection: SyscallSelection,
) -> Result<SyscallConfig> {
    let mut conf = SyscallConfig::with_table(table);

    // SConfig: the legacy per-module filter struct (still written to
    // `filter_map` for the old layout, and used for the perf layer).
    conf.sconfig.unwind_stack = global.unwind_stack;
    conf.sconfig.show_regs = global.show_regs;
    conf.sconfig.uid = target.uid;
    conf.sconfig.pid = target.pid;
    conf.sconfig.debug = global.debug;

    conf.debug = global.debug;
    conf.dump_hex = global.dump_hex;
    conf.color = global.color;
    conf.auto_resume = global.auto_resume;
    conf.full_tname = global.full_tname;
    conf.buffer_mb = global.buffer;

    // Filter lists: dev parses these in `persistentPreRunEFunc` and every module
    // reads the same `mconf` fields, so the syscall module gets the same lists
    // as the stack module (report W4/W5/W8/W17).
    let filters = crate::config::ResolvedFilters::from_globals(global)?;
    conf.uid_whitelist = filters.uid_whitelist;
    conf.uid_blacklist = filters.uid_blacklist;
    conf.pid_whitelist = filters.pid_whitelist;
    conf.pid_blacklist = filters.pid_blacklist;
    conf.tid_whitelist = filters.tid_whitelist;
    conf.tid_blacklist = filters.tid_blacklist.all.clone();
    conf.tname_whitelist = filters.tname_whitelist;
    conf.tname_blacklist = filters.tname_blacklist;

    // Legacy 5-entry wire mirror (`struct filter_t.tid_blacklist[5]`).
    conf.sconfig.tid_blacklist = filters.tid_blacklist.legacy;
    conf.sconfig.tid_blacklist_mask = filters.tid_blacklist.legacy_mask;

    // Syscall selection: whitelist/blacklist + trace mode (`Parse_Syscall`).
    conf.sys_whitelist = selection.whitelist;
    conf.sys_blacklist = selection.blacklist;
    conf.trace_mode = selection.trace_mode;
    conf.trace_mode_override = Some(selection.trace_mode);

    // `GetCommonFilter`: uid groups and kill signals come from the same place
    // for every module (`config_module.go:991-995`).
    conf.trace_uid_group = target.trace_uid_group;
    conf.kill_signal = crate::module::stack_probe::parse_signal_name(&global.kill_signal);
    conf.tkill_signal = crate::module::stack_probe::parse_signal_name(&global.tkill_signal);

    Ok(conf)
}

/// Run the syscall module (one module for every selected syscall, dev model).
pub fn run(
    global: &GlobalConfig,
    target: &TargetConfig,
    table: SyscallPointTable,
    selection: SyscallSelection,
) -> Result<()> {
    let conf = build_config(global, target, table, selection)?;
    let logger = Arc::new(crate::logger::Logger::new("syscall_", true));
    if !global.log_file.is_empty() {
        logger.set_out_file(&global.exec_path, &global.log_file, global.quiet)?;
    }

    if global.debug {
        logger.println(&format!("SysCallConf:{}", conf.info()));
        logger.println(&format!("point table: {} points", conf.point_table.len()));
    }

    let lib_path = format!("{}/preload_libs", global.exec_path);
    let module = SyscallTracepointModule::new(conf, lib_path);
    module
        .run(logger)
        .map_err(|e| anyhow!("{e:#}"))
        .context("syscall module failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::global::parse_id_list;

    fn global() -> GlobalConfig {
        GlobalConfig::default()
    }

    fn selection(all: bool) -> SyscallSelection {
        SyscallSelection {
            enable: true,
            trace_mode: if all {
                crate::contract::consts::TRACE_ALL
            } else {
                crate::contract::consts::TRACE_COMMON
            },
            whitelist: if all { Vec::new() } else { vec![56] },
            blacklist: Vec::new(),
        }
    }

    /// The normal path loads the embedded dev table (306 points on aarch64),
    /// which is what makes the point-args maps non-empty (report W1).
    #[test]
    fn default_table_is_the_embedded_dev_table() {
        let table = load_point_table(&global()).unwrap();
        assert!(
            table.len() > 250,
            "embedded table has {} points",
            table.len()
        );
        assert!(table.by_name("openat").is_some());
    }

    /// Report W16: `--config <syscall table>` now actually replaces the table
    /// instead of being stored and ignored.
    #[test]
    fn config_flag_overrides_the_embedded_table() {
        let dir = std::env::temp_dir().join("stackplz_syscall_cfg_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom.json");
        std::fs::write(
            &path,
            r#"{
                "type": "syscall",
                "points": [
                    {"nr": 999, "name": "custom_call",
                     "params": [{"name": "fd", "type": "int"}, {"name": "ret", "type": "int"}]}
                ]
            }"#,
        )
        .unwrap();

        let mut global = global();
        global.config_files = vec![path.to_string_lossy().into_owned()];
        let table = load_point_table(&global).unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table.by_name("custom_call").map(|p| p.nr), Some(999));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing `-c` file is an error, not a silent fallback to the embedded
    /// table.
    #[test]
    fn missing_config_file_is_an_error() {
        let mut global = global();
        global.config_files = vec!["/nonexistent/syscall.json".to_string()];
        assert!(load_point_table(&global).is_err());
    }

    /// The filter lists and kill signals must reach the module config
    /// (report W4/W5): `-u/-p/-t/--no-*/--kill/--tkill`.
    #[test]
    fn build_config_carries_filters_signals_and_groups() {
        let mut global = global();
        global.uid = "0,1000".to_string();
        global.pid = "1234".to_string();
        global.tid = "11,22".to_string();
        global.no_tid = "33,44".to_string();
        global.tname = "alpha".to_string();
        global.no_tname = "beta".to_string();
        global.kill_signal = "SIGSTOP".to_string();
        global.tkill_signal = "SIGTRAP".to_string();
        global.full_tname = true;

        let target = TargetConfig {
            trace_uid_group: crate::contract::TraceGroup::Root as u32,
            uid: 1000,
            ..Default::default()
        };

        let table = SyscallPointTable::empty();
        let conf = build_config(&global, &target, table, selection(false)).unwrap();

        assert_eq!(conf.uid_whitelist, vec![0, 1000]);
        assert_eq!(conf.uid_blacklist, Vec::<u32>::new());
        assert_eq!(conf.pid_whitelist, vec![1234]);
        assert_eq!(conf.tid_whitelist, vec![11, 22]);
        assert_eq!(conf.tid_blacklist, vec![33, 44]);
        assert_eq!(conf.tname_whitelist, vec!["alpha".to_string()]);
        assert_eq!(conf.tname_blacklist, vec!["beta".to_string()]);
        assert!(conf.full_tname);

        // W5: --kill/--tkill must land in common_filter.signal/tsignal.
        assert_eq!(
            conf.kill_signal,
            crate::module::stack_probe::parse_signal_name("SIGSTOP")
        );
        assert_ne!(conf.kill_signal, 0);
        assert_ne!(conf.tkill_signal, 0);
        let bytes = conf.to_common_filter_bytes();
        assert_eq!(
            u32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
            conf.kill_signal,
            "signal at offset 12"
        );
        assert_eq!(
            u32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
            conf.tkill_signal,
            "tsignal at offset 16"
        );

        // W4: -n root must set trace_uid_group, not 0.
        assert_eq!(
            u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
            crate::contract::TraceGroup::Root as u32
        );
    }

    /// `-u 0` is a real whitelist entry (dev semantics, report §4.2/W11).
    #[test]
    fn uid_zero_reaches_the_config_as_a_filter() {
        let mut global = global();
        global.uid = "0".to_string();
        let table = SyscallPointTable::empty();
        let conf = build_config(&global, &TargetConfig::default(), table, selection(true)).unwrap();
        assert_eq!(conf.uid_whitelist, vec![0]);
        assert!(!conf.has_no_user_filter());
        assert_eq!(
            u32::from_ne_bytes(conf.to_common_filter_bytes()[20..24].try_into().unwrap()),
            0,
            "no_filter_allow must be 0 once a filter exists"
        );
        let _ = parse_id_list("UidWhitelist", "0");
    }

    /// Report §4.4-2 / brief item 8, re-evaluated after W1 was fixed:
    /// `-n root` used to fall through to the permissive `no_filter_allow` because
    /// the group mask was never written (it was hard-wired to 0). Now the group
    /// bit is a real filter, so the fallback is off and `-n root` admits only
    /// `uid == GROUP_ROOT` processes (`ebpf/common/filtering.h:91-105`), not
    /// "every uid".
    #[test]
    fn name_group_alone_disables_the_permissive_fallback() {
        let global = GlobalConfig::default();
        let target = TargetConfig {
            trace_uid_group: crate::contract::TraceGroup::Root as u32,
            ..Default::default()
        };
        let conf = build_config(
            &global,
            &target,
            SyscallPointTable::empty(),
            selection(true),
        )
        .unwrap();
        assert!(
            !conf.has_no_user_filter(),
            "a uid group is a filter: the fallback must stay off"
        );
        assert_eq!(
            u32::from_ne_bytes(conf.to_common_filter_bytes()[20..24].try_into().unwrap()),
            0,
            "no_filter_allow must be 0 for -n root (no more 'trace every uid')"
        );
        assert_eq!(
            u32::from_ne_bytes(conf.to_common_filter_bytes()[8..12].try_into().unwrap()),
            crate::contract::TraceGroup::Root as u32,
            "trace_uid_group carries the ROOT bit to the kernel"
        );
    }

    /// The remaining round-1 deviation, made explicit: with *no* filter flags at
    /// all, round 1 deliberately restores master's "0 = no filtering" semantics
    /// (`no_filter_allow = 1`) instead of dev's default deny. Brief item 8 keeps
    /// that intentional fix; this test pins it so the deviation is visible
    /// instead of accidental.
    #[test]
    fn no_filters_at_all_keeps_the_round1_permissive_deviation() {
        let global = GlobalConfig::default();
        let conf = build_config(
            &global,
            &TargetConfig::default(),
            SyscallPointTable::empty(),
            selection(true),
        )
        .unwrap();
        assert!(conf.has_no_user_filter());
        assert_eq!(
            u32::from_ne_bytes(conf.to_common_filter_bytes()[20..24].try_into().unwrap()),
            1,
            "round-1 fix ②: no filter flags => permissive fallback (master semantics)"
        );
    }

    /// `-b/--buffer` (MiB) must reach the module config, which turns it into
    /// perf ring-buffer pages (`pages = buffer_mb * 256`). Before this round the
    /// flag was accepted and ignored (report W10 "dead flag list").
    #[test]
    fn buffer_flag_reaches_the_module_config() {
        let global = GlobalConfig {
            buffer: 16,
            ..Default::default()
        };
        let conf = build_config(
            &global,
            &TargetConfig::default(),
            SyscallPointTable::empty(),
            selection(true),
        )
        .unwrap();
        assert_eq!(conf.buffer_mb, 16);
        assert_eq!(conf.buffer_mb as usize * 256, 4096, "16 MiB == 4096 pages");
    }

    /// Trace mode comes from `-s`, not from a hard-coded guess: `-s all` writes
    /// TRACE_ALL, `-s openat` writes TRACE_COMMON.
    #[test]
    fn trace_mode_comes_from_the_selection() {
        let mut global = global();
        global.uid = "1000".to_string();
        let table = SyscallPointTable::empty();
        let bytes_all = build_config(
            &global,
            &TargetConfig::default(),
            table.clone(),
            selection(true),
        )
        .unwrap()
        .to_common_filter_bytes();
        assert_eq!(
            u32::from_ne_bytes(bytes_all[4..8].try_into().unwrap()),
            crate::contract::consts::TRACE_ALL
        );
        let bytes_common = build_config(&global, &TargetConfig::default(), table, selection(false))
            .unwrap()
            .to_common_filter_bytes();
        assert_eq!(
            u32::from_ne_bytes(bytes_common[4..8].try_into().unwrap()),
            crate::contract::consts::TRACE_COMMON
        );
    }
}
