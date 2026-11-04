//! Stack (uprobe) module handler.
//!
//! dev has no `stack` subcommand: `-w/--point` (and `-c/--config` with a uprobe
//! file) are global flags and `runFunc` starts the uprobe module when syscall
//! tracing is not enabled (`cli/cmd/root.go:387-396`). Mirrors
//! `parseConfig` + `MStack.Run` (`cli/cmd/stack.go`, `user/module/stack.go`).
//!
//! All filter flags are threaded through [`StackConfig`] so the module can write
//! the same maps as `MStack.updateFilter()` (report W17): uid/pid/tid/tname
//! lists, `child_parent_map`, `thread_filter`, `arg_filter`, and
//! `common_filter.trace_uid_group` (the previous code hard-coded `0xFF`).

use crate::config::global::GlobalConfig;
use crate::config::hook_json::{hex2int, HookConfig};
use crate::config::{ProbeConfig, SConfig, StackConfig, TargetConfig, UprobeArgs};
use crate::module::{StackProbeModule, MODULE_NAME_STACK};
use crate::util::find_lib;
use anyhow::{bail, Context, Result};
use std::sync::Arc;

/// True when `-c/--config` names at least one uprobe config file.
///
/// The module selection in `runFunc` needs to know whether there is a uprobe
/// hook source before the config files are parsed (`stack.go:parseConfig`).
pub fn has_uprobe_config(global: &GlobalConfig) -> bool {
    global.config_files.iter().any(|path| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
            })
            .map(|kind| kind == "uprobe")
            .unwrap_or(false)
    })
}

/// Build the [`StackConfig`] carrier from the global flags.
///
/// dev fills one `ModuleConfig` for every module, so uid/pid/tid/tname lists,
/// the uid-group mask and the kill signals are identical to the syscall side
/// (`config_module.go:InitCommonConfig`, `GetCommonFilter`).
pub fn build_stack_config(global: &GlobalConfig, target: &TargetConfig) -> Result<StackConfig> {
    let filters = crate::config::ResolvedFilters::from_globals(global)?;
    Ok(StackConfig {
        unwind_stack: global.unwind_stack,
        show_regs: global.show_regs,
        reg_name: global.reg_name.clone(),
        full_tname: global.full_tname,
        buffer_mb: global.buffer,
        uid_whitelist: filters.uid_whitelist,
        uid_blacklist: filters.uid_blacklist,
        pid_whitelist: filters.pid_whitelist,
        pid_blacklist: filters.pid_blacklist,
        tid_whitelist: filters.tid_whitelist,
        tid_blacklist: filters.tid_blacklist.all.clone(),
        tname_whitelist: filters.tname_whitelist,
        tname_blacklist: filters.tname_blacklist,
        trace_uid_group: target.trace_uid_group,
        kill_signal: crate::module::stack_probe::parse_signal_name(&global.kill_signal),
        tkill_signal: crate::module::stack_probe::parse_signal_name(&global.tkill_signal),
        // A stack-only run has no `-s`, so dev's `SysCallConf.TraceMode` stays at
        // its zero value, `TRACE_COMMON` (0).
        trace_mode: crate::contract::consts::TRACE_COMMON,
        ..Default::default()
    })
}

/// Build the uprobe probes. Mirrors `parseConfig` / `Parse_HookPoint`.
fn build_probes(
    global: &GlobalConfig,
    target: &TargetConfig,
    stack_conf: &StackConfig,
) -> Result<Vec<(ProbeConfig, Vec<UprobeArgs>)>> {
    let mut probes: Vec<(ProbeConfig, Vec<UprobeArgs>)> = Vec::new();

    let legacy_tid = crate::config::ResolvedFilters::from_globals(global)?;
    let sconfig = SConfig {
        unwind_stack: stack_conf.unwind_stack,
        show_regs: stack_conf.show_regs,
        reg_name: stack_conf.reg_name.clone(),
        uid: target.uid,
        pid: target.pid,
        tid_blacklist: legacy_tid.tid_blacklist.legacy,
        tid_blacklist_mask: legacy_tid.tid_blacklist.legacy_mask,
        debug: global.debug,
    };

    // 1. `-w/--point` mode: one library, one probe, many points.
    if !global.hook_point.is_empty() {
        let library = find_lib(&global.library, &target.library_dirs)?;
        let points = crate::config::point_parser::parse_hook_point(
            &global.hook_point,
            &library,
            global.dump_hex,
            global.color,
        )?;
        let mut probe = ProbeConfig {
            sconfig,
            lib_name: String::new(),
            library: library.clone(),
            symbol: String::new(),
            offset: 0,
        };
        probe.check()?;
        probes.push((probe, points));
        return Ok(probes);
    }

    // 2. `-c/--config` uprobe files.
    for path in &global.config_files {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Error when opening file: {path}"))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse {path} as JSON"))?;
        if value.get("type").and_then(|v| v.as_str()) != Some("uprobe") {
            continue;
        }
        let mut hook_cfg: HookConfig = serde_json::from_str(&text)?;
        hook_cfg
            .library_dirs
            .extend(target.library_dirs.iter().cloned());
        for lib_hook in &hook_cfg.libs {
            if lib_hook.disable {
                if global.debug {
                    eprintln!("disabled, skip hook {}", lib_hook.library);
                }
                continue;
            }
            let library = find_lib(&lib_hook.library, &hook_cfg.library_dirs)?;
            let mut seen_symbols: Vec<String> = Vec::new();
            let mut seen_offsets: Vec<String> = Vec::new();
            for base in &lib_hook.configs {
                for symbol in &base.symbols {
                    let symbol = symbol.trim();
                    if symbol.is_empty() || seen_symbols.iter().any(|s| s == symbol) {
                        continue;
                    }
                    seen_symbols.push(symbol.to_string());
                    let mut probe = ProbeConfig {
                        sconfig: SConfig {
                            unwind_stack: base.unwindstack,
                            show_regs: base.regs,
                            ..sconfig.clone()
                        },
                        lib_name: String::new(),
                        library: library.clone(),
                        symbol: symbol.to_string(),
                        offset: 0,
                    };
                    probe.check()?;
                    probes.push((probe, Vec::new()));
                }
                for offset in &base.offsets {
                    let offset = offset.trim();
                    if offset.is_empty()
                        || !offset.starts_with("0x")
                        || seen_offsets.iter().any(|s| s == offset)
                    {
                        continue;
                    }
                    seen_offsets.push(offset.to_string());
                    let mut probe = ProbeConfig {
                        sconfig: SConfig {
                            unwind_stack: base.unwindstack,
                            show_regs: base.regs,
                            ..sconfig.clone()
                        },
                        lib_name: String::new(),
                        library: library.clone(),
                        symbol: String::new(),
                        offset: hex2int(offset),
                    };
                    probe.check()?;
                    probes.push((probe, Vec::new()));
                }
            }
        }
    }

    if probes.is_empty() {
        bail!("hook nothing, plz set -w/--point or -s/--syscall or --brk");
    }
    Ok(probes)
}

/// Run the stack module(s).
pub fn run(global: &GlobalConfig, target: &TargetConfig) -> Result<()> {
    // Required before any argtype/point-arg work.
    crate::argtype::init_argtypes();

    let stack_conf = build_stack_config(global, target)?;
    let probes = build_probes(global, target, &stack_conf)?;

    let logger = Arc::new(crate::logger::Logger::new("", true));
    if !global.log_file.is_empty() {
        logger.set_out_file(&global.exec_path, &global.log_file, global.quiet)?;
    }

    let lib_path = format!("{}/preload_libs", global.exec_path);
    for (mut probe, hook_points) in probes {
        probe.sconfig.debug = global.debug;
        logger.println(&format!(
            "{}\thook info:{}",
            MODULE_NAME_STACK,
            probe.info()
        ));

        let module = StackProbeModule::new(probe, lib_path.clone())
            .with_hook_points(hook_points)
            .with_signals(
                stack_conf.kill_signal,
                stack_conf.tkill_signal,
                global.auto_resume,
            )
            // W17: all filter maps are written from this carrier.
            .with_stack_config(stack_conf.clone());
        module
            .run(logger.clone())
            .with_context(|| format!("{MODULE_NAME_STACK} module failed"))?;
    }
    Ok(())
}
