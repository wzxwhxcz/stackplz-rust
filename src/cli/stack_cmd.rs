//! Stack (uprobe) module handler.
//!
//! dev has no `stack` subcommand: `-w/--point` (and `-c/--config` with a uprobe
//! file) are global flags and `runFunc` starts the uprobe module when syscall
//! tracing is not enabled (`cli/cmd/root.go:386-396`). Mirrors
//! `GlobalConfig.Parse_Libinfo` + `MStack.Run` (`config_global.go:160`,
//! `user/module/stack.go`).
//!
//! All filter flags are threaded through [`StackConfig`] so the module can write
//! the same maps as `MStack.updateFilter()` (report W17): uid/pid/tid/tname
//! lists, `child_parent_map`, `thread_filter`, `arg_filter`, and
//! `common_filter.trace_uid_group` (the previous code hard-coded `0xFF`).

use crate::config::base0::parse_base0_u64;
use crate::config::global::GlobalConfig;
use crate::config::hook_json::{hex2int, HookConfig};
use crate::config::{
    PointConfig, ProbeConfig, SConfig, StackConfig, TargetConfig, UprobeArgs, UprobeFileConfig,
    EBPF_UPROBE_ENTER,
};
use crate::module::{StackProbeModule, MODULE_NAME_STACK};
use crate::util::find_lib;
use anyhow::{anyhow, bail, Context, Result};
use std::sync::Arc;

/// True when `-c/--config` names at least one uprobe config file.
///
/// The module selection in `runFunc` needs to know whether there is a uprobe
/// hook source before the config files are parsed (`stack.go:parseConfig`).
pub fn has_uprobe_config(global: &GlobalConfig) -> Result<bool> {
    for path in &global.config_files {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Error when opening file: {path}"))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse {path} as JSON"))?;
        // Round 11 / O1: recognize both config shapes — dev (`type` =
        // "uprobe") and master (`libs`). A bare `type` = "syscall" file is
        // not an uprobe source (its `points` key belongs to the syscall
        // table).
        if value.get("type").and_then(|t| t.as_str()) == Some("uprobe")
            || value.get("libs").is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Build the [`StackConfig`] carrier from the global flags.
///
/// dev fills one `ModuleConfig` for every module, so uid/pid/tid/tname lists,
/// the uid-group mask and the kill signals are identical to the syscall side
/// (`config_module.go:InitCommonConfig`, `GetCommonFilter`).
pub fn build_stack_config(global: &GlobalConfig, target: &TargetConfig) -> Result<StackConfig> {
    let filters = crate::config::ResolvedFilters::from_globals(global)?;
    let conf = StackConfig {
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
        // Round 11 / Q1: the global `--dumphex` flag, same line as the
        // syscall side (`syscall_cmd.rs`).
        dump_hex: global.dump_hex,
        // A stack-only run has no `-s`, so dev's `SysCallConf.TraceMode` stays at
        // its zero value, `TRACE_COMMON` (0).
        trace_mode: crate::contract::consts::TRACE_COMMON,
    };
    conf.validate()?; // K2: zero buffer_mb fails here, not later at perf_pages.
    Ok(conf)
}

/// One attachable uprobe point for a `-c/--config` entry.
///
/// `-w/--point` strings get a fully parsed [`UprobeArgs`] from
/// `parse_hook_point`; a config entry names only a symbol or an offset and has
/// no argument list, so the point needs no `point_args`. Without this the probe
/// carries zero points and `StackProbeModule` attaches nothing at all.
fn uprobe_point(library: &str, symbol: &str, offset: u64) -> crate::config::UprobeArgs {
    crate::config::UprobeArgs {
        lib_path: library.to_string(),
        symbol: symbol.to_string(),
        offset,
        ..Default::default()
    }
}

/// Convert one dev-era `PointConfig` to a [`UprobeArgs`]. Mirrors Go's
/// `StackUprobeConfig.Parse_FileConfig` (`config_module.go:287-333`):
/// `name` splits on '+' (one segment: `0x…` → offset, else symbol; two
/// segments: symbol+offset; three+ → error), `signal` feeds the kill
/// signal (N1), `params` become point args.
fn dev_point_to_uprobe_args(
    library: &str,
    index: usize,
    point: &PointConfig,
) -> Result<UprobeArgs> {
    let mut ua = UprobeArgs::new();
    ua.index = index as u32;
    ua.lib_path = library.to_string();
    ua.name = point.name.clone();

    let parts: Vec<&str> = point.name.split('+').collect();
    match parts.len() {
        1 => {
            let sym_or_off = parts[0];
            if sym_or_off.starts_with("0x") || sym_or_off.starts_with("0X") {
                ua.offset = parse_base0_u64(sym_or_off)
                    .map_err(|e| anyhow!("parse for {} failed, err:{}", point.name, e))?;
            } else {
                ua.symbol = sym_or_off.to_string();
            }
        }
        2 => {
            ua.symbol = parts[0].to_string();
            ua.offset = parse_base0_u64(parts[1])
                .map_err(|e| anyhow!("parse for {} failed, err:{}", point.name, e))?;
        }
        _ => bail!("parse for {} failed, err:too many '+' segments", point.name),
    }

    // N1: the per-point kill signal was parsed but never wired out.
    if !point.signal.is_empty() {
        ua.kill_signal = crate::module::stack_probe::parse_signal_name(&point.signal);
    }

    for (arg_index, param) in point.params.iter().enumerate() {
        ua.point_args
            .push(param.get_point_arg(arg_index as u32, EBPF_UPROBE_ENTER)?);
    }
    Ok(ua)
}

/// Build the uprobe probes. Mirrors `parseConfig` / `Parse_HookPoint`.
///
/// `w_points` carries the `-w/--point` points already parsed (and dispatched)
/// by `run_func` (round 11 / P1): `Some((library, points))` uses them directly
/// and skips the `-w` parse. `None` falls back to parsing `global.hook_point`
/// here (the pre-P1 path).
fn build_probes(
    global: &GlobalConfig,
    target: &TargetConfig,
    w_points: Option<(String, Vec<UprobeArgs>)>,
) -> Result<Vec<(ProbeConfig, Vec<UprobeArgs>)>> {
    let mut probes: Vec<(ProbeConfig, Vec<UprobeArgs>)> = Vec::new();

    let legacy_tid = crate::config::ResolvedFilters::from_globals(global)?;
    let sconfig = SConfig {
        uid: target.uid,
        pid: target.pid,
        tid_blacklist: legacy_tid.tid_blacklist.legacy,
        tid_blacklist_mask: legacy_tid.tid_blacklist.legacy_mask,
    };

    // 1. `-w/--point` mode: one library, one probe, many points.
    if let Some((library, points)) = w_points {
        if !points.is_empty() {
            let probe = ProbeConfig {
                sconfig,
                lib_name: String::new(),
                library,
                symbol: String::new(),
                offset: 0,
            };
            // Container probe: `find_lib` already validated the library path;
            // the symbol/offset rule in `ProbeConfig::check` applies to
            // per-symbol probes, not to a library-level carrier whose points
            // carry the attach attributes.
            probes.push((probe, points));
        }
        return Ok(probes);
    }
    if !global.hook_point.is_empty() {
        let library = find_lib(&global.library, &target.library_dirs)?;
        let points = crate::config::point_parser::parse_hook_point(
            &global.hook_point,
            &library,
            global.dump_hex,
        )?;
        let probe = ProbeConfig {
            sconfig,
            lib_name: String::new(),
            library,
            symbol: String::new(),
            offset: 0,
        };
        probes.push((probe, points));
        return Ok(probes);
    }

    // 2. `-c/--config` uprobe files. Dispatch on the file's shape (round 11
    // / O1): syscall tables pass through (they belong to the syscall side),
    // master-era `libs` files take the `HookConfig` path, dev-era `points`
    // files convert like Go's `Parse_FileConfig`, anything else errors loudly
    // instead of being silently skipped.
    for path in &global.config_files {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Error when opening file: {path}"))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse {path} as JSON"))?;

        if value.get("type").and_then(|v| v.as_str()) == Some("syscall") {
            continue;
        }

        if value.get("libs").is_some() {
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
                            sconfig: sconfig.clone(),
                            lib_name: String::new(),
                            library: library.clone(),
                            symbol: symbol.to_string(),
                            offset: 0,
                        };
                        probe.check()?;
                        probes.push((probe, vec![uprobe_point(&library, symbol, 0)]));
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
                            sconfig: sconfig.clone(),
                            lib_name: String::new(),
                            library: library.clone(),
                            symbol: String::new(),
                            offset: hex2int(offset),
                        };
                        probe.check()?;
                        let off = probe.offset;
                        probes.push((probe, vec![uprobe_point(&library, "", off)]));
                    }
                }
            }
            continue;
        }

        if value.get("type").and_then(|v| v.as_str()) == Some("uprobe")
            && value.get("points").is_some()
        {
            let cfg: UprobeFileConfig = serde_json::from_str(&text)?;
            let library = find_lib(&cfg.library, &target.library_dirs)?;
            for (index, point) in cfg.points.iter().enumerate() {
                let ua = dev_point_to_uprobe_args(&library, index, point)?;
                let mut probe = ProbeConfig {
                    sconfig: sconfig.clone(),
                    lib_name: String::new(),
                    library: library.clone(),
                    symbol: ua.symbol.clone(),
                    offset: ua.offset,
                };
                probe.check()?;
                probes.push((probe, vec![ua]));
            }
            continue;
        }

        bail!("unrecognized config shape: {path}");
    }

    if probes.is_empty() {
        bail!("hook nothing, plz set -w/--point or -s/--syscall or --brk");
    }
    Ok(probes)
}

/// Run the stack module(s).
pub fn run(
    global: &GlobalConfig,
    target: &TargetConfig,
    w_points: Option<(String, Vec<UprobeArgs>)>,
) -> Result<()> {
    // Required before any argtype/point-arg work.
    crate::argtype::init_argtypes();

    let stack_conf = build_stack_config(global, target)?;
    let probes = build_probes(global, target, w_points)?;

    let logger = Arc::new(crate::logger::Logger::new("", true));
    if !global.log_file.is_empty() {
        logger.set_out_file(&global.exec_path, &global.log_file, global.quiet)?;
    }

    let lib_path = format!("{}/preload_libs", global.exec_path);
    // Round 10 / M3: run all probes inside one closure so the dropped-lines
    // warning is presented exactly once, on the success path AND on the
    // error path (the old code printed it only after a fully successful
    // loop — a failing `run()` returned through `?` before reaching it).
    let result = (|| -> Result<()> {
        for (probe, hook_points) in probes {
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
    })();
    // Round 7 / F1: the drop counter added in round 6 had no reader, so a
    // full disk / closed stdout stayed silent. Present it once here.
    crate::logger::Logger::finish_run(result, &logger)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cfg_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "stackplz-uprobe-cfg-{tag}-{}.json",
            std::process::id()
        ));
        p
    }

    fn global_with_configs(paths: Vec<std::path::PathBuf>) -> GlobalConfig {
        GlobalConfig {
            config_files: paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn has_uprobe_config_detects_uprobe_type() {
        let p = temp_cfg_path("uprobe");
        std::fs::write(&p, r#"{"type":"uprobe"}"#).unwrap();
        assert!(has_uprobe_config(&global_with_configs(vec![p.clone()])).unwrap());
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn has_uprobe_config_rejects_other_types() {
        let p = temp_cfg_path("syscall");
        std::fs::write(&p, r#"{"type":"syscall"}"#).unwrap();
        assert!(!has_uprobe_config(&global_with_configs(vec![p.clone()])).unwrap());
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn has_uprobe_config_surfaces_parse_errors_with_path() {
        let p = temp_cfg_path("badjson");
        std::fs::write(&p, "not json").unwrap();
        let err = has_uprobe_config(&global_with_configs(vec![p.clone()])).unwrap_err();
        assert!(
            format!("{err:#}").contains(p.to_string_lossy().as_ref()),
            "error must name the offending path: {err:#}"
        );
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn has_uprobe_config_surfaces_read_errors() {
        let p = temp_cfg_path("missing");
        assert!(has_uprobe_config(&global_with_configs(vec![p])).is_err());
    }

    /// Round 11 / O1: a master-era file (`libs`, no `type` key — the shipped
    /// `config.json` shape) is a uprobe source: the gate accepts it and
    /// `build_probes` produces one probe per symbol.
    #[test]
    fn has_uprobe_config_accepts_master_shape() {
        let p = temp_cfg_path("master-gate");
        std::fs::write(
            &p,
            r#"{"library_dirs": [], "libs": [{"library": "libc.so", "configs": []}]}"#,
        )
        .unwrap();
        assert!(has_uprobe_config(&global_with_configs(vec![p.clone()])).unwrap());
        std::fs::remove_file(&p).unwrap();
    }

    /// Round 11 / O1: the shipped `config.json` shape (master-era `libs`,
    /// no `type` key) used to be silently skipped (`continue`) and, with no
    /// `-w`, `run_func` answered `NothingToHook`. It now yields probes.
    #[test]
    fn build_probes_master_config_loads_probes() {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-master-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("bionic")).unwrap();
        std::fs::write(dir.join("bionic/libc.so"), b"").unwrap();
        let cfg = temp_cfg_path("master");
        std::fs::write(
            &cfg,
            format!(
                r#"{{"library_dirs": [{}], "libs": [{{"library": "bionic/libc.so", "disable": false, "configs": [{{"symbols": ["open"], "offsets": []}}, {{"symbols": ["read", "send", "recv"], "offsets": []}}]}}]}}"#,
                serde_json::to_string(&dir.to_string_lossy()).unwrap()
            ),
        )
        .unwrap();
        let global = global_with_configs(vec![cfg.clone()]);
        assert!(has_uprobe_config(&global).unwrap());
        let probes = build_probes(&global, &TargetConfig::default(), None).unwrap();
        let mut symbols: Vec<String> = probes
            .iter()
            .flat_map(|(probe, points)| {
                assert!(
                    probe.library.ends_with("bionic/libc.so"),
                    "unexpected library: {}",
                    probe.library
                );
                points.iter().map(|p| p.symbol.clone()).collect::<Vec<_>>()
            })
            .collect();
        symbols.sort();
        assert_eq!(symbols, ["open", "read", "recv", "send"]);
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Round 11 / O1 + N1: the upstream dev fixture
    /// (`tests/config_uprobe_test_symbol.json` shape) parses through the `-c`
    /// path and the per-point `signal` reaches `UprobeArgs.kill_signal`
    /// (SIGSTOP → 19, lowercase likewise, absent → 0). Before this round the
    /// file was rejected at the door (`unknown field 'type'`).
    #[test]
    fn build_probes_dev_config_wires_signal() {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-dev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("libnative-lib.so"), b"").unwrap();
        let cfg = temp_cfg_path("dev");
        std::fs::write(
            &cfg,
            r#"{"type": "uprobe", "library": "libnative-lib.so", "points": [
                {"name": "_Z5func1v", "signal": "SIGSTOP", "params": []},
                {"name": "helper", "signal": "sigstop", "params": []},
                {"name": "plain", "params": []}
            ]}"#,
        )
        .unwrap();
        let global = global_with_configs(vec![cfg.clone()]);
        let target = TargetConfig {
            library_dirs: vec![dir.to_string_lossy().to_string()],
            ..Default::default()
        };
        let probes = build_probes(&global, &target, None).unwrap();
        assert_eq!(probes.len(), 3, "one probe per dev point");
        let points: Vec<&UprobeArgs> = probes.iter().flat_map(|(_, ps)| ps.iter()).collect();
        assert_eq!(points[0].symbol, "_Z5func1v");
        assert_eq!(points[0].kill_signal, 19, "SIGSTOP");
        assert_eq!(points[1].kill_signal, 19, "lowercase sigstop");
        assert_eq!(points[2].kill_signal, 0, "absent signal means none");
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Round 11 / O1: a `-c` file that is neither shape (no `points`, no
    /// `libs`) must fail loudly instead of being silently skipped.
    #[test]
    fn build_probes_unrecognized_shape_errors() {
        let cfg = temp_cfg_path("shape");
        std::fs::write(&cfg, r#"{"type": "uprobe", "library": "x.so"}"#).unwrap();
        let err = build_probes(
            &global_with_configs(vec![cfg.clone()]),
            &TargetConfig::default(),
            None,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("unrecognized config shape"),
            "{err:#}"
        );
        std::fs::remove_file(&cfg).unwrap();
    }

    /// Round 11 / O1: a dev point name with three `+` segments is rejected
    /// (Go `Parse_FileConfig` rejects it the same way).
    #[test]
    fn build_probes_dev_three_segment_name_errors() {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-dev3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("libnative-lib.so"), b"").unwrap();
        let cfg = temp_cfg_path("dev3");
        std::fs::write(
            &cfg,
            r#"{"type": "uprobe", "library": "libnative-lib.so", "points": [
                {"name": "a+b+c", "params": []}
            ]}"#,
        )
        .unwrap();
        let target = TargetConfig {
            library_dirs: vec![dir.to_string_lossy().to_string()],
            ..Default::default()
        };
        let err = build_probes(&global_with_configs(vec![cfg.clone()]), &target, None).unwrap_err();
        assert!(
            format!("{err:#}").contains("too many '+' segments"),
            "{err:#}"
        );
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
