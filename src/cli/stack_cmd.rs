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

/// Offset-marker policy (R11-2): **only lowercase `0x`** (and the `+0x`
/// suffix) marks an offset; uppercase `0X` is never an offset marker and falls
/// through to the symbol path — matching Go, which checks
/// `strings.HasPrefix(sym_or_off, "0x")` only. All offset parsing in this
/// crate follows this function: `point_parser.rs` (-w) and the master offsets
/// gate.
fn is_offset_marker(s: &str) -> bool {
    s.starts_with("0x")
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
            if is_offset_marker(sym_or_off) {
                ua.offset = parse_base0_u64(sym_or_off)
                    .map_err(|e| anyhow!("parse for {} failed, err:{}", point.name, e))?;
            } else {
                // `0X…` lands here: a symbol, never an offset (see
                // `is_offset_marker` policy).
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

    // N1 + R11-1: the per-point kill signal is strict here — an unknown name
    // must fail loudly (it used to silently become 0 = "no signal"), unlike
    // the global `--kill`/`--tkill` flags which share the lenient
    // `parse_signal_name` (numbers and lowercase stay accepted in both).
    ua.kill_signal = crate::module::stack_probe::parse_signal_name_strict(&point.signal)?;

    for (arg_index, param) in point.params.iter().enumerate() {
        ua.point_args
            .push(param.get_point_arg(arg_index as u32, EBPF_UPROBE_ENTER)?);
    }
    Ok(ua)
}

/// Renumber every probe's hook points so `point.index` equals its position in
/// the probe's vec (round 12 / R11-8). The BPF program `probe_stack_{i}`
/// attaches by position and looks up the `uprobe_point_args` map with that same
/// number, so a stale index — kept by `dispatch_w_points` when a bound point
/// was removed, or produced by the per-dev-point probes — would silently miss
/// the point args (`stack.c:44-46` → no events, no error).
///
/// `enter_key` is remapped alongside so R11-6's pairing survives: the C
/// handler saves registers under `UPROBE_ENTER + point_key + 1` on enter and
/// restores them on exit using the exit point's `enter_key` (`stack.c:59-70`),
/// so a main point gets `pos + 1` and its companion exit point must keep that
/// same key, not its own `pos + 1`. The companion is the point that follows a
/// nonzero `exit_offset` point; a lone `enter_key` without a preceding main
/// (no exit companion) gets its own `pos + 1`.
fn renumber_probe_points(probes: &mut [(ProbeConfig, Vec<UprobeArgs>)]) {
    for (_, points) in probes {
        let mut pending_enter_key = 0u32;
        for (pos, point) in points.iter_mut().enumerate() {
            point.index = pos as u32;
            if point.enter_key == 0 && point.exit_offset == 0 {
                continue;
            }
            if point.exit_offset != 0 {
                // Main point: stamp the key its exit companion will reuse.
                point.enter_key = pos as u32 + 1;
                pending_enter_key = point.enter_key;
            } else if pending_enter_key != 0 {
                // Companion exit point: keep the main point's key.
                point.enter_key = pending_enter_key;
                pending_enter_key = 0;
            } else {
                point.enter_key = pos as u32 + 1;
            }
        }
    }
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
        renumber_probe_points(&mut probes);
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
        renumber_probe_points(&mut probes);
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
                        if offset.is_empty() || seen_offsets.iter().any(|s| s == offset) {
                            continue;
                        }
                        // R11-3: the gate and the converter must agree — a
                        // non-`0x` offset (e.g. uppercase `0X10`) is rejected
                        // loudly instead of silently skipped (it used to
                        // disappear without any warning while `hex2int`
                        // could have parsed it).
                        if !is_offset_marker(offset) {
                            bail!("offset {offset} must start with 0x");
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
    renumber_probe_points(&mut probes);
    Ok(probes)
}

/// Run N jobs — one per probe module — concurrently until an interrupt, the
/// first job error, or every job finishing cleanly. Mirrors `run_modules`'s
/// completion semantics for one module family (round 12 / R11-7): a trace
/// module never legitimately ends on its own, so all-Ok without an interrupt is
/// an error, not a success.
fn run_jobs_concurrently<F>(jobs: Vec<F>, interrupted: impl Fn() -> bool) -> Result<()>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    if jobs.is_empty() {
        return Err(anyhow!("no stack probes to run"));
    }
    let (tx, rx) = std::sync::mpsc::channel::<Result<()>>();
    for (i, job) in jobs.into_iter().enumerate() {
        let tx = tx.clone();
        std::thread::Builder::new()
            .name(format!("stack-probe-{i}"))
            .spawn(move || {
                let _ = tx.send(job());
            })
            .map_err(|e| anyhow!("failed to spawn stack probe thread: {e}"))?;
    }
    drop(tx);
    loop {
        if interrupted() {
            return Ok(());
        }
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Every thread sent exactly one message and is gone: all probes
                // stopped without an interrupt.
                return Err(anyhow!("all stack probes stopped without a signal"));
            }
        }
    }
}

/// Run the stack module(s).
pub fn run(
    global: &GlobalConfig,
    target: &TargetConfig,
    w_points: Option<(String, Vec<UprobeArgs>)>,
    logger: Arc<crate::logger::Logger>,
    resume: Arc<crate::signal::ConsoleResume>,
) -> Result<()> {
    // Required before any argtype/point-arg work.
    crate::argtype::init_argtypes();

    let stack_conf = build_stack_config(global, target)?;
    let probes = build_probes(global, target, w_points)?;

    let lib_path = format!("{}/preload_libs", global.exec_path);
    // Round 10 / M3 + round 12 / R11-7: every probe gets its own module thread
    // (`module.run()` blocks in its poll loop), so a multi-probe `-c` config no
    // longer runs only the first probe. The dropped-lines warning is still
    // presented exactly once via `finish_run`, outside this block.
    let result = {
        let jobs: Vec<_> = probes
            .into_iter()
            .map(|(probe, hook_points)| {
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
                // The outer `map` closure is `FnMut`; clone the Arcs into the
                // per-probe `move` job closure so nothing is moved out of it.
                let logger = logger.clone();
                let resume = resume.clone();
                move || {
                    module
                        .run(logger, resume)
                        .with_context(|| format!("{MODULE_NAME_STACK} module failed"))
                }
            })
            .collect();
        run_jobs_concurrently(jobs, crate::cli::interrupted)
    };
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

    // ---- Round 12 / R11-7: concurrent probe runner (no BPF needed) ----

    fn sleep_job(ms: u64) -> Box<dyn FnOnce() -> Result<()> + Send> {
        Box::new(move || {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            Ok(())
        })
    }

    /// N jobs run concurrently: 3 × 60ms jobs finish in ~60ms, not ~180ms.
    #[test]
    fn run_jobs_concurrently_runs_jobs_in_parallel() {
        let start = std::time::Instant::now();
        let jobs: Vec<_> = vec![sleep_job(60), sleep_job(60), sleep_job(60)];
        let err = run_jobs_concurrently(jobs, || false).unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            format!("{err:#}").contains("stopped without a signal"),
            "{err:#}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(120),
            "3×60ms jobs ran concurrently, took {elapsed:?}"
        );
    }

    /// The first job error returns immediately, without waiting for the other
    /// (long-sleeping) jobs.
    #[test]
    fn run_jobs_concurrently_short_circuits_on_first_error() {
        let start = std::time::Instant::now();
        let jobs: Vec<_> = vec![
            sleep_job(800),
            Box::new(move || -> Result<()> { Err(anyhow!("probe boom")) }),
        ];
        let err = run_jobs_concurrently(jobs, || false).unwrap_err();
        let elapsed = start.elapsed();
        assert!(format!("{err:#}").contains("probe boom"), "{err:#}");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "short-circuited before the 800ms job, took {elapsed:?}"
        );
    }

    /// All jobs finishing Ok without an interrupt is an error: a trace module
    /// never legitimately ends on its own.
    #[test]
    fn run_jobs_concurrently_all_ok_without_interrupt_is_error() {
        let jobs: Vec<_> = vec![sleep_job(1), sleep_job(1), sleep_job(1)];
        let err = run_jobs_concurrently(jobs, || false).unwrap_err();
        assert!(
            format!("{err:#}").contains("all stack probes stopped without a signal"),
            "{err:#}"
        );
    }

    /// An interrupt returns Ok even while jobs are still running.
    #[test]
    fn run_jobs_concurrently_interrupt_returns_ok() {
        let start = std::time::Instant::now();
        let jobs: Vec<_> = vec![sleep_job(2000), sleep_job(2000)];
        let result = run_jobs_concurrently(jobs, || true);
        assert!(result.is_ok(), "{result:?}");
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "interrupt returns before the 2s jobs finish"
        );
    }

    // ---- Round 12 / R11-8: probe point renumbering ----

    fn blank_point(index: u32, enter_key: u32, exit_offset: u64) -> UprobeArgs {
        UprobeArgs {
            index,
            enter_key,
            exit_offset,
            ..Default::default()
        }
    }

    fn blank_probe() -> ProbeConfig {
        ProbeConfig {
            sconfig: crate::config::SConfig::default(),
            lib_name: String::new(),
            library: String::new(),
            symbol: String::new(),
            offset: 0,
        }
    }

    /// The invariant the BPF side relies on: `point.index` equals its position
    /// in the probe's vec, and a non-zero `enter_key` follows it (`pos + 1`).
    #[test]
    fn renumber_probe_points_aligns_index_and_enter_key() {
        let mut probes: Vec<(ProbeConfig, Vec<UprobeArgs>)> = vec![
            (
                blank_probe(),
                vec![
                    blank_point(1, 2, 0),
                    blank_point(4, 0, 0),
                    blank_point(9, 10, 0),
                ],
            ),
            (blank_probe(), vec![blank_point(3, 7, 0)]),
        ];
        renumber_probe_points(&mut probes);
        let points = &probes[0].1;
        let idx: Vec<u32> = points.iter().map(|p| p.index).collect();
        let keys: Vec<u32> = points.iter().map(|p| p.enter_key).collect();
        assert_eq!(idx, vec![0, 1, 2]);
        assert_eq!(
            keys,
            vec![1, 0, 3],
            "enter_key follows pos, zeros stay zero"
        );
        assert_eq!(probes[1].1[0].index, 0);
        assert_eq!(probes[1].1[0].enter_key, 1);
    }

    /// A companion exit point keeps its main point's `enter_key` (C pairs by
    /// key, not by position — `stack.c:59-70`): main at pos 0 → key 1,
    /// companion at pos 1 → key 1 too; the second main at pos 3 → key 4,
    /// its companion at pos 4 → key 4.
    #[test]
    fn renumber_probe_points_keeps_companion_enter_key_pairing() {
        let mut probes: Vec<(ProbeConfig, Vec<UprobeArgs>)> = vec![(
            blank_probe(),
            vec![
                blank_point(0, 5, 0x40), // main (exit companion follows)
                blank_point(1, 5, 0),    // companion
                blank_point(2, 0, 0),    // plain point, no exit
                blank_point(3, 9, 0x20), // main
                blank_point(4, 9, 0),    // companion
            ],
        )];
        renumber_probe_points(&mut probes);
        let points = &probes[0].1;
        let idx: Vec<u32> = points.iter().map(|p| p.index).collect();
        let keys: Vec<u32> = points.iter().map(|p| p.enter_key).collect();
        assert_eq!(idx, vec![0, 1, 2, 3, 4]);
        assert_eq!(keys, vec![1, 1, 0, 4, 4]);
    }

    /// Scenario A: a 3-point dev file produces one probe per point; each
    /// probe's single point must carry index 0 (= its position), not its file
    /// position (1/2), which used to make probes 2+ look up the wrong map key.
    #[test]
    fn build_probes_renumbers_dev_points() {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-dev-renum-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("libnative-lib.so"), b"").unwrap();
        let cfg = temp_cfg_path("dev-renum");
        std::fs::write(
            &cfg,
            r#"{"type": "uprobe", "library": "libnative-lib.so", "points": [
                {"name": "func1", "params": []},
                {"name": "func2", "params": []},
                {"name": "func3", "params": []}
            ]}"#,
        )
        .unwrap();
        let target = TargetConfig {
            library_dirs: vec![dir.to_string_lossy().to_string()],
            ..Default::default()
        };
        let probes = build_probes(&global_with_configs(vec![cfg.clone()]), &target, None).unwrap();
        assert_eq!(probes.len(), 3, "one probe per dev point");
        for (i, (_, points)) in probes.iter().enumerate() {
            assert_eq!(points.len(), 1);
            assert_eq!(
                points[0].index, 0,
                "probe {i} point index must equal its position"
            );
        }
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Scenario B: `dispatch_w_points` keeps stale indexes on the remaining
    /// `-w` points (e.g. `openat` at index 1 after a bound `write` was
    /// removed); the `-w` branch renumbers them to 0..m-1 and remaps
    /// `enter_key`.
    #[test]
    fn build_probes_renumbers_w_points_remaining() {
        let w_points = Some((
            "libtest.so".to_string(),
            vec![
                blank_point(1, 3, 0),
                blank_point(4, 0, 0),
                blank_point(7, 8, 0),
            ],
        ));
        let probes =
            build_probes(&GlobalConfig::default(), &TargetConfig::default(), w_points).unwrap();
        assert_eq!(probes.len(), 1);
        let points = &probes[0].1;
        let idx: Vec<u32> = points.iter().map(|p| p.index).collect();
        let keys: Vec<u32> = points.iter().map(|p| p.enter_key).collect();
        assert_eq!(idx, vec![0, 1, 2]);
        assert_eq!(keys, vec![1, 0, 3]);
    }

    /// Two dev files must not collide: every probe keeps the invariant
    /// `index == pos` regardless of which file (or position within it) it came
    /// from.
    #[test]
    fn build_probes_two_dev_files_no_collision() {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-dev2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("liba.so"), b"").unwrap();
        std::fs::write(dir.join("libb.so"), b"").unwrap();
        let cfg_a = temp_cfg_path("dev-a");
        let cfg_b = temp_cfg_path("dev-b");
        std::fs::write(
            &cfg_a,
            r#"{"type": "uprobe", "library": "liba.so", "points": [
                {"name": "fa1", "params": []},
                {"name": "fa2", "params": []}
            ]}"#,
        )
        .unwrap();
        std::fs::write(
            &cfg_b,
            r#"{"type": "uprobe", "library": "libb.so", "points": [
                {"name": "fb1", "params": []}
            ]}"#,
        )
        .unwrap();
        let target = TargetConfig {
            library_dirs: vec![dir.to_string_lossy().to_string()],
            ..Default::default()
        };
        let probes = build_probes(
            &global_with_configs(vec![cfg_a.clone(), cfg_b.clone()]),
            &target,
            None,
        )
        .unwrap();
        assert_eq!(probes.len(), 3);
        for (i, (_, points)) in probes.iter().enumerate() {
            assert_eq!(points.len(), 1);
            assert_eq!(points[0].index, 0, "probe {i}");
        }
        std::fs::remove_file(&cfg_a).unwrap();
        std::fs::remove_file(&cfg_b).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Shared dev-point harness: writes a temp config with `points`, resolves a
    /// temp library, and returns the `build_probes` result.
    fn build_dev_probes(
        tag: &str,
        points_json: &str,
    ) -> anyhow::Result<Vec<(ProbeConfig, Vec<UprobeArgs>)>> {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("libnative-lib.so"), b"").unwrap();
        let cfg = temp_cfg_path(tag);
        std::fs::write(
            &cfg,
            format!(
                r#"{{"type": "uprobe", "library": "libnative-lib.so", "points": {points_json}}}"#
            ),
        )
        .unwrap();
        let target = TargetConfig {
            library_dirs: vec![dir.to_string_lossy().to_string()],
            ..Default::default()
        };
        let result = build_probes(&global_with_configs(vec![cfg.clone()]), &target, None);
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        result
    }

    /// R11-1: an unknown signal name in a dev config must fail loudly instead
    /// of silently becoming 0 (no signal).
    #[test]
    fn build_probes_dev_config_rejects_unknown_signal() {
        let err = build_dev_probes(
            "dev-sig",
            r#"[{"name": "sym", "signal": "SIGBOGUS", "params": []}]"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("unknown signal"), "{err:#}");
    }

    /// R11-1: numeric signals stay accepted in dev configs (documented
    /// extension — same as `parse_signal_name("19") == 19`).
    #[test]
    fn build_probes_dev_config_numeric_signal() {
        let probes = build_dev_probes(
            "dev-sig-num",
            r#"[{"name": "sym", "signal": "19", "params": []}]"#,
        )
        .unwrap();
        let points: Vec<&UprobeArgs> = probes.iter().flat_map(|(_, ps)| ps.iter()).collect();
        assert_eq!(points[0].kill_signal, 19, "raw number signal");
    }

    /// R11-2: uppercase `0X…` is a symbol, never an offset (policy: only
    /// lowercase `0x` marks an offset; Go's `HasPrefix(..., "0x")` behaves the
    /// same).
    #[test]
    fn build_probes_dev_config_uppercase_0x_is_symbol() {
        let probes = build_dev_probes("dev-0X", r#"[{"name": "0X10", "params": []}]"#).unwrap();
        assert_eq!(probes.len(), 1);
        let (probe, points) = &probes[0];
        assert_eq!(probe.symbol, "0X10");
        assert_eq!(probe.offset, 0);
        assert_eq!(points[0].symbol, "0X10");
        assert_eq!(points[0].offset, 0);
    }

    /// R11-3: a master config whose offsets contain an uppercase `0X` entry
    /// must fail loudly (it used to be silently skipped).
    #[test]
    fn build_probes_master_uppercase_0x_offset_errors() {
        let dir = std::env::temp_dir().join(format!("stackplz-master-0X-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("bionic")).unwrap();
        std::fs::write(dir.join("bionic/libc.so"), b"").unwrap();
        let cfg = temp_cfg_path("master-0X");
        std::fs::write(
            &cfg,
            format!(
                r#"{{"library_dirs": [{}], "libs": [{{"library": "bionic/libc.so", "disable": false, "configs": [{{"symbols": [], "offsets": ["0X10"]}}]}}]}}"#,
                serde_json::to_string(&dir.to_string_lossy()).unwrap()
            ),
        )
        .unwrap();
        let global = global_with_configs(vec![cfg.clone()]);
        let err = build_probes(&global, &TargetConfig::default(), None).unwrap_err();
        assert!(format!("{err:#}").contains("must start with 0x"), "{err:#}");
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// R11-3: mixed `["0X10", "0x20"]` errors loudly too — no silent partial
    /// drop of the uppercase entry.
    #[test]
    fn build_probes_master_mixed_case_offsets_error() {
        let dir = std::env::temp_dir().join(format!("stackplz-master-mix-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("bionic")).unwrap();
        std::fs::write(dir.join("bionic/libc.so"), b"").unwrap();
        let cfg = temp_cfg_path("master-mix");
        std::fs::write(
            &cfg,
            format!(
                r#"{{"library_dirs": [{}], "libs": [{{"library": "bionic/libc.so", "disable": false, "configs": [{{"symbols": [], "offsets": ["0X10", "0x20"]}}]}}]}}"#,
                serde_json::to_string(&dir.to_string_lossy()).unwrap()
            ),
        )
        .unwrap();
        let global = global_with_configs(vec![cfg.clone()]);
        let err = build_probes(&global, &TargetConfig::default(), None).unwrap_err();
        assert!(format!("{err:#}").contains("must start with 0x"), "{err:#}");
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// R11-3: lowercase `0x` offsets still attach (gate is not over-strict).
    #[test]
    fn build_probes_master_lowercase_offset_loads() {
        let dir = std::env::temp_dir().join(format!("stackplz-master-ok-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("bionic")).unwrap();
        std::fs::write(dir.join("bionic/libc.so"), b"").unwrap();
        let cfg = temp_cfg_path("master-ok");
        std::fs::write(
            &cfg,
            format!(
                r#"{{"library_dirs": [{}], "libs": [{{"library": "bionic/libc.so", "disable": false, "configs": [{{"symbols": [], "offsets": ["0x20"]}}]}}]}}"#,
                serde_json::to_string(&dir.to_string_lossy()).unwrap()
            ),
        )
        .unwrap();
        let global = global_with_configs(vec![cfg.clone()]);
        let probes = build_probes(&global, &TargetConfig::default(), None).unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].0.offset, 0x20);
        std::fs::remove_file(&cfg).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
