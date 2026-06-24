//! `stack` subcommand handler. Mirrors `stackCommandFunc` + `parseConfig`
//! (`cli/cmd/stack.go:74-307`).

use super::args::StackArgs;
use crate::config::hook_json::{hex2int, HookConfig};
use crate::config::{GlobalConfig, ProbeConfig, SConfig, StackConfig, TargetConfig};
use crate::module::{StackProbeModule, MODULE_NAME_STACK};
use crate::util::find_lib;
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// Run the `stack` subcommand. Mirrors `stackCommandFunc`.
pub fn run(global: &mut GlobalConfig, target: &mut TargetConfig, args: StackArgs) -> Result<()> {
    // Initialize the argtype subsystem before any type-related operations.
    crate::argtype::init_argtypes();

    let stack_cfg = StackConfig::from(&args);
    let logger = Arc::new(crate::logger::Logger::new("", true));

    // Logger file output (--out), exec-dir relative.
    if !global.logger_file.is_empty() {
        logger.set_out_file(&global.exec_path, &global.logger_file, global.quiet)?;
    }

    // Build the probe list.
    // Each probe may carry parsed hook points (from -w mode).
    let mut probes: Vec<(ProbeConfig, Vec<crate::config::UprobeArgs>)> = Vec::new();
    if !stack_cfg.hook_points.is_empty() {
        // -w/--point mode: parse hook point strings into UprobeArgs.
        // Use the global --library flag as the library path.
        let library = if stack_cfg.library != "/apex/com.android.runtime/lib64/bionic/libc.so" {
            find_lib(&stack_cfg.library, &target.library_dirs)?
        } else {
            find_lib(&global.library, &target.library_dirs)?
        };
        let points = crate::config::point_parser::parse_hook_point(
            &stack_cfg.hook_points,
            &library,
            global.dumphex,
            global.color,
        )?;
        // In -w mode, all points share one library, so we create one probe.
        let mut p = ProbeConfig {
            sconfig: SConfig {
                unwind_stack: stack_cfg.unwind_stack,
                show_regs: stack_cfg.show_regs,
                reg_name: stack_cfg.reg_name.clone(),
                uid: target.uid,
                pid: target.pid,
                tid_blacklist: target.tid_blacklist,
                tid_blacklist_mask: target.tid_blacklist_mask,
                ..Default::default()
            },
            lib_name: String::new(),
            library: library.clone(),
            symbol: String::new(),
            offset: 0,
        };
        p.check()?;
        probes.push((p, points));
        if global.debug {
            logger.println(&format!(
                "{}\tparsed {} hook points from -w flags",
                MODULE_NAME_STACK,
                probes[0].1.len()
            ));
        }
    } else if !stack_cfg.config.is_empty() {
        let cfg_probes = {
            let mut tmp = Vec::new();
            parse_config(&logger, global, target, &stack_cfg, &mut tmp)?;
            tmp
        };
        for p in cfg_probes {
            probes.push((p, Vec::new()));
        }
    } else {
        let library = find_lib(&stack_cfg.library, &target.library_dirs)?;
        let mut p = ProbeConfig {
            sconfig: SConfig {
                unwind_stack: stack_cfg.unwind_stack,
                show_regs: stack_cfg.show_regs,
                reg_name: stack_cfg.reg_name.clone(),
                uid: target.uid,
                pid: target.pid,
                tid_blacklist: target.tid_blacklist,
                tid_blacklist_mask: target.tid_blacklist_mask,
                ..Default::default()
            },
            lib_name: String::new(),
            library,
            symbol: stack_cfg.symbol.clone(),
            offset: stack_cfg.offset,
        };
        p.check()?;
        probes.push((p, Vec::new()));
    }

    let lib_path = format!("{}/preload_libs", global.exec_path);
    let mut run_count = 0u32;

    for (mut probe, hook_points) in probes {
        probe.sconfig.debug = global.debug;
        logger.println(&format!(
            "{}\thook info:{}",
            MODULE_NAME_STACK,
            probe.info()
        ));

        let mod_logger = logger.clone();
        let mod_lib_path = lib_path.clone();
        let kill = crate::module::stack_probe::parse_signal_name(&global.kill_signal);
        let tkill = crate::module::stack_probe::parse_signal_name(&global.tkill_signal);
        let auto_resume = global.auto_resume;
        let handle = std::thread::Builder::new()
            .name(format!("stack-{}", probe.info()))
            .spawn(move || {
                let module = StackProbeModule::new(probe, mod_lib_path)
                    .with_hook_points(hook_points)
                    .with_signals(kill, tkill, auto_resume);
                if let Err(e) = module.run(mod_logger) {
                    eprintln!("{} module error: {}", MODULE_NAME_STACK, e);
                }
            })
            .ok();
        if handle.is_some() {
            run_count += 1;
        }
    }

    if run_count == 0 {
        logger.println("No runnable modules, Exit(1)");
        std::process::exit(1);
    }
    logger.println(&format!("start {} modules", run_count));

    // Block on SIGINT/SIGTERM.
    wait_for_signal();
    Ok(())
}

/// Parse a `stack --config` JSON file into probe configs.
/// Mirrors `parseConfig` (`stack.go:199-307`).
fn parse_config(
    logger: &Arc<crate::logger::Logger>,
    global: &GlobalConfig,
    target: &TargetConfig,
    stack_cfg: &StackConfig,
    probes: &mut Vec<ProbeConfig>,
) -> Result<()> {
    let mut config_path = stack_cfg.config.clone();
    if !config_path.starts_with('/') && !std::path::Path::new(&config_path).exists() {
        config_path = format!("{}/{}", global.exec_path, config_path);
    }
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| anyhow!("Error when opening file: {}", e))?;
    let mut hook_cfg: HookConfig = serde_json::from_str(&content)?;

    // Merge library_dirs from the file with the target's discovered dirs.
    hook_cfg
        .library_dirs
        .extend(target.library_dirs.iter().cloned());

    for lib_hook in &hook_cfg.libs {
        if lib_hook.disable {
            if global.debug {
                logger.println(&format!("disabled, skip hook {}", lib_hook.library));
            }
            continue;
        }
        let library = find_lib(&lib_hook.library, &hook_cfg.library_dirs)?;
        let mut seen_symbols: Vec<String> = Vec::new();
        let mut seen_offsets: Vec<String> = Vec::new();

        for base in &lib_hook.configs {
            // Symbols.
            for symbol in &base.symbols {
                let symbol = symbol.trim();
                if symbol.is_empty() {
                    continue;
                }
                if seen_symbols.iter().any(|s| s == symbol) {
                    logger.println(&format!("duplicated symbol:{}", symbol));
                    continue;
                }
                seen_symbols.push(symbol.to_string());
                let mut p = ProbeConfig {
                    sconfig: SConfig {
                        unwind_stack: base.unwindstack,
                        show_regs: base.regs,
                        uid: target.uid,
                        pid: target.pid,
                        ..Default::default()
                    },
                    lib_name: String::new(),
                    library: library.clone(),
                    symbol: symbol.to_string(),
                    offset: 0,
                };
                p.check()?;
                probes.push(p);
            }
            // Offsets (hex strings, must start with 0x).
            for offset in &base.offsets {
                let offset = offset.trim();
                if offset.is_empty() {
                    continue;
                }
                if !offset.starts_with("0x") {
                    logger.println(&format!("must start with 0x, offset:{}", offset));
                    continue;
                }
                if seen_offsets.iter().any(|s| s == offset) {
                    logger.println(&format!("duplicated offset:{}", offset));
                    continue;
                }
                seen_offsets.push(offset.to_string());
                let mut p = ProbeConfig {
                    sconfig: SConfig {
                        unwind_stack: base.unwindstack,
                        show_regs: base.regs,
                        uid: target.uid,
                        pid: target.pid,
                        ..Default::default()
                    },
                    lib_name: String::new(),
                    library: library.clone(),
                    symbol: String::new(),
                    offset: hex2int(offset),
                };
                p.check()?;
                probes.push(p);
            }
        }
    }
    if global.debug {
        logger.println(&format!("hook count {}", probes.len()));
    }
    Ok(())
}

/// Block until SIGINT/SIGTERM arrives. Mirrors `<-stopper` in Go.
#[cfg(unix)]
pub fn wait_for_signal() {
    use std::os::raw::c_int;
    extern "C" {
        fn signal(signum: c_int, handler: usize) -> usize;
    }
    // AtomicBool is Sync, so a plain `static` (not `static mut`) is sound and
    // avoids the `static_mut_refs` / `unsafe` access warnings.
    static CAUGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    extern "C" fn handler(_sig: c_int) {
        CAUGHT.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;
    unsafe {
        signal(SIGINT, handler as *const () as usize);
        signal(SIGTERM, handler as *const () as usize);
    }
    while !CAUGHT.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(not(unix))]
pub fn wait_for_signal() {
    // Non-unix hosts can't receive SIGINT the unix way; just block forever
    // (this path is only hit in tests, never on the real device).
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

// Re-export under a stable name for sibling handlers.
pub use wait_for_signal as wait_for_signal_exported;
