//! Persistent pre-run logic. Mirrors `persistentPreRunEFunc` in
//! `cli/cmd/root.go:40-102`, plus the `parseByPackage` / `parseByUid` helpers.
//!
//! Responsibilities:
//!   1. Resolve the executable directory (`global_config.ExecPath`).
//!   2. Extract the bundled `preload_libs/*.so` next to the binary if missing.
//!   3. If `--prepare`, re-extract and `exit(0)`.
//!   4. Parse `--no-tids` into the target blacklist + mask.
//!   5. Resolve the target UID + library dirs from `--name` (dumpsys) or
//!      `--uid` (pm). Exactly one is required.

use crate::assets;
use crate::config::sconfig::parse_tid_blacklist;
use crate::config::{GlobalConfig, TargetConfig};
use anyhow::{anyhow, bail, Result};

/// The persistent pre-run. Runs before any subcommand's `Run`.
/// Mirrors `persistentPreRunEFunc`.
pub fn persistent_pre_run(
    global: &mut GlobalConfig,
    target: &mut TargetConfig,
) -> Result<()> {
    // 1. Executable directory.
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("please build as executable binary, {}", e))?;
    let exec_dir = exe
        .parent()
        .ok_or_else(|| anyhow!("cannot resolve executable directory"))?
        .to_string_lossy()
        .to_string();
    global.exec_path = exec_dir.clone();

    // 2. Extract preload_libs if missing.
    let preload_dir = format!("{}/preload_libs", exec_dir);
    let mut has_restored = false;
    if !std::path::Path::new(&preload_dir).exists() {
        assets::restore_assets(&exec_dir, "preload_libs")?;
        has_restored = true;
    }

    // 3. --prepare: re-extract (if needed) and exit 0.
    if global.prepare {
        if !has_restored {
            assets::restore_assets(&exec_dir, "preload_libs")?;
        }
        println!("RestoreAssets preload_libs success");
        std::process::exit(0);
    }

    // 4. Pid + tid blacklist.
    if global.pid > 0 {
        target.pid = global.pid;
    }
    let (blacklist, mask) = parse_tid_blacklist(&global.tids_blacklist)?;
    target.tid_blacklist = blacklist;
    target.tid_blacklist_mask = mask;

    // 5. Target resolution: exactly one of --name / --uid.
    if !global.name.is_empty() {
        parse_by_package(global, target, &global.name.clone())?;
    } else if global.uid != 0 {
        parse_by_uid(global, target, global.uid)?;
    } else {
        bail!("please set --uid or --name");
    }
    Ok(())
}

/// Resolve a UID to a package name via `pm list package --uid`, then resolve
/// the package. Mirrors `parseByUid` (`root.go:104-141`).
fn parse_by_uid(global: &mut GlobalConfig, target: &mut TargetConfig, uid: u64) -> Result<()> {
    let output = run_capture("pm", &["list", "package", "--uid", &uid.to_string()])?;
    let line = output.trim();
    if line.is_empty() {
        bail!("can not find package by uid={}", uid);
    }
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    if parts.len() != 2 {
        bail!("get package name by uid={} failed, sep => <=", uid);
    }
    let name_parts: Vec<&str> = parts[0].splitn(2, ':').collect();
    if name_parts.len() != 2 {
        bail!("get package name by uid={} failed, sep =>:<=", uid);
    }
    parse_by_package(global, target, name_parts[1])
}

/// Resolve a package name to UID + library dirs via `dumpsys package`.
/// Mirrors `parseByPackage` (`root.go:143-206`).
fn parse_by_package(
    global: &mut GlobalConfig,
    target: &mut TargetConfig,
    name: &str,
) -> Result<()> {
    target.name = name.to_string();
    global.name = name.to_string();

    let output = run_capture("dumpsys", &["package", name])?;
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "userId" => {
                    let uid: u64 = value.parse().unwrap_or(0);
                    target.uid = uid;
                    global.uid = uid; // fix global_config.Uid when only --name was set
                }
                "legacyNativeLibraryDir" => {
                    target.library_dirs.push(value.to_string());
                }
                "dataDir" => {
                    target.data_dir = value.to_string();
                }
                "primaryCpuAbi" => {
                    if value == "arm64-v8a" {
                        target.abi = value.to_string();
                        if target.library_dirs.len() != 1 {
                            bail!(
                                "can not find legacyNativeLibraryDir, cmd: dumpsys package {}",
                                name
                            );
                        }
                        target.library_dirs[0] = format!("{}/arm64", target.library_dirs[0]);
                    } else {
                        bail!("not support package={} primaryCpuAbi={}", name, value);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Run a command and capture stdout. Mirrors `cmd.StdoutPipe` + `ReadAll`.
fn run_capture(program: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| anyhow!("run {} failed: {}", program, e))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
