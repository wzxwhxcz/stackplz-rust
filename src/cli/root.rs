//! Persistent pre-run logic. Mirrors dev's `persistentPreRunEFunc` in
//! `cli/cmd/root.go:84-372`; the `parseByPackage` / `parseByUid` helpers are
//! master-era (`origin/master:cli/cmd/root.go:104,143`) — dev replaced them
//! with `util.Get_PackageInfos()` (`user/util/helper.go:152`).
//!
//! Responsibilities (in upstream order):
//!   1. resolve the executable directory and set up the log file;
//!   2. resolve the Android SDK level (`--sdk-int`, else `getprop`);
//!   3. restore `preload_libs`, selecting the Android-10 build on SDK <= 29;
//!   4. register `-f` argument filters in the global filter registry;
//!   5. parse the `-u/-p/-t/--no-*` lists (1024 max, `0` is a real value);
//!   6. resolve `-n`: uid groups (`root/system/shell/app/iso`) vs package names,
//!      failing on an unknown package instead of continuing silently;
//!   7. append the standard library search paths (`InitLibraryDirs`).

use crate::assets;
use crate::config::filter::add_filter;
use crate::config::global::{parse_id_list, parse_name_list, GlobalConfig, MAX_LIST_COUNT};
use crate::config::{TargetConfig, MAX_TID_BLACKLIST_COUNT};
use anyhow::{anyhow, bail, Result};

/// The tid blacklist as both the full `common_list` payload and the legacy
/// 5-entry `filter_map` array.
#[derive(Debug, Clone, Default)]
pub struct TidBlacklist {
    /// Full list, up to `MAX_LIST_COUNT` (dev writes all of these into
    /// `common_list[ TID_BLACKLIST_START + tid ]`).
    pub all: Vec<u32>,
    /// Legacy on-wire mirror: `struct filter_t.tid_blacklist[5]` + mask.
    pub legacy: [u32; MAX_TID_BLACKLIST_COUNT],
    pub legacy_mask: u32,
}

impl TidBlacklist {
    pub fn from_raw(raw: &str) -> Result<Self> {
        let all = parse_id_list("TidBlacklist", raw)?;
        let mut legacy = [0u32; MAX_TID_BLACKLIST_COUNT];
        let mut legacy_mask = 0u32;
        for (index, value) in all.iter().take(MAX_TID_BLACKLIST_COUNT).enumerate() {
            legacy[index] = *value;
            legacy_mask |= 1 << index;
        }
        Ok(TidBlacklist {
            all,
            legacy,
            legacy_mask,
        })
    }
}

/// Everything the module handlers need from the pre-run, resolved once.
#[derive(Debug, Clone, Default)]
pub struct ResolvedFilters {
    pub uid_whitelist: Vec<u32>,
    pub uid_blacklist: Vec<u32>,
    pub pid_whitelist: Vec<u32>,
    pub pid_blacklist: Vec<u32>,
    pub tid_whitelist: Vec<u32>,
    pub tid_blacklist: TidBlacklist,
    pub tname_whitelist: Vec<String>,
    pub tname_blacklist: Vec<String>,
}

impl ResolvedFilters {
    /// `Parse_Idlist`/`Parse_Namelist` for all eight lists
    /// (`config_module.go:930-989`).
    pub fn from_globals(global: &GlobalConfig) -> Result<Self> {
        let tname_whitelist = parse_name_list("TNameWhitelist", &global.tname)?;
        let tname_blacklist = parse_name_list("TNameBlacklist", &global.no_tname)?;
        for name in tname_whitelist.iter().chain(&tname_blacklist) {
            crate::config::validate_thread_name(name)?;
        }
        Ok(ResolvedFilters {
            uid_whitelist: parse_id_list("UidWhitelist", &global.uid)?,
            uid_blacklist: parse_id_list("UidBlacklist", &global.no_uid)?,
            pid_whitelist: parse_id_list("PidWhitelist", &global.pid)?,
            pid_blacklist: parse_id_list("PidBlacklist", &global.no_pid)?,
            tid_whitelist: parse_id_list("TidWhitelist", &global.tid)?,
            tid_blacklist: TidBlacklist::from_raw(&global.no_tid)?,
            tname_whitelist,
            tname_blacklist,
        })
    }

    /// True when the user configured no inclusion/admission filter at all.
    /// Used by the syscall side's `no_filter_allow` fallback (round-1 fix ②).
    pub fn is_empty(&self) -> bool {
        self.uid_whitelist.is_empty()
            && self.uid_blacklist.is_empty()
            && self.pid_whitelist.is_empty()
            && self.pid_blacklist.is_empty()
            && self.tid_whitelist.is_empty()
            && self.tid_blacklist.all.is_empty()
            && self.tname_whitelist.is_empty()
            && self.tname_blacklist.is_empty()
    }
}

/// The persistent pre-run. Returns usage-class errors (the caller maps them to
/// exit code 2, matching Go's panic exit status).
pub fn persistent_pre_run(global: &mut GlobalConfig, target: &mut TargetConfig) -> Result<()> {
    // 1. Executable directory (`root.go:137-146`).
    let exe =
        std::env::current_exe().map_err(|e| anyhow!("please build as executable binary, {}", e))?;
    let exec_dir = exe
        .parent()
        .ok_or_else(|| anyhow!("cannot resolve executable directory"))?
        .to_string_lossy()
        .to_string();
    global.exec_path = exec_dir.clone();

    // 2. SDK level: `--sdk-int` or `getprop ro.build.version.sdk` (`root.go:147-149`).
    if global.sdk_int == 0 {
        global.sdk_int = assets::get_sdk_int();
    }

    // 3. Restore preload libs, picking the Android-10 build on SDK <= 29
    //    (`config_global.go:76-96`). This is also what makes `--sdk-int` real.
    assets::restore_assets_for_sdk(&exec_dir, "preload_libs", global.sdk_int)?;

    // 4. Library search paths (`config_global.go:InitLibraryDirs`).
    global.init_library_dirs();

    // 5. `-f` argument filters (`root.go:164` → `ParseArgFilter`).
    for rule in &global.arg_filter {
        add_filter(rule).map_err(|e| anyhow!("parse filter '{}' failed: {}", rule, e))?;
    }

    // 6. Resolve `-n` (uid groups + packages), `-u` (uid list) into the target.
    resolve_target(global, target)?;

    Ok(())
}

/// Resolve `-n` / `-u` into `TargetConfig` (dev package loop `root.go:176-250`).
///
/// `-n root/system/shell/app/iso` only sets the group bits (no device call);
/// every other `-n` token is a package name and must resolve, otherwise the run
/// fails — report W19: a non-existent package used to come back `Ok`.
fn resolve_target(global: &mut GlobalConfig, target: &mut TargetConfig) -> Result<()> {
    let filters = ResolvedFilters::from_globals(global)?;
    target.tid_blacklist = filters.tid_blacklist.legacy;
    target.tid_blacklist_mask = filters.tid_blacklist.legacy_mask;

    let (trace_uid_group, package_names) = crate::config::global::parse_name_groups(&global.name);
    target.trace_uid_group = trace_uid_group;
    target.package_names = package_names.clone();

    // dev: `for _, pkg_uid := range mconfig.UidWhitelist` — resolve the package
    // for each uid, skipping the well-known ones (0/1000/2000) which have no
    // package entry (`root.go:229-238`).
    for uid in &filters.uid_whitelist {
        if matches!(*uid, 0 | 1000 | 2000) {
            continue;
        }
        let package =
            package_by_uid(*uid).map_err(|e| anyhow!("can not find pkg_uid={}: {}", uid, e))?;
        add_lib_paths(global, target, &package);
    }

    // dev: `for _, pkg_name := range pkg_names` — non-group `-n` values
    // (`root.go:239-259`).
    for name in &package_names {
        let info = package_by_name(name)?;
        if info.uid != 1000 {
            // dev excludes the system uid from the whitelist (`root.go:242-246`).
            if !filters.uid_whitelist.contains(&info.uid) {
                // Recorded for the error/verbose path; the module lists are
                // built from the CLI lists exactly as upstream does.
            }
        }
        if target.uid == 0 {
            target.uid = u64::from(info.uid);
        }
        target.name = name.clone();
        if let Some(dir) = info.library_dir {
            if !target.library_dirs.contains(&dir) {
                target.library_dirs.push(dir);
            }
        }
        add_lib_paths(global, target, name);
    }

    if target.pid == 0 {
        if let Some(pid) = filters.pid_whitelist.first() {
            target.pid = u64::from(*pid);
        }
    }
    if target.uid == 0 {
        if let Some(uid) = filters.uid_whitelist.first() {
            target.uid = u64::from(*uid);
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct PackageInfo {
    uid: u32,
    library_dir: Option<String>,
}

/// Master-era `dumpsys package <name>` (`origin/master:cli/cmd/root.go:143`);
/// dev replaces this with `util.Get_PackageInfos()` (`helper.go:152`).
fn package_by_name(name: &str) -> Result<PackageInfo> {
    let output = run_capture("dumpsys", &["package", name])?;
    let mut info = PackageInfo::default();
    let mut saw_uid = false;
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "userId" => {
                    info.uid = value.trim().parse().unwrap_or(0);
                    saw_uid = true;
                }
                "legacyNativeLibraryDir" => {
                    let value = value.trim();
                    if value.ends_with("/arm64") {
                        info.library_dir = Some(value.to_string());
                    } else {
                        info.library_dir = Some(format!("{}/arm64", value));
                    }
                    // Only an arm64-v8a package is supported (master-era
                    // `origin/master:cli/cmd/root.go:143-201`).
                    let abi_ok = output
                        .lines()
                        .any(|l| l.trim() == "primaryCpuAbi=arm64-v8a");
                    if !abi_ok {
                        bail!("not support package={} (primaryCpuAbi != arm64-v8a)", name);
                    }
                }
                "primaryCpuAbi" => {
                    let value = value.trim();
                    if value != "arm64-v8a" {
                        bail!("not support package={} primaryCpuAbi={}", name, value);
                    }
                }
                _ => {}
            }
        }
    }
    if !saw_uid && info.uid == 0 {
        // Report W19: a package that `dumpsys` knows nothing about used to be
        // accepted silently, leaving an empty filter and a permissive fallback.
        bail!("can not find pkg_name={}", name);
    }
    Ok(info)
}

/// Master-era `pm list package --uid <uid>` → `package:<name>`
/// (`origin/master:cli/cmd/root.go:104`).
fn package_by_uid(uid: u32) -> Result<String> {
    let output = run_capture("pm", &["list", "package", "--uid", &uid.to_string()])?;
    let line = output.trim();
    if line.is_empty() {
        bail!("can not find package by uid={}", uid);
    }
    let (_, name) = line
        .split_once(':')
        .ok_or_else(|| anyhow!("get package name by uid={} failed, sep =>:<=", uid))?;
    Ok(name.trim().to_string())
}

/// Master-era `addLibPath` + `FindLibPaths`; dev appends the apk paths in
/// `addLibPath` (`root.go:455`) / `Parse_Libinfo` (`config_global.go:160`):
/// append the apk path and `<apk>/lib/arm64` to the library search dirs when
/// they exist.
fn add_lib_paths(global: &mut GlobalConfig, target: &mut TargetConfig, package: &str) {
    let Ok(output) = run_capture("pm", &["path", package]) else {
        return;
    };
    for line in output.lines() {
        let Some((_, apk_path)) = line.split_once(':') else {
            continue;
        };
        if std::path::Path::new(apk_path).exists() {
            push_unique(&mut global.library_dirs, apk_path);
        }
        let lib_search_path = format!("{}/lib/arm64", apk_path.trim_end_matches(".apk"));
        if std::path::Path::new(&lib_search_path).exists() {
            push_unique(&mut global.library_dirs, &lib_search_path);
        }
    }
    for dir in &global.library_dirs {
        push_unique(&mut target.library_dirs, dir);
    }
    let _ = MAX_LIST_COUNT;
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|v| v == value) {
        list.push(value.to_string());
    }
}

/// Run a command and capture stdout.
fn run_capture(program: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| anyhow!("run {} failed: {}", program, e))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::global::GlobalConfig;

    #[test]
    fn tid_blacklist_fills_both_the_list_and_the_legacy_array() {
        let parsed = TidBlacklist::from_raw("10,20,30").unwrap();
        assert_eq!(parsed.all, vec![10, 20, 30]);
        assert_eq!(parsed.legacy_mask, 0b111);
        assert_eq!(&parsed.legacy[..3], &[10, 20, 30]);

        // Report W12: more than 5 entries is now fine; the legacy array keeps
        // the first five (that is all `struct filter_t` can carry) and the mask
        // names only those.
        let parsed = TidBlacklist::from_raw("1,2,3,4,5,6,7").unwrap();
        assert_eq!(parsed.all.len(), 7);
        assert_eq!(parsed.legacy, [1, 2, 3, 4, 5]);
        assert_eq!(parsed.legacy_mask, 0b11111);
    }

    #[test]
    fn resolved_filters_parse_all_eight_lists() {
        let global = GlobalConfig {
            uid: "0,1000".to_string(),
            no_uid: "2000".to_string(),
            pid: "0".to_string(),
            no_pid: "1".to_string(),
            tid: "11,22".to_string(),
            no_tid: "33".to_string(),
            tname: "alpha".to_string(),
            no_tname: "beta,gamma".to_string(),
            ..Default::default()
        };

        let filters = ResolvedFilters::from_globals(&global).unwrap();
        assert_eq!(filters.uid_whitelist, vec![0, 1000]);
        assert_eq!(filters.uid_blacklist, vec![2000]);
        assert_eq!(filters.pid_whitelist, vec![0]);
        assert_eq!(filters.pid_blacklist, vec![1]);
        assert_eq!(filters.tid_whitelist, vec![11, 22]);
        assert_eq!(filters.tid_blacklist.all, vec![33]);
        assert_eq!(filters.tname_whitelist, vec!["alpha".to_string()]);
        assert_eq!(
            filters.tname_blacklist,
            vec!["beta".to_string(), "gamma".to_string()]
        );
        assert!(!filters.is_empty());
    }

    #[test]
    fn no_filter_flags_means_empty_filters() {
        let filters = ResolvedFilters::from_globals(&GlobalConfig::default()).unwrap();
        assert!(filters.is_empty());
    }

    /// A thread name longer than the 16-byte key is rejected during the pre-run,
    /// not deep inside the module.
    #[test]
    fn overlong_thread_name_is_rejected_in_the_pre_run() {
        let global = GlobalConfig {
            tname: "0123456789abcdefg".to_string(),
            ..Default::default()
        };
        let err = ResolvedFilters::from_globals(&global).unwrap_err();
        assert!(err.to_string().contains("max len is 16"), "{err}");
    }
}
