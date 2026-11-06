//! Global CLI state. Mirrors `GlobalConfig` in `user/config/config_global.go`
//! plus the string-list parsing that upstream does in
//! `persistentPreRunEFunc` (`cli/cmd/root.go:160-175`) via
//! `ModuleConfig.Parse_Idlist` / `Parse_Namelist` (`config_module.go:930-971`).
//!
//! Two deliberate porting choices:
//!
//! 1. **`-u/-p/-t` stay strings all the way to the parser**, exactly like dev
//!    (`root.go:621-623` uses `StringVarP`). Round 2's `u64` flags with `0` as
//!    an "absent" sentinel made `-u 0` ("trace root only") and multi-uid lists
//!    inexpressible; that type is gone. See DONE.md §W11 for the conflict note
//!    against the round-2 decision.
//! 2. **List limits are 1024**, dev's `MAX_COUNT` (`config_const.go:11`), not
//!    master's 5-entry `tid_blacklist[5]` array bound. The legacy 5-entry array
//!    in `SConfig` is still filled for the `filter_map` wire struct, but it no
//!    longer bounds the CLI.

use anyhow::{bail, Result};

use crate::cli::args::Cli;
use crate::contract::enums::TraceGroup;

/// dev `config.MAX_COUNT` (`user/config/config_const.go:11`).
pub const MAX_LIST_COUNT: usize = 1024;

/// Mirrors Go `config.GlobalConfig`.
#[derive(Debug, Clone, Default)]
pub struct GlobalConfig {
    // ---- target / filter (raw strings, exactly like cobra's StringVarP) ----
    pub name: String,
    pub uid: String,
    pub pid: String,
    pub tid: String,
    pub no_uid: String,
    pub no_pid: String,
    pub no_tid: String,
    pub tname: String,
    pub no_tname: String,
    pub full_tname: bool,
    pub arg_filter: Vec<String>,

    // ---- signals ----
    pub auto_resume: bool,
    pub kill_signal: String,
    pub tkill_signal: String,

    // ---- syscall hook ----
    pub syscall: String,
    pub no_syscall: String,
    pub config_files: Vec<String>,

    // ---- uprobe hook ----
    pub hook_point: Vec<String>,
    pub library: String,
    pub library_dirs: Vec<String>,
    pub reg_name: String,

    // ---- output / logging ----
    pub unwind_stack: bool,
    pub show_regs: bool,
    pub stack_size: u32,
    pub dump_hex: bool,
    pub fmt_json: bool,
    pub color: bool,
    pub debug: bool,
    pub quiet: bool,
    pub log_file: String,

    // ---- runtime ----
    pub sdk_int: u32,
    pub nocheck: bool,
    pub buffer: u32,

    /// Directory of the running executable; populated by `persistent_pre_run`.
    pub exec_path: String,
}

impl GlobalConfig {
    pub fn from(cli: &Cli) -> Self {
        Self {
            name: cli.name.clone(),
            uid: cli.uid.clone(),
            pid: cli.pid.clone(),
            tid: cli.tid.clone(),
            no_uid: cli.no_uid.clone(),
            no_pid: cli.no_pid.clone(),
            no_tid: cli.no_tid.clone(),
            tname: cli.tname.clone(),
            no_tname: cli.no_tname.clone(),
            full_tname: cli.full_tname,
            arg_filter: cli.filter.clone(),
            auto_resume: cli.auto,
            kill_signal: cli.kill.clone(),
            tkill_signal: cli.tkill.clone(),
            syscall: cli.syscall.clone(),
            no_syscall: cli.no_syscall.clone(),
            config_files: cli.config.clone(),
            hook_point: cli.point.clone(),
            library: cli.library.clone(),
            library_dirs: cli.libdirs.clone(),
            reg_name: cli.reg.clone(),
            unwind_stack: cli.stack,
            show_regs: cli.regs,
            stack_size: cli.stack_size,
            dump_hex: cli.dumphex,
            fmt_json: cli.json,
            color: cli.color,
            debug: cli.debug,
            quiet: cli.quiet,
            log_file: cli.out.clone(),
            sdk_int: cli.sdk_int,
            nocheck: cli.nocheck,
            buffer: cli.buffer,
            exec_path: String::new(),
        }
    }

    /// `Is32Bit()`. On dev this is a build-tag constant of the *host binary*
    /// (`config_global_forarm64.go:6-8` → false). This crate instead reports the
    /// **target task** ABI at runtime (`is_current_task_compat32()` in
    /// `ebpf/common/task.h`) and keeps this field 0 — an intentional round-2
    /// choice that must not be rolled back (brief item 8).
    pub fn is_32bit(&self) -> bool {
        false
    }

    /// `InitLibraryDirs()` (`config_global_forarm64.go:14-24`): the standard
    /// Android library search paths for the target ABI.
    pub fn init_library_dirs(&mut self) {
        let paths: &[&str] = if cfg!(target_pointer_width = "32") {
            &[
                "/system/lib",
                "/apex/com.android.art/lib",
                "/apex/com.android.conscrypt/lib",
                "/apex/com.android.runtime/bin",
                "/apex/com.android.runtime/lib/bionic",
            ]
        } else {
            &[
                "/system/lib64",
                "/apex/com.android.art/lib64",
                "/apex/com.android.conscrypt/lib64",
                "/apex/com.android.runtime/bin",
                "/apex/com.android.runtime/lib64/bionic",
            ]
        };
        for path in paths {
            if !self.library_dirs.iter().any(|p| p == path) {
                self.library_dirs.push((*path).to_string());
            }
        }
    }
}

/// `ModuleConfig.Parse_Idlist` (`config_module.go:930-961`): split on ',', cap
/// at [`MAX_LIST_COUNT`], parse each item as a `u32`.
///
/// Upstream `panic`s on a bad entry; here it is an error that the CLI turns into
/// exit code 2 (Go's panic exit status), so scripts see the same failure class.
pub fn parse_id_list(list_name: &str, raw: &str) -> Result<Vec<u32>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let items: Vec<&str> = raw.split(',').collect();
    if items.len() > MAX_LIST_COUNT {
        bail!(
            "max {list_name} count is {MAX_LIST_COUNT}, provided count:{}",
            items.len()
        );
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let item = item.trim();
        let value: u32 = item
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid {list_name} entry: {item:?} (expected a u32)"))?;
        out.push(value);
    }
    Ok(out)
}

/// `ModuleConfig.Parse_Namelist` (`config_module.go:963-989`).
pub fn parse_name_list(list_name: &str, raw: &str) -> Result<Vec<String>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let items: Vec<&str> = raw.split(',').collect();
    if items.len() > MAX_LIST_COUNT {
        bail!(
            "max {list_name} count is {MAX_LIST_COUNT}, provided count:{}",
            items.len()
        );
    }
    Ok(items.into_iter().map(str::to_string).collect())
}

/// Split `-n` into uid-group bits and package names.
///
/// Mirrors `persistentPreRunEFunc` (`root.go:206-250`): `root`, `system`,
/// `shell`, `app`, `iso` set the corresponding `TraceGroup` bit; anything else
/// is a package name that has to be resolved with `dumpsys`. dev ORs the bits
/// into `mconfig.TraceGroup`; `root` is `1 << 1`, not `1 << 0`
/// (`user/util/helper.go:290-295`).
pub fn parse_name_groups(raw: &str) -> (u32, Vec<String>) {
    let mut groups: u32 = 0;
    let mut packages: Vec<String> = Vec::new();
    for name in raw.split(',') {
        match name {
            "" => {}
            "root" => groups |= TraceGroup::Root as u32,
            "system" => groups |= TraceGroup::System as u32,
            "shell" => groups |= TraceGroup::Shell as u32,
            "app" => groups |= TraceGroup::App as u32,
            "iso" => groups |= TraceGroup::Iso as u32,
            other => {
                if !packages.iter().any(|p| p == other) {
                    packages.push(other.to_string());
                }
            }
        }
    }
    (groups, packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv).expect("argv should parse")
    }

    /// Report W11/§4.2: a string list makes `-u 0` (trace root only) and
    /// multi-uid lists expressible, which the previous `u64` flag could not do.
    #[test]
    fn uid_zero_is_a_real_whitelist_entry() {
        let ids = parse_id_list("UidWhitelist", "0").unwrap();
        assert_eq!(ids, vec![0], "dev: -u 0 means `whitelist [0]` = root only");

        let ids = parse_id_list("UidWhitelist", "1000,1001").unwrap();
        assert_eq!(ids, vec![1000, 1001]);
    }

    /// Empty string means "flag not given" (upstream early-returns).
    #[test]
    fn empty_list_means_no_filter() {
        assert!(parse_id_list("UidWhitelist", "").unwrap().is_empty());
        assert!(parse_name_list("TNameWhitelist", "").unwrap().is_empty());
    }

    /// Report W12: the limit is dev's 1024, not master's 5.
    #[test]
    fn list_limit_is_one_thousand_twenty_four() {
        let raw: Vec<String> = (0..MAX_LIST_COUNT).map(|i| i.to_string()).collect();
        let raw = raw.join(",");
        assert_eq!(
            parse_id_list("TidBlacklist", &raw).unwrap().len(),
            MAX_LIST_COUNT
        );

        let too_many: Vec<String> = (0..MAX_LIST_COUNT + 1).map(|i| i.to_string()).collect();
        let err = parse_id_list("TidBlacklist", &too_many.join(",")).unwrap_err();
        assert!(
            err.to_string().contains("max TidBlacklist count is 1024"),
            "{err}"
        );

        // The old master-shaped bound was 5; 6 entries must now be fine.
        assert_eq!(
            parse_id_list("TidBlacklist", "1,2,3,4,5,6").unwrap().len(),
            6
        );
    }

    /// A non-numeric entry is user error (upstream panics in `ParseUint`).
    #[test]
    fn non_numeric_entry_is_an_error() {
        let err = parse_id_list("UidWhitelist", "1000,abc").unwrap_err();
        assert!(
            err.to_string().contains("invalid UidWhitelist entry"),
            "{err}"
        );
        // A trailing comma is an empty item, not a silent zero.
        assert!(parse_id_list("UidWhitelist", "1000,").is_err());
    }

    /// `-n root` must set the uid group, not be treated as a package name
    /// (report W4/F3: the Rust CLI used to look every `-n` value up as a package).
    #[test]
    fn name_groups_are_recognised_before_package_lookup() {
        let (groups, packages) = parse_name_groups("root,system,app,com.example");
        assert_eq!(
            groups,
            TraceGroup::Root as u32 | TraceGroup::System as u32 | TraceGroup::App as u32
        );
        assert_eq!(packages, vec!["com.example".to_string()]);

        assert_eq!(parse_name_groups("root").0, 1 << 1);
        assert!(parse_name_groups("root").1.is_empty());
        // Empty tokens (e.g. `-n ""`) set nothing.
        assert_eq!(parse_name_groups("").0, 0);
        assert!(parse_name_groups("").1.is_empty());
    }

    /// Library dirs get the standard ABI paths appended (dev `InitLibraryDirs`).
    #[test]
    fn init_library_dirs_appends_standard_paths() {
        let mut conf = GlobalConfig::default();
        conf.library_dirs.push("/custom".to_string());
        conf.init_library_dirs();
        assert_eq!(conf.library_dirs[0], "/custom");
        assert!(conf.library_dirs.iter().any(|p| p.contains("bionic")));
        // Idempotent: calling it twice does not duplicate entries.
        let count = conf.library_dirs.len();
        conf.init_library_dirs();
        assert_eq!(conf.library_dirs.len(), count);
    }

    #[test]
    fn flags_are_copied_from_the_cli() {
        let cli = parse(&[
            "stackplz",
            "-u",
            "1000",
            "-n",
            "root",
            "-s",
            "%file",
            "--no-syscall",
            "openat",
            "--stack-size",
            "16384",
            "-b",
            "16",
            "--sdk-int",
            "28",
            "--nocheck",
        ]);
        let g = GlobalConfig::from(&cli);
        assert_eq!(g.uid, "1000");
        assert_eq!(g.name, "root");
        assert_eq!(g.syscall, "%file");
        assert_eq!(g.no_syscall, "openat");
        assert_eq!(g.stack_size, 16384);
        assert_eq!(g.buffer, 16);
        assert_eq!(g.sdk_int, 28);
        assert!(g.nocheck);
        assert!(!g.is_32bit());
    }
}
