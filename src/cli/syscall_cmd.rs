//! `syscall` subcommand handler. Mirrors `syscallCommandFunc`
//! (`cli/cmd/syscall.go:40-136`).

use super::args::SyscallArgs;
use crate::config::{GlobalConfig, SyscallConfig, TargetConfig};
use crate::module::{SyscallTracepointModule, MODULE_NAME_SYSCALL};
use anyhow::{bail, Result};
use std::sync::Arc;

/// Split a comma separated option value into trimmed, non-empty items.
fn csv_items(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

/// Parse a comma separated `u32` id list.
///
/// Mirrors master's `ModuleConfig.Parse_Idlist` (`config_module.go:930`), which
/// panics on a malformed entry. A non-numeric token is never dropped silently:
/// dropping it would make e.g. `--no-pid 1,abc` stop filtering `1`'s peer
/// without telling the user, which is exactly the class of defect this mapping
/// fixes.
fn parse_u32_list(raw: &str, list_name: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for item in csv_items(raw) {
        match item.parse::<u32>() {
            Ok(value) => out.push(value),
            Err(_) => bail!("invalid {list_name} entry: {item:?} (expected a u32)"),
        }
    }
    Ok(out)
}

/// Parse a comma separated thread-name list (`Parse_Namelist`,
/// `config_module.go:963`). Empty items are skipped.
fn parse_name_list(raw: &str) -> Vec<String> {
    csv_items(raw).map(str::to_string).collect()
}

/// Parse the `-s`/`--no-syscall` list into syscall numbers.
///
/// The second element of the tuple reports whether the special `all` item was
/// present (`Parse_SyscallNames`, `config_module.go:560`): `-s all` means "no
/// sysno whitelist", i.e. `TRACE_ALL`. Token values that are neither `all` nor a
/// number are an error, as with the id lists above.
fn parse_syscall_numbers(raw: &str) -> Result<(Vec<u32>, bool)> {
    let mut numbers = Vec::new();
    let mut saw_all = false;
    for item in csv_items(raw) {
        if item == "all" {
            saw_all = true;
            continue;
        }
        match item.parse::<u32>() {
            Ok(value) => numbers.push(value),
            Err(_) => {
                bail!("invalid syscall entry: {item:?} (expected a syscall number or \"all\")")
            }
        }
    }
    Ok((numbers, saw_all))
}

/// Build the [`SyscallConfig`] for one syscall number.
///
/// Mirrors master's `persistentPreRunEFunc` filter mapping
/// (`cli/cmd/root.go:166-175`): the global uid/pid/tid/tname options are
/// `Parse_Idlist`/`Parse_Namelist`-ed into the module config, which is what
/// hands them to eBPF (`update_common_list` / `thread_filter` in
/// `src/module/syscall_tracepoint.rs`).
///
/// Without this mapping every `conf.*_whitelist`/`*_blacklist` stayed empty, so
/// `-p/-u/-t/--tname/--no-*` never reached the BPF side and
/// [`SyscallConfig::has_no_user_filter`] stayed `true`, forcing the permissive
/// "no filtering" fallback for every run.
pub fn build_config(
    global: &GlobalConfig,
    target: &TargetConfig,
    args: &SyscallArgs,
    sysno: i64,
) -> Result<SyscallConfig> {
    let mut conf = SyscallConfig::new();
    conf.sconfig.unwind_stack = args.stack;
    conf.sconfig.show_regs = args.regs;
    conf.sconfig.uid = global.uid;
    conf.sconfig.pid = global.pid;
    conf.sconfig.tid_blacklist = target.tid_blacklist;
    conf.sconfig.tid_blacklist_mask = target.tid_blacklist_mask;
    conf.config = args.config.clone();
    conf.nr = sysno;
    conf.debug = global.debug;

    // `-u`/`-p` are single valued with 0 meaning "not given"; the rest are
    // comma separated lists (master treats 0 as absent for these two as well).
    if global.uid != 0 {
        conf.uid_whitelist.push(global.uid as u32);
    }
    conf.uid_blacklist = parse_u32_list(&global.no_uid, "uid blacklist")?;
    if global.pid != 0 {
        conf.pid_whitelist.push(global.pid as u32);
    }
    conf.pid_blacklist = parse_u32_list(&global.no_pid, "pid blacklist")?;
    conf.tid_whitelist = parse_u32_list(&global.tid, "tid whitelist")?;
    conf.tid_blacklist = parse_u32_list(&global.tids_blacklist, "tid blacklist")?;
    conf.tname_whitelist = parse_name_list(&global.tname);
    conf.tname_blacklist = parse_name_list(&global.no_tname);

    // `-s <nr>[,<nr>...]` becomes the eBPF sysno whitelist that `TRACE_COMMON`
    // gates on. `-s all` must not gate at all, so the list stays empty and
    // `SyscallConfig::trace_mode()` yields `TRACE_ALL`.
    let (sys_whitelist, saw_all) = parse_syscall_numbers(&global.syscall)?;
    if !saw_all {
        conf.sys_whitelist = sys_whitelist;
    }
    // `--no-syscall` is a blacklist; eBPF applies it in both trace modes, so
    // its behaviour is unchanged by the `-s all` handling above.
    conf.sys_blacklist = parse_syscall_numbers(&global.no_syscall)?.0;

    Ok(conf)
}

/// Run the `syscall` subcommand. Mirrors `syscallCommandFunc`.
pub fn run(global: &mut GlobalConfig, target: &mut TargetConfig, args: SyscallArgs) -> Result<()> {
    // `syscall` subcommand uses the `syscall_` log prefix.
    let logger = Arc::new(crate::logger::Logger::new("syscall_", true));
    if !global.logger_file.is_empty() {
        logger.set_out_file(&global.exec_path, &global.logger_file, global.quiet)?;
    }

    let sysno_configs = vec![args.nr];
    let lib_path = format!("{}/preload_libs", global.exec_path);
    let mut run_count = 0u32;

    for sysno in sysno_configs {
        let conf = build_config(global, target, &args, sysno)?;

        logger.println(&format!("{}\thook nr:{}", MODULE_NAME_SYSCALL, conf.nr));

        let mod_logger = logger.clone();
        let mod_lib_path = lib_path.clone();
        let handle = std::thread::Builder::new()
            .name(format!("syscall-{}", sysno))
            .spawn(move || {
                let module = SyscallTracepointModule::new(conf, mod_lib_path);
                if let Err(e) = module.run(mod_logger) {
                    eprintln!("{} module error: {}", MODULE_NAME_SYSCALL, e);
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

    super::stack_cmd::wait_for_signal_exported();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{Cli, Command};
    use crate::contract::consts::{TRACE_ALL, TRACE_COMMON};
    use clap::Parser;

    fn u32_at(bytes: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap())
    }

    /// Parse `argv` exactly like `cli::start()` does and build the config the
    /// same way `run()` does, so the tests cover flag -> `SyscallConfig`.
    fn build(argv: &[&str]) -> Result<SyscallConfig> {
        let cli = Cli::try_parse_from(argv).expect("cli should parse");
        let global = GlobalConfig::from(&cli.global);
        let target = TargetConfig::default();
        let args = match cli.command {
            Some(Command::Syscall(args)) => args,
            _ => panic!("expected the syscall subcommand"),
        };
        build_config(&global, &target, &args, args.nr)
    }

    /// `-s all` means "every syscall": the whitelist stays empty so
    /// `trace_mode()` is `TRACE_ALL` and eBPF does not gate.
    #[test]
    fn sys_all_leaves_the_sysno_gate_open() {
        let conf = build(&["stackplz", "--uid", "10245", "-s", "all", "syscall"]).unwrap();
        assert!(
            conf.sys_whitelist.is_empty(),
            "-s all must not gate syscalls"
        );
        assert_eq!(conf.trace_mode(), TRACE_ALL);
        assert_eq!(u32_at(&conf.to_common_filter_bytes(), 4), TRACE_ALL);
    }

    /// Regression test for report §5.1 through the CLI: `-s 63,64` must produce
    /// the sysno whitelist *and* `TRACE_COMMON(0)`, otherwise the gate in
    /// `ebpf/syscall.c` is dead code and every syscall is traced.
    #[test]
    fn sysno_whitelist_switches_the_gate_on() {
        let conf = build(&["stackplz", "--uid", "10245", "-s", "63,64", "syscall"]).unwrap();
        assert_eq!(conf.sys_whitelist, vec![63, 64]);
        assert_eq!(conf.trace_mode(), TRACE_COMMON);
        assert_eq!(u32_at(&conf.to_common_filter_bytes(), 4), TRACE_COMMON);
    }

    /// `--no-syscall` alone keeps today's semantics: it fills the blacklist,
    /// does not fill the whitelist, and therefore does not close the gate
    /// (eBPF checks the blacklist in `TRACE_ALL` mode too).
    #[test]
    fn no_syscall_only_fills_the_blacklist() {
        let conf = build(&["stackplz", "--uid", "1", "--no-syscall", "63", "syscall"]).unwrap();
        assert!(conf.sys_whitelist.is_empty());
        assert_eq!(conf.sys_blacklist, vec![63]);
        assert_eq!(conf.trace_mode(), TRACE_ALL);
    }

    /// Regression test for report §5.3: every filtering flag must be mapped
    /// into the config lists that `update_common_list`/`update_thread_filter`
    /// push to eBPF, and the permissive fallback must be off.
    #[test]
    fn cli_filter_flags_reach_the_bpf_config() {
        let conf = build(&[
            "stackplz",
            "--uid",
            "1000",
            "--pid",
            "1234",
            "--tid",
            "111,222",
            "--no-tids",
            "333,444",
            "--tname",
            "alpha,beta",
            "--no-tname",
            "gamma",
            "--no-uid",
            "0,10",
            "--no-pid",
            "5",
            "syscall",
        ])
        .unwrap();

        // `sconfig` (uprobe side) keeps the single-valued fields.
        assert_eq!(conf.sconfig.uid, 1000);
        assert_eq!(conf.sconfig.pid, 1234);

        assert_eq!(conf.uid_whitelist, vec![1000]);
        assert_eq!(conf.uid_blacklist, vec![0, 10]);
        assert_eq!(conf.pid_whitelist, vec![1234]);
        assert_eq!(conf.pid_blacklist, vec![5]);
        assert_eq!(conf.tid_whitelist, vec![111, 222]);
        assert_eq!(conf.tid_blacklist, vec![333, 444]);
        assert_eq!(
            conf.tname_whitelist,
            vec!["alpha".to_string(), "beta".to_string()]
        );
        assert_eq!(conf.tname_blacklist, vec!["gamma".to_string()]);

        assert!(!conf.has_no_user_filter(), "filters are configured");
        let bytes = conf.to_common_filter_bytes();
        assert_eq!(
            bytes[20..24],
            0u32.to_ne_bytes(),
            "no_filter_allow must be 0 once a filter is configured"
        );
    }

    /// The mandatory target uid (`-u`/`-n` resolves to a uid) is itself a
    /// whitelist entry, so even a bare run must disable the permissive
    /// fallback and let `should_trace()` do its normal whitelist check.
    #[test]
    fn required_uid_alone_disables_the_permissive_fallback() {
        let conf = build(&["stackplz", "--uid", "10245", "syscall"]).unwrap();
        assert_eq!(conf.uid_whitelist, vec![10245]);
        assert!(!conf.has_no_user_filter());
        assert_eq!(
            u32_at(&conf.to_common_filter_bytes(), 20),
            0,
            "no_filter_allow"
        );
    }

    /// Boundary pin for the `-u 0` / `-u root` question (see `build_config`).
    ///
    /// Master's `-u` is a **string** (`root.go:621`, default `""`), and
    /// `Parse_Idlist` only early-returns on `""` (`config_module.go:930`), so
    /// master's `-u 0` really means "whitelist `[0]`" = trace root only.
    ///
    /// This crate's `-u` is `u64` with `0` as the "absent" sentinel
    /// (`cli/args.rs:57`), and `cli/root.rs:65` bails with "please set --uid or
    /// --name" when `uid == 0` without `--name` — so `uid == 0` can never reach
    /// this function as a user-chosen filter. Under that type the only sound
    /// reading is "not given", which is what `build_config` implements. The
    /// gap to master ("only trace root" is not expressible) is a pre-existing
    /// CLI-typing limitation, recorded as a residual risk in DONE.md §8.4
    /// rather than hard-coded here as an `uid == 0` special case.
    ///
    /// Excluding root *is* still expressible through the blacklist, which is
    /// the same path master uses.
    #[test]
    fn uid_zero_is_absent_not_trace_root_only() {
        // `--uid 0` parses (it is a valid u64) but yields no whitelist entry.
        let conf = build(&["stackplz", "--uid", "0", "syscall"]).unwrap();
        assert!(
            conf.uid_whitelist.is_empty(),
            "uid == 0 is the 'not given' sentinel of this crate's u64 flag"
        );
        assert!(conf.has_no_user_filter());

        // Excluding root works exactly like master: the blacklist is a list.
        let conf = build(&["stackplz", "--uid", "0", "--no-uid", "0", "syscall"]).unwrap();
        assert_eq!(conf.uid_blacklist, vec![0]);
        assert!(!conf.has_no_user_filter());

        // `-u root` is not a uid at all: master's `ParseUint` would panic, here
        // clap rejects it before any config is built.
        assert!(
            Cli::try_parse_from(["stackplz", "--uid", "root", "syscall"]).is_err(),
            "`-u root` must be rejected as a non-numeric uid"
        );
    }

    /// A non-numeric list entry is user error, not something to drop silently
    /// (master panics in `Parse_Idlist`/`Parse_SyscallNames`).
    #[test]
    fn non_numeric_list_entry_is_an_error() {
        let err = build(&["stackplz", "--uid", "1", "--no-uid", "abc", "syscall"]).unwrap_err();
        assert!(
            err.to_string().contains("uid blacklist"),
            "unexpected error: {err}"
        );

        let err = build(&["stackplz", "--uid", "1", "--tid", "12,x", "syscall"]).unwrap_err();
        assert!(
            err.to_string().contains("tid whitelist"),
            "unexpected error: {err}"
        );

        let err = build(&["stackplz", "--uid", "1", "-s", "open", "syscall"]).unwrap_err();
        assert!(
            err.to_string().contains("syscall entry"),
            "unexpected error: {err}"
        );
    }
}
