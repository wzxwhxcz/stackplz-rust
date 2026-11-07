//! CLI argument definitions — one root command, mirroring upstream `dev`.
//!
//! Upstream `dev` (`cli/cmd/root.go:69-75`) has **no subcommands**: `rootCmd.Run
//! = runFunc` and `runFunc` picks the module(s) from the flags that were given
//! (`--brk` → brk, `-s` → syscall, `-w` → uprobe). The previous Rust CLI was
//! built on `origin/master`'s cobra tree (`stack` / `syscall` subcommands,
//! `--nr`, `--prepare`, `--no-tids`, `u64 -u/-p`), which is a different
//! interface entirely (report W2/W3/W11/W12).
//!
//! Cobra settings reproduced from `dev`:
//! - `cobra.EnablePrefixMatching = false` (`root.go:616`) → `infer_long_args(false)`
//! - `CompletionOptions.DisableDefaultCmd = true` → `disable_help_subcommand(true)`
//! - `SilenceUsage = true` → only the error is printed, never the usage block
//! - every flag is a **persistent/global** flag: `-u/-p/-t` are comma separated
//!   `string` lists (`root.go:621-623`), `--no-tid` is the blacklist name
//!   (`root.go:626`), `-w/--point` and `-c/--config` are `StringArray`s.
//!
//! Flags removed in this round (they had no consumer and no implementation to
//! hook them to — see DONE.md §W10):
//! `--prepare`, `--nr`, `--no-tids`, `--symbol`, `--offset`, `--library`,
//! `--maxop`, `--jstack`, `--mstack`, `--getoff`, `--dumpret`, `--rpc`,
//! `--rpc-path`, `--brk`, `--brk-pid`, `--brk-lib`, `--brk-len`, `--dump`,
//! `--parse`, `--showpc`, `--showtime`, `--showuid`, `--btf`.
//!
//! `--stack`, `--regs` and `--stack-size` were also removed (review F4): the
//! eBPF side never emits `UnwindBuf` stack data, so the native unwinder
//! (`event::parse_stack`) has no production caller. Accepting the flags made
//! them silently do nothing; they are rejected now instead.

use clap::Parser;

/// `stackplz` root command. Mirrors `rootCmd` in `cli/cmd/root.go`.
///
/// Short: "打印堆栈信息，目前仅支持5.10+内核，出现崩溃请升级系统版本"
#[derive(Debug, Parser)]
#[command(
    name = "stackplz",
    author,
    version,
    about = "基于eBPF的堆栈追踪工具，指定目标程序的uid、库文件路径和符号即可",
    long_about = None,
    // `cobra.EnablePrefixMatching = false` on dev (master sets it to true).
    infer_long_args(false),
    disable_help_subcommand(true),
)]
pub struct Cli {
    // ---- target / filter flags (root.go:618-631) --------------------------
    /// uid white list, comma separated (e.g. `-u 1000,1001`; `-u 0` traces root)
    #[arg(short = 'u', long, default_value = "")]
    pub uid: String,

    /// pid white list, comma separated
    #[arg(short = 'p', long, default_value = "")]
    pub pid: String,

    /// tid white list, comma separated
    #[arg(short = 't', long, default_value = "")]
    pub tid: String,

    /// must set uid or package name, comma separated; `root/system/shell/app/iso`
    /// are uid-group names
    #[arg(short = 'n', long, default_value = "")]
    pub name: String,

    /// uid black list, comma separated
    #[arg(long, default_value = "")]
    pub no_uid: String,

    /// pid black list, comma separated
    #[arg(long, default_value = "")]
    pub no_pid: String,

    /// tid black list, comma separated, max 1024
    #[arg(long, default_value = "")]
    pub no_tid: String,

    /// thread name white list, comma separated
    #[arg(long, default_value = "")]
    pub tname: String,

    /// thread name black list, comma separated
    #[arg(long, default_value = "")]
    pub no_tname: String,

    /// disable default thread name black list (18 entries)
    #[arg(long, default_value_t = false)]
    pub full_tname: bool,

    /// arg filter rule, e.g. `-f w:/data` (repeatable)
    #[arg(short = 'f', long = "filter", value_name = "RULE")]
    pub filter: Vec<String>,

    // ---- signal flags (root.go:633-635) ----------------------------------
    /// auto resume when use --kill SIGSTOP
    #[arg(long, default_value_t = false)]
    pub auto: bool,

    /// send signal when hit hook point, e.g. SIGSTOP/SIGABRT/SIGTRAP
    #[arg(long, default_value = "")]
    pub kill: String,

    /// send signal to thread when hit hook point
    #[arg(long, default_value = "")]
    pub tkill: String,

    // ---- syscall hook (root.go:674-676) ----------------------------------
    /// filter syscalls, comma separated: `all`, a name, a number, a `%group`
    /// (`%file`, `%net`, ...), or `name:f0.f2` with `-f` filter groups
    #[arg(short = 's', long, default_value = "")]
    pub syscall: String,

    /// syscall black list, max 20 (same syntax as -s)
    #[arg(long, default_value = "")]
    pub no_syscall: String,

    // ---- uprobe hook (root.go:662-671) -----------------------------------
    /// lib name or lib full path, default is libc.so
    #[arg(short = 'l', long = "lib", default_value = "libc.so")]
    pub library: String,

    /// lib dirs, library directory path or apk path (repeatable)
    #[arg(long = "libdirs", value_name = "DIR")]
    pub libdirs: Vec<String>,

    /// hook point config, e.g. `strstr+0x0[str,str]`, `write[int,buf:128,int]`
    #[arg(short = 'w', long = "point", value_name = "POINT")]
    pub point: Vec<String>,

    /// get the offset of reg
    #[arg(long, default_value = "")]
    pub reg: String,

    /// hook config file (repeatable; syscall or uprobe JSON)
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Vec<String>,

    // ---- stack output flags (root.go:646-652) ----------------------------
    // `--stack`, `--regs` and `--stack-size` are not accepted: the unwinder has
    // no production caller (review F4, see the module doc above).
    /// dump buffer as hex
    #[arg(long, default_value_t = false)]
    pub dumphex: bool,

    // ---- logging (root.go:653-658) --------------------------------------
    /// enable debug logging
    #[arg(short = 'd', long, default_value_t = false)]
    pub debug: bool,

    /// wont logging to terminal when used
    #[arg(short = 'q', long, default_value_t = false)]
    pub quiet: bool,

    /// enable color for log file
    #[arg(long, default_value_t = false)]
    pub color: bool,

    /// log event as json format
    #[arg(short = 'j', long, default_value_t = false)]
    pub json: bool,

    /// save the log to file
    #[arg(short = 'o', long, default_value = "")]
    pub out: String,

    // ---- runtime flags (root.go:618, 672-673) ---------------------------
    /// android os sdk int, optional (default: `getprop ro.build.version.sdk`)
    #[arg(long = "sdk-int", default_value_t = 0)]
    pub sdk_int: u32,

    /// disable check for bpf kernel config
    #[arg(long, default_value_t = false)]
    pub nocheck: bool,

    /// perf cache buffer size, default 8M
    #[arg(short = 'b', long, default_value_t = 8)]
    pub buffer: u32,
}

impl Cli {
    /// True when any hook source was given. Used by the "hook nothing" check to
    /// report the same fatal message as upstream dev.
    pub fn has_hook_source(&self) -> bool {
        !self.point.is_empty() || !self.syscall.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv).expect("argv should parse")
    }

    /// dev has no subcommands: a bare invocation parses (and then runs).
    #[test]
    fn bare_invocation_parses_without_a_subcommand() {
        let cli = parse(&["stackplz"]);
        assert!(cli.uid.is_empty());
        assert_eq!(cli.library, "libc.so");
        assert_eq!(cli.buffer, 8);
        assert_eq!(cli.sdk_int, 0);
    }

    /// `-u/-p/-t` are strings on dev, so lists and `0` are expressible.
    #[test]
    fn uid_pid_tid_are_string_lists() {
        let cli = parse(&["stackplz", "-u", "1000,1001", "-p", "0", "-t", "11,22"]);
        assert_eq!(cli.uid, "1000,1001");
        assert_eq!(cli.pid, "0");
        assert_eq!(cli.tid, "11,22");

        // The old (master-shaped) CLI could not accept either of these.
        assert!(!cli.uid.is_empty());
        assert_eq!(cli.pid, "0");
    }

    /// `--no-tid` is the dev flag name (`--no-tids` was master's).
    #[test]
    fn no_tid_is_the_blacklist_flag() {
        let cli = parse(&["stackplz", "--no-tid", "100,200"]);
        assert_eq!(cli.no_tid, "100,200");
        assert!(
            Cli::try_parse_from(["stackplz", "--no-tids", "1"]).is_err(),
            "--no-tids is a master-only spelling"
        );
    }

    /// `cobra.EnablePrefixMatching = false`: `--sy` is not `--syscall`.
    #[test]
    fn long_flag_prefix_matching_is_disabled() {
        assert!(
            Cli::try_parse_from(["stackplz", "--s", "openat"]).is_err(),
            "dev disables prefix matching, so ambiguous prefixes must fail"
        );
        // Exact names still work.
        let cli = parse(&["stackplz", "--syscall", "openat"]);
        assert_eq!(cli.syscall, "openat");
    }

    /// `-s` accepts the dev spec syntax verbatim; parsing happens later (the
    /// point table is needed), so the CLI keeps the raw string.
    #[test]
    fn syscall_spec_keeps_names_groups_and_filter_groups() {
        let cli = parse(&["stackplz", "-s", "%file,openat:f0.f2,readlinkat:|f1"]);
        assert_eq!(cli.syscall, "%file,openat:f0.f2,readlinkat:|f1");
    }

    /// `-f`, `-w` and `-c` are repeatable arrays, like cobra's `StringArrayVarP`.
    #[test]
    fn repeated_array_flags_accumulate() {
        let cli = parse(&[
            "stackplz",
            "-f",
            "w:/data",
            "-f",
            "eq:1",
            "-w",
            "write[int,buf:128,int]",
            "-w",
            "read[str]",
            "-c",
            "a.json",
            "-c",
            "b.json",
        ]);
        assert_eq!(cli.filter, vec!["w:/data", "eq:1"]);
        assert_eq!(cli.point.len(), 2);
        assert_eq!(cli.point[0], "write[int,buf:128,int]");
        assert_eq!(cli.config, vec!["a.json", "b.json"]);
    }

    /// Flags that were dead in this crate are gone rather than silently accepted.
    #[test]
    fn removed_dead_flags_are_rejected() {
        for flag in [
            "--prepare",
            "--nr",
            "--maxop",
            "--jstack",
            "--mstack",
            "--getoff",
            "--dumpret",
            "--rpc",
            "--brk",
            "--dump",
            "--parse",
            "--btf",
            "--showpc",
            "--showtime",
            "--showuid",
        ] {
            assert!(
                Cli::try_parse_from(["stackplz", flag, "x"]).is_err()
                    || Cli::try_parse_from(["stackplz", flag]).is_err(),
                "{flag} should have been removed"
            );
        }
    }

    /// There is no `stack`/`syscall` subcommand any more; a positional argument
    /// is rejected because the root command takes none.
    #[test]
    fn subcommands_are_gone() {
        assert!(Cli::try_parse_from(["stackplz", "syscall"]).is_err());
        assert!(Cli::try_parse_from(["stackplz", "stack", "--symbol", "open"]).is_err());
    }

    #[test]
    fn has_hook_source_detects_point_and_syscall() {
        assert!(!parse(&["stackplz"]).has_hook_source());
        assert!(parse(&["stackplz", "-w", "write[int]"]).has_hook_source());
        assert!(parse(&["stackplz", "-s", "all"]).has_hook_source());
    }
}
