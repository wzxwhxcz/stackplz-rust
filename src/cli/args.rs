//! CLI argument definitions, mirroring the Go cobra command tree.
//!
//! Replicates:
//! - Root command `stackplz` with global persistent flags (`cli/cmd/root.go`)
//! - Subcommand `stack` (`cli/cmd/stack.go`)
//! - Subcommand `syscall` (`cli/cmd/syscall.go`)
//!
//! Cobra quirks intentionally reproduced:
//! - `cobra.EnablePrefixMatching = true`  => `infer_long_args(true)`
//! - `rootCmd.SilenceUsage = true`         => we handle usage suppression in main
//! - `CompletionOptions.DisableDefaultCmd` => no auto `completion` subcommand
//! - All numeric flags unsigned except `--nr` (signed i64, default -1)
//! - `--offset` parsed as u64 from CLI, but hex-string in JSON config

use clap::{Args, Parser, Subcommand};

/// `stackplz` root command. Mirrors `rootCmd` in `cli/cmd/root.go`.
///
/// Short: "打印堆栈信息，目前仅支持4.14内核，出现崩溃请升级系统版本"
/// Long:  "基于eBPF的堆栈追踪工具，指定目标程序的uid、库文件路径和符号即可\n
///         \t./stackplz stack --uid 10235 --stack --symbol open"
#[derive(Debug, Parser)]
#[command(
    name = "stackplz",
    author,
    version,
    about = "基于eBPF的堆栈追踪工具，指定目标程序的uid、库文件路径和符号即可",
    long_about = None,
    // Reproduce cobra.EnablePrefixMatching = true (long-flag prefix inference).
    infer_long_args(true),
    // Reproduce DisableDefaultCmd (no auto `completion` subcommand).
    disable_help_subcommand(true),
)]
pub struct Cli {
    /// Global persistent flags, inherited by all subcommands.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The tracing subcommand.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Global persistent flags. Mirrors `global_config` bindings in `root.go:220-229`.
#[derive(Debug, Clone, Args)]
pub struct GlobalArgs {
    /// prepare libs
    #[arg(long, default_value_t = false)]
    pub prepare: bool,

    /// must set uid or package name
    #[arg(short = 'n', long, default_value = "")]
    pub name: String,

    /// must set uid or package name
    #[arg(short = 'u', long, default_value_t = 0)]
    pub uid: u64,

    /// add pid to filter
    #[arg(short = 'p', long, default_value_t = 0)]
    pub pid: u64,

    /// tid white list
    #[arg(short = 't', long, default_value = "")]
    pub tid: String,

    /// tid black list, max 5
    #[arg(long, default_value = "")]
    pub no_tids: String,

    /// thread name white list
    #[arg(long, default_value = "")]
    pub tname: String,

    /// thread name black list
    #[arg(long, default_value = "")]
    pub no_tname: String,

    /// disable default thread name black list
    #[arg(long, default_value_t = false)]
    pub full_tname: bool,

    /// enable debug logging
    #[arg(short = 'd', long, default_value_t = false)]
    pub debug: bool,

    /// -o save the packets to file
    #[arg(short = 'o', long, default_value = "")]
    pub out: String,

    /// use with --out, wont logging to terminal when used
    #[arg(short = 'q', long, default_value_t = false)]
    pub quiet: bool,

    /// enable color for log file
    #[arg(long, default_value_t = false)]
    pub color: bool,

    /// log event as json format
    #[arg(short = 'j', long, default_value_t = false)]
    pub json: bool,

    /// dump buffer as hex
    #[arg(long, default_value_t = false)]
    pub dumphex: bool,

    /// show origin pc register value
    #[arg(long, default_value_t = false)]
    pub showpc: bool,

    /// show event boot time info
    #[arg(long, default_value_t = false)]
    pub showtime: bool,

    /// show process uid info
    #[arg(long, default_value_t = false)]
    pub showuid: bool,

    /// enable unwindstack
    #[arg(long, default_value_t = false)]
    pub stack: bool,

    /// show regs
    #[arg(long, default_value_t = false)]
    pub regs: bool,

    /// try get pc and lr offset
    #[arg(long, default_value_t = false)]
    pub getoff: bool,

    /// try parse java stack
    #[arg(long, default_value_t = false)]
    pub jstack: bool,

    /// manual parse stack
    #[arg(long, default_value_t = false)]
    pub mstack: bool,

    /// disable check for bpf
    #[arg(long, default_value_t = false)]
    pub nocheck: bool,

    /// declare BTF enabled
    #[arg(long, default_value_t = false)]
    pub btf: bool,

    /// lib name or lib full path, default is libc.so
    #[arg(short = 'l', long, default_value = "libc.so")]
    pub library: String,

    /// perf cache buffer size, default 8M
    #[arg(short = 'b', long, default_value_t = 8)]
    pub buffer: u32,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// show stack plz
    #[command(
        name = "stack",
        about = "show stack plz",
        long_about = "show stack which based unwindstack"
    )]
    Stack(StackArgs),

    /// filter and show syscall stack plz
    #[command(
        name = "syscall",
        about = "filter and show syscall stack plz",
        long_about = "filter and show syscall stack which based unwindstack"
    )]
    Syscall(SyscallArgs),
}

/// `stack` subcommand flags. Mirrors `stack_config` in `stack.go:61-71`.
#[derive(Debug, Clone, Args)]
pub struct StackArgs {
    /// enable unwindstack
    #[arg(long, default_value_t = false)]
    pub stack: bool,

    /// show regs
    #[arg(long, default_value_t = false)]
    pub regs: bool,

    /// full lib path
    #[arg(long, default_value = "/apex/com.android.runtime/lib64/bionic/libc.so")]
    pub library: String,

    /// lib symbol
    #[arg(long, default_value = "")]
    pub symbol: String,

    /// lib hook offset
    #[arg(long, default_value_t = 0)]
    pub offset: u64,

    /// get the offset of reg
    #[arg(long, default_value = "")]
    pub reg: String,

    /// hook config file
    #[arg(long, default_value = "")]
    pub config: String,

    /// hook point config, e.g. strstr+0x0[str,str] write[int,buf:128,int]
    #[arg(short = 'w', long = "point")]
    pub point: Vec<String>,
}

/// `syscall` subcommand flags. Mirrors `syscall_config` in `syscall.go:33-36`.
#[derive(Debug, Clone, Args)]
pub struct SyscallArgs {
    /// enable unwindstack
    #[arg(long, default_value_t = false)]
    pub stack: bool,

    /// show regs
    #[arg(long, default_value_t = false)]
    pub regs: bool,

    /// syscall hook config file
    #[arg(long, default_value = "")]
    pub config: String,

    /// filter syscall number
    #[arg(long, default_value_t = -1)]
    pub nr: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stack_subcommand_defaults() {
        let cli = Cli::try_parse_from(["stackplz", "--uid", "10245", "stack", "--symbol", "open"])
            .unwrap();
        assert_eq!(cli.global.uid, 10245);
        match cli.command {
            Some(Command::Stack(s)) => {
                assert_eq!(s.symbol, "open");
                assert_eq!(s.library, "/apex/com.android.runtime/lib64/bionic/libc.so");
                assert_eq!(s.offset, 0);
                assert!(!s.stack);
                assert!(!s.regs);
            }
            _ => panic!("expected stack subcommand"),
        }
    }

    #[test]
    fn parse_syscall_nr_default() {
        let cli = Cli::try_parse_from(["stackplz", "--uid", "1", "syscall"]).unwrap();
        match cli.command {
            Some(Command::Syscall(s)) => assert_eq!(s.nr, -1),
            _ => panic!("expected syscall subcommand"),
        }
    }

    #[test]
    fn parse_syscall_nr_value() {
        let cli =
            Cli::try_parse_from(["stackplz", "--name", "com.x", "syscall", "--nr", "63"]).unwrap();
        match cli.command {
            Some(Command::Syscall(s)) => assert_eq!(s.nr, 63),
            _ => panic!("expected syscall subcommand"),
        }
    }

    #[test]
    fn infer_long_args_prefix_matching() {
        // cobra.EnablePrefixMatching=true allows `--sy` for `--symbol`.
        let cli = Cli::try_parse_from(["stackplz", "--uid", "1", "stack", "--sy", "open"]).unwrap();
        match cli.command {
            Some(Command::Stack(s)) => assert_eq!(s.symbol, "open"),
            _ => panic!("expected stack subcommand"),
        }
    }

    #[test]
    fn no_tids_flag() {
        let cli = Cli::try_parse_from(["stackplz", "--uid", "1", "--no-tids", "100,200", "stack"])
            .unwrap();
        assert_eq!(cli.global.no_tids, "100,200");
    }

    #[test]
    fn parse_point_flag() {
        let cli = Cli::try_parse_from([
            "stackplz",
            "--uid",
            "1",
            "stack",
            "-w",
            "write[int,buf:128,int]",
            "-w",
            "read[str]",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Stack(s)) => {
                assert_eq!(s.point.len(), 2);
                assert_eq!(s.point[0], "write[int,buf:128,int]");
                assert_eq!(s.point[1], "read[str]");
            }
            _ => panic!("expected stack subcommand"),
        }
    }

    #[test]
    fn parse_global_flags() {
        let cli = Cli::try_parse_from([
            "stackplz",
            "--uid",
            "1",
            "--json",
            "--dumphex",
            "--showpc",
            "--showtime",
            "--showuid",
            "--color",
            "--debug",
            "stack",
        ])
        .unwrap();
        assert!(cli.global.json);
        assert!(cli.global.dumphex);
        assert!(cli.global.showpc);
        assert!(cli.global.showtime);
        assert!(cli.global.showuid);
        assert!(cli.global.color);
        assert!(cli.global.debug);
    }

    #[test]
    fn parse_library_flag() {
        let cli = Cli::try_parse_from([
            "stackplz",
            "--uid",
            "1",
            "--library",
            "libnative-lib.so",
            "stack",
        ])
        .unwrap();
        assert_eq!(cli.global.library, "libnative-lib.so");
    }
}
