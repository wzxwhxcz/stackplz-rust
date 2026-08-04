//! Global CLI options. Mirrors `GlobalConfig` in `user/config/config_global.go`
//! and the bindings set up in `cli/cmd/root.go:220-229`.

use crate::cli::args::GlobalArgs;

/// Mirrors Go `config.GlobalConfig`.
#[derive(Debug, Clone, Default)]
pub struct GlobalConfig {
    pub quiet: bool,
    pub prepare: bool,
    pub name: String,
    pub debug: bool,
    pub uid: u64,
    pub pid: u64,
    pub tid: String,
    pub tids_blacklist: String,
    pub tname: String,
    pub no_tname: String,
    pub full_tname: bool,
    pub logger_file: String,
    /// Directory of the running executable; populated by `persistent_pre_run`.
    pub exec_path: String,
    // Output format flags.
    pub color: bool,
    pub json: bool,
    pub dumphex: bool,
    pub showpc: bool,
    pub showtime: bool,
    pub showuid: bool,
    pub getoff: bool,
    pub jstack: bool,
    pub mstack: bool,
    // Stack/regs flags (global-level, inherited by subcommands).
    pub stack: bool,
    pub regs: bool,
    // BPF flags.
    pub nocheck: bool,
    pub btf: bool,
    // Library.
    pub library: String,
    // Perf buffer size in MB.
    pub buffer: u32,
    // Signal flags.
    pub kill_signal: String,
    pub tkill_signal: String,
    pub auto_resume: bool,
    // Dump/Parse flags.
    pub dump_file: String,
    pub parse_file: String,
    // Advanced filter flags.
    pub no_uid: String,
    pub no_pid: String,
    pub sdk_int: u32,
    // Misc flags.
    pub dumpret: bool,
    // P0 missing parameters (root.go:631-676).
    pub filter: Vec<String>,
    pub syscall: String,
    pub no_syscall: String,
    pub maxop: u32,
    pub stack_size: u32,
    pub libdirs: Vec<String>,
}

impl GlobalConfig {
    pub fn from(args: &GlobalArgs) -> Self {
        Self {
            quiet: args.quiet,
            prepare: args.prepare,
            name: args.name.clone(),
            debug: args.debug,
            uid: args.uid,
            pid: args.pid,
            tid: args.tid.clone(),
            tids_blacklist: args.no_tids.clone(),
            tname: args.tname.clone(),
            no_tname: args.no_tname.clone(),
            full_tname: args.full_tname,
            logger_file: args.out.clone(),
            exec_path: String::new(),
            color: args.color,
            json: args.json,
            dumphex: args.dumphex,
            showpc: args.showpc,
            showtime: args.showtime,
            showuid: args.showuid,
            getoff: args.getoff,
            jstack: args.jstack,
            mstack: args.mstack,
            stack: args.stack,
            regs: args.regs,
            nocheck: args.nocheck,
            btf: args.btf,
            library: args.library.clone(),
            buffer: args.buffer,
            kill_signal: args.kill.clone(),
            tkill_signal: args.tkill.clone(),
            auto_resume: args.auto,
            dump_file: args.dump.clone(),
            parse_file: args.parse.clone(),
            no_uid: args.no_uid.clone(),
            no_pid: args.no_pid.clone(),
            sdk_int: args.sdk_int,
            dumpret: args.dumpret,
            filter: args.filter.clone(),
            syscall: args.syscall.clone(),
            no_syscall: args.no_syscall.clone(),
            maxop: args.maxop,
            stack_size: args.stack_size,
            libdirs: args.libdirs.clone(),
        }
    }
}
