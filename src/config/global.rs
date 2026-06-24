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
        }
    }
}
