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
    pub tids_blacklist: String,
    pub logger_file: String,
    /// Directory of the running executable; populated by `persistent_pre_run`.
    /// Mirrors `global_config.ExecPath`.
    pub exec_path: String,
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
            tids_blacklist: args.no_tids.clone(),
            logger_file: args.out.clone(),
            exec_path: String::new(),
        }
    }
}
