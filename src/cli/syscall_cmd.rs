//! `syscall` subcommand handler. Mirrors `syscallCommandFunc`
//! (`cli/cmd/syscall.go:40-136`).

use super::args::SyscallArgs;
use crate::config::{GlobalConfig, SyscallConfig, TargetConfig};
use crate::module::{SyscallTracepointModule, MODULE_NAME_SYSCALL};
use anyhow::Result;
use std::sync::Arc;

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
