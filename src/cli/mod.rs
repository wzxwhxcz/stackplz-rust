//! CLI entry point. Mirrors package `cli` and `cli/cmd` from the Go project.
//!
//! - `cli.Start()`   => [`start`]
//! - `cmd.Execute()` => clap parse + dispatch in [`start`]
//! - `persistentPreRunEFunc` => [`root::persistent_pre_run`]

pub mod args;
pub mod root;
pub mod stack_cmd;
pub mod syscall_cmd;

use crate::config::{GlobalConfig, TargetConfig};
use anyhow::Result;
use args::{Cli, Command};
use clap::{CommandFactory, Parser};

/// Parse command-line arguments and dispatch to the appropriate subcommand.
///
/// Mirrors `cli.Start()` -> `cmd.Execute()`. Returns the process exit code so
/// the caller (`main`) can `std::process::exit` after running any destructors.
pub fn start() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap exits with code 2 on parse errors and 0 on --help by default;
            // propagate its chosen exit code.
            e.exit();
        }
    };

    // No subcommand: cobra prints help and returns nil. We mirror that.
    let command = match cli.command {
        Some(c) => c,
        None => {
            Cli::command().print_help().ok();
            println!();
            return 0;
        }
    };

    // Global mutable state shared between pre-run and subcommand handlers,
    // equivalent to the package-level `global_config` / `target_config` in Go.
    let mut global_config = GlobalConfig::from(&cli.global);
    let mut target_config = TargetConfig::default();

    // PersistentPreRun runs before the subcommand Run in cobra. It must execute
    // here too (lib extraction, tid-blacklist parsing, uid/library resolution).
    if let Err(e) = root::persistent_pre_run(&mut global_config, &mut target_config) {
        // SilenceUsage=true in Go; we just print the error and exit 1.
        eprintln!("Error: {e}");
        return 1;
    }

    let result: Result<()> = match command {
        Command::Stack(args) => stack_cmd::run(&mut global_config, &mut target_config, args),
        Command::Syscall(args) => syscall_cmd::run(&mut global_config, &mut target_config, args),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        return 1;
    }
    0
}
