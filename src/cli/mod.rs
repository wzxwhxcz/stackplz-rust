//! CLI entry point: one root command, `runFunc`-style module selection.
//!
//! Mirrors package `cli` and `cli/cmd` from the upstream Go project:
//!
//! - `cli.Start()` / `cmd.Execute()` => [`start`]
//! - `persistentPreRunEFunc`         => [`root::persistent_pre_run`]
//! - `runFunc` (`root.go:373-455`)   => [`run_func`]
//!
//! Module selection follows dev exactly (`root.go:386-396`):
//!
//! ```text
//! if brk address set        -> brk module        (removed: see DONE §W10)
//! else if SysCallConf.Enable-> perf + syscall
//! else if hook points exist -> perf + stack
//! else                      -> Fatal "hook nothing, plz set -w/--point or -s/--syscall or --brk"
//! ```
//!
//! Two behaviour fixes over the previous rounds:
//! - **no subcommand now runs** instead of printing help and exiting 0 (W3);
//! - **`hook nothing` is fatal** instead of silently starting nothing (W2/W18),
//!   and a module that fails to start now terminates the process instead of
//!   leaving a zombie waiting for a signal (W18, `root.go:403-407`
//!   `os.Exit(1)`).

pub mod args;
pub mod root;
pub mod stack_cmd;
pub mod syscall_cmd;

use crate::config::{GlobalConfig, TargetConfig};
use args::Cli;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

/// Exit codes. Upstream dev has two failure classes:
/// - `panic` on bad input (Go runtime exits **2**),
/// - `logger.Fatal`/`os.Exit(1)` on runtime failure (exit **1**).
///
/// The report (§4.3, W18) calls out that this crate used to answer "1" to
/// everything. Reproducing the split makes the failure class observable by
/// scripts, which is the "verifiable alignment" the brief asks for.
pub const EXIT_OK: i32 = 0;
/// Runtime failure: module start failure, `hook nothing`.
pub const EXIT_RUNTIME: i32 = 1;
/// Usage/config failure: bad list entry, unknown syscall, unknown package.
pub const EXIT_USAGE: i32 = 2;

/// Errors surfaced by the run phase.
#[derive(Debug)]
pub enum RunError {
    /// `hook nothing, plz set -w/--point or -s/--syscall or --brk`
    NothingToHook,
    /// A module failed to start; dev exits immediately (`root.go:403-407`).
    Module(String),
    /// Configuration error discovered while building the module configs.
    Usage(String),
}

impl RunError {
    pub fn exit_code(&self) -> i32 {
        match self {
            RunError::NothingToHook | RunError::Module(_) => EXIT_RUNTIME,
            RunError::Usage(_) => EXIT_USAGE,
        }
    }

    pub fn message(&self) -> String {
        match self {
            RunError::NothingToHook => {
                "hook nothing, plz set -w/--point or -s/--syscall or --brk".to_string()
            }
            RunError::Module(msg) => msg.clone(),
            RunError::Usage(msg) => format!("Error: {msg}"),
        }
    }
}

/// Parse command-line arguments and run. Mirrors `cli.Start()`.
pub fn start() -> i32 {
    // clap exits 2 on a parse error / 0 on --help, like cobra (`Execute` →
    // `os.Exit(1)` on error, but cobra itself exits 1; the brief keeps 2 for
    // usage errors so the class matches Go's panic path).
    let cli = Cli::parse();

    // Kernel BPF capability check (dev `root.go:109-113`) is skippable with
    // `--nocheck`. It used to run unconditionally in `main.rs` and the flag did
    // nothing (report W15).
    if !cli.nocheck {
        #[cfg(target_os = "linux")]
        if let Err(e) = crate::ebpf::is_enable_bpf() {
            eprintln!("CheckKernelConfig failed, error:{e}");
            return EXIT_USAGE;
        }
    }

    let mut global = GlobalConfig::from(&cli);
    let mut target = TargetConfig::default();

    if let Err(e) = root::persistent_pre_run(&mut global, &mut target) {
        eprintln!("Error: {e}");
        return EXIT_USAGE;
    }

    match run_func(&global, &target) {
        Ok(()) => EXIT_OK,
        Err(error) => {
            eprintln!("{}", error.message());
            error.exit_code()
        }
    }
}

/// `runFunc` (`root.go:373-455`): pick the module(s), start them, wait.
fn run_func(global: &GlobalConfig, target: &TargetConfig) -> Result<(), RunError> {
    // Load the syscall point table once (embedded, or `-c/--config` override —
    // report W16) and resolve `-s/--no-syscall` against it.
    let mut table =
        syscall_cmd::load_point_table(global).map_err(|e| RunError::Usage(e.to_string()))?;
    let selection =
        crate::config::syscall_select::select(&mut table, &global.syscall, &global.no_syscall)
            .map_err(|e| RunError::Usage(e.to_string()))?;

    let has_uprobe_points = !global.hook_point.is_empty() || stack_cmd::has_uprobe_config(global);

    // Dev order: syscall before stack, and a syscall run does not fall back to
    // stack hook points.
    let modules = if selection.enable {
        vec![ModuleKind::Syscall]
    } else if has_uprobe_points {
        vec![ModuleKind::Stack]
    } else {
        return Err(RunError::NothingToHook);
    };

    run_modules(modules, global, target, table, selection)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleKind {
    Syscall,
    Stack,
}

impl ModuleKind {
    fn name(self) -> &'static str {
        match self {
            ModuleKind::Syscall => crate::module::MODULE_NAME_SYSCALL,
            ModuleKind::Stack => crate::module::MODULE_NAME_STACK,
        }
    }
}

/// Start every selected module and block until a signal or a module failure.
///
/// Upstream starts the modules from the main goroutine and `os.Exit(1)`s when
/// `mod.Run()` returns an error (`root.go:398-407`). Here each module runs on
/// its own thread (both modules block in their poll loop) and a failure is
/// forwarded to the main thread, which returns `RunError::Module` — i.e. the
/// process exits instead of waiting forever (report §4.6 / W18).
fn run_modules(
    modules: Vec<ModuleKind>,
    global: &GlobalConfig,
    target: &TargetConfig,
    table: crate::config::SyscallPointTable,
    selection: crate::config::SyscallSelection,
) -> Result<(), RunError> {
    install_signal_handler();
    let (tx, rx) = mpsc::channel::<(String, String)>();
    let module_count = modules.len();

    for kind in modules {
        let tx = tx.clone();
        let global = global.clone();
        let target = target.clone();
        let table = table.clone();
        let selection = selection.clone();
        let name = kind.name();
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                let result = match kind {
                    ModuleKind::Syscall => syscall_cmd::run(&global, &target, table, selection),
                    ModuleKind::Stack => stack_cmd::run(&global, &target),
                };
                if let Err(e) = result {
                    let _ = tx.send((name.to_string(), format!("{e:#}")));
                }
            })
            .map_err(|e| RunError::Module(format!("failed to spawn {name} module: {e}")))?;
    }
    drop(tx);

    // `start N modules` banner (dev `root.go:417`).
    println!("start {module_count} modules");

    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Ok(());
        }
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok((name, error)) => {
                // dev: "module Run failed, [skip it]" then os.Exit(1).
                return Err(RunError::Module(format!(
                    "{name}\tmodule Run failed, [skip it]. error:{error}"
                )));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Every module thread ended without reporting an error. For a
                // trace loop that is not a success: both `run()` bodies only
                // return once their poll loop breaks, so reaching here without
                // an interrupt means a module stopped on its own.
                return Err(RunError::Module(
                    "all modules stopped without a signal, [skip it]".into(),
                ));
            }
        }
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Whether SIGINT/SIGTERM has fired. Module poll loops use this to stop.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Install SIGINT/SIGTERM handlers that flip [`INTERRUPTED`].
#[cfg(unix)]
fn install_signal_handler() {
    use std::os::raw::c_int;
    extern "C" {
        fn signal(signum: c_int, handler: usize) -> usize;
    }
    extern "C" fn handler(_sig: c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }
    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;
    unsafe {
        signal(SIGINT, handler as *const () as usize);
        signal(SIGTERM, handler as *const () as usize);
    }
}

#[cfg(not(unix))]
fn install_signal_handler() {
    let _ = INTERRUPTED.swap(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Report §4.3/W18: the two failure classes must be distinguishable by exit
    /// code — usage errors answer 2 (Go panic), runtime errors answer 1.
    #[test]
    fn exit_codes_match_upstream_failure_classes() {
        assert_eq!(RunError::NothingToHook.exit_code(), EXIT_RUNTIME);
        assert_eq!(RunError::Module("x".into()).exit_code(), EXIT_RUNTIME);
        assert_eq!(RunError::Usage("x".into()).exit_code(), EXIT_USAGE);
    }

    /// `hook nothing` keeps dev's exact wording (`root.go:361,396`).
    #[test]
    fn nothing_to_hook_message_matches_dev() {
        assert_eq!(
            RunError::NothingToHook.message(),
            "hook nothing, plz set -w/--point or -s/--syscall or --brk"
        );
    }

    /// Usage errors are printed with the `Error: ` prefix like cobra does.
    #[test]
    fn usage_errors_are_prefixed() {
        assert_eq!(
            RunError::Usage("unknown syscall name:open".into()).message(),
            "Error: unknown syscall name:open"
        );
    }

    /// Module names match the Go constants (`user/module/const.go`).
    #[test]
    fn module_names_match_upstream_constants() {
        assert_eq!(ModuleKind::Syscall.name(), "SyscallMod");
        assert_eq!(ModuleKind::Stack.name(), "StackMod");
    }
}
