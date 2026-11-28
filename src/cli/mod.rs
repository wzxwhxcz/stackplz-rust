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
use std::sync::{mpsc, Arc};

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
    // The `-w` parse resolves argument types, so the registry must be up
    // before anything parses points (`stack_cmd::run` repeats the call; the
    // OnceLock makes the second one a no-op).
    crate::argtype::init_argtypes();

    // Load the syscall point table once (embedded, or `-c/--config` override —
    // report W16) and resolve `-s/--no-syscall` against it.
    let mut table =
        syscall_cmd::load_point_table(global).map_err(|e| RunError::Usage(e.to_string()))?;

    // Round 11 / P1: parse `-w` points and dispatch `]s`/`]ss` bindings into
    // the syscall table *before* selection — Go's order is `LoadConfig`,
    // then `Parse_HookPoint` + `GetSyscall` (which appends the bound names
    // to the syscall spec), then `Parse_Syscall` (`root.go:259-290`,
    // `config_module.go:272-283`).
    let dispatch = dispatch_w_points(global, target, &mut table)
        .map_err(|e| RunError::Usage(e.to_string()))?;
    let syscall_spec = merge_syscall_spec(&global.syscall, &dispatch.bound_names);
    let selection =
        crate::config::syscall_select::select(&mut table, &syscall_spec, &global.no_syscall)
            .map_err(|e| RunError::Usage(e.to_string()))?;

    let has_uprobe_points = dispatch
        .w_points
        .as_ref()
        .is_some_and(|(_, points)| !points.is_empty())
        || stack_cmd::has_uprobe_config(global).map_err(|e| RunError::Usage(e.to_string()))?;

    // Dev order: syscall before stack. Without a binding the old either-or
    // rule stands (a `-s` run does not fall back to stack hook points); when
    // a `]s` binding exists the syscall module is enabled *in addition* to
    // the stack module, because one run now genuinely needs both.
    let mut modules = Vec::new();
    if selection.enable {
        modules.push(ModuleKind::Syscall);
    }
    if has_uprobe_points && (!selection.enable || !dispatch.bound_names.is_empty()) {
        modules.push(ModuleKind::Stack);
    }
    if modules.is_empty() {
        return Err(RunError::NothingToHook);
    }

    run_modules(modules, global, target, table, selection, dispatch.w_points)
}

/// Outcome of `dispatch_w_points` (round 11 / P1): the `-w` points that
/// remain for the stack module, and the syscall names bound into the table.
/// A named struct (rather than a nested tuple) keeps the dispatch signature
/// under clippy's `type_complexity` limit.
#[derive(Debug)]
struct WDispatch {
    /// Remaining `-w` points for the stack module (`None` when there is no
    /// `-w` input or nothing remains).
    w_points: Option<(String, Vec<crate::config::UprobeArgs>)>,
    /// Syscall names bound into the table, for the `-s` spec merge.
    bound_names: Vec<String>,
}

/// Parse `-w/--point` and dispatch `]s`/`]ss` bindings into the syscall
/// table (round 11 / P1, Go `GetSyscall`, `config_module.go:272-283`).
///
/// A bound point is removed from the uprobe list and its name is returned so
/// the caller can merge it into the syscall spec before selection; an
/// unknown bound name is an error (see `update_syscall_point`).
///
/// An exit companion (`get_exit_point`) carries `bind_syscall == false`, so
/// it always stays in the uprobe list — Go's `GetExitPoint` does not copy
/// `BindSyscall` either (`config_uprobe.go:26-43`).
///
/// Round 14 / R13-3: a bound main with an exit offset is contradictory
/// input and bails in `update_syscall_point`. The main is traced by the
/// syscall module, but its exit companion would be orphaned in the uprobe
/// list, and no module can supply the entry registers the companion's SAVE
/// branch needs — it would report exit-time registers as if they were
/// entry-time ones. (No CLI input currently produces that combination — the
/// `]s` suffix strip leaves the string ending in `]`, so the exit-offset
/// parse sees trailing garbage like `0x40]` and fails, leaving the offset
/// at 0 — but the check guards the invariant if the parser ever changes.)
fn dispatch_w_points(
    global: &GlobalConfig,
    target: &TargetConfig,
    table: &mut crate::config::SyscallPointTable,
) -> anyhow::Result<WDispatch> {
    if global.hook_point.is_empty() {
        return Ok(WDispatch {
            w_points: None,
            bound_names: Vec::new(),
        });
    }
    let library = crate::util::find_lib(&global.library, &target.library_dirs)?;
    let points = crate::config::point_parser::parse_hook_point(
        &global.hook_point,
        &library,
        global.dump_hex,
    )?;
    let mut bound_names = Vec::new();
    let mut remaining = Vec::new();
    for point in points {
        if table.update_syscall_point(&point)? {
            bound_names.push(point.name.clone());
        } else {
            remaining.push(point);
        }
    }
    let w_points = if remaining.is_empty() {
        None
    } else {
        Some((library, remaining))
    };
    Ok(WDispatch {
        w_points,
        bound_names,
    })
}

/// Merge bound `-w ...]s` names into the `-s/--syscall` spec (round 11 / P1):
/// Go appends `GetSyscall`'s return to `gconfig.SysCall` before
/// `Parse_Syscall` (`root.go:281-284`), so a bare `-w 'write[...]s'` enables
/// the syscall module with no `-s` at all. Empty parts are skipped so the
/// merged spec never starts with a stray comma.
fn merge_syscall_spec(base: &str, bound_names: &[String]) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !base.is_empty() {
        parts.push(base);
    }
    parts.extend(bound_names.iter().map(String::as_str));
    parts.join(",")
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

/// Decide what one module-completion message means (round 12 / R11-4): a
/// trace module never legitimately ends on its own, so an Ok completion is a
/// failure too — unless we were interrupted (Ctrl-C), the only clean stop.
/// Pure, so the run_modules wait loop is testable without threads or channels.
/// Returns `None` when the run should end cleanly, else the error to surface.
fn handle_module_completion(
    name: &str,
    error: Option<String>,
    interrupt: bool,
) -> Option<RunError> {
    if interrupt {
        return None;
    }
    match error {
        Some(e) => Some(RunError::Module(format!(
            "{name}\tmodule Run failed, [skip it]. error:{e}"
        ))),
        None => Some(RunError::Module(format!(
            "{name}\tmodule stopped without a signal, [skip it]"
        ))),
    }
}

/// Extract a panic payload's message text for diagnostics. Joining a module
/// thread returns `Err(payload)` when it panicked; the default hook already
/// printed it to stderr, so the join loop only labels it with the module
/// name. `downcast_ref` must try both common shapes (`&str`, `String`).
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Join module handles and collect `(name, msg)` for every panic, in join
/// order. Panics still go to stderr for live runs; the returned list is what
/// gets folded into the outcome (R18-B1) or appended to a spawn error
/// (R18-B2b), so it survives even when stderr is dropped.
fn collect_joined_panics(
    handles: Vec<(String, std::thread::JoinHandle<()>)>,
) -> Vec<(String, String)> {
    let mut panics = Vec::new();
    for (name, handle) in handles {
        if let Err(payload) = handle.join() {
            let msg = panic_message(payload);
            eprintln!("module {name} panicked: {msg}");
            panics.push((name, msg));
        }
    }
    panics
}

/// Format collected panics as `module {a} panicked: {x}; module {b} …`.
fn format_panics(panics: &[(String, String)]) -> String {
    panics
        .iter()
        .map(|(name, msg)| format!("module {name} panicked: {msg}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Join every module thread and fold all panics into the outcome (R18-B1):
/// a module that panicked before sending its completion only shows up at the
/// join, and the generic Disconnected error would otherwise hide it. Only
/// that generic error is replaced — an explicit module error or an interrupt
/// keeps its own cause.
fn finalize_module_outcome(
    mut outcome: Result<(), RunError>,
    handles: Vec<(String, std::thread::JoinHandle<()>)>,
) -> Result<(), RunError> {
    let panics = collect_joined_panics(handles);
    if !panics.is_empty()
        && matches!(
            outcome,
            Err(RunError::Module(ref m))
                if m.as_str() == "all modules stopped without a signal, [skip it]"
        )
    {
        outcome = Err(RunError::Module(format_panics(&panics)));
    }
    outcome
}

/// Build the spawn-failure error, appending any wind-down panic texts
/// (R18-B2b); without panics the message is unchanged.
fn spawn_failure_error(
    name: &str,
    e: impl std::fmt::Display,
    panics: &[(String, String)],
) -> RunError {
    let mut msg = format!("failed to spawn {name} module: {e}");
    if !panics.is_empty() {
        msg.push_str(&format!(
            "; also module(s) panicked: {}",
            format_panics(panics)
        ));
    }
    RunError::Module(msg)
}

/// Start every selected module and block until a signal or a module failure.
///
/// Upstream starts the modules from the main goroutine and `os.Exit(1)`s when
/// `mod.Run()` returns an error (`root.go:398-407`). Here each module runs on
/// its own thread (both modules block in their poll loop) and a failure is
/// forwarded to the main thread, which returns `RunError::Module` — i.e. the
/// process exits instead of waiting forever (report §4.6 / W18).
///
/// Round 12: one shared `Logger` (R11-9: two Loggers on the same `-o` path
/// truncated/unlinked each other's file), one shared `ConsoleResume`
/// (R11-5: a single stdin `c` resumes both modules), and every module exit —
/// Ok or Err — is reported to the wait loop (R11-4: a poll-error Ok exit
/// used to vanish until the other module finished too).
///
/// Round 14 (R14-5/R14-6/R14-2): module thread JoinHandles are collected and
/// joined before returning — `main()` exits via `process::exit`, so a thread
/// still printing its shutdown tail would otherwise lose its `TotalLost`
/// line, and the dropped-lines warning is only final after the join.
fn run_modules(
    modules: Vec<ModuleKind>,
    global: &GlobalConfig,
    target: &TargetConfig,
    table: crate::config::SyscallPointTable,
    selection: crate::config::SyscallSelection,
    w_points: Option<(String, Vec<crate::config::UprobeArgs>)>,
) -> Result<(), RunError> {
    install_signal_handler();

    let logger = Arc::new(crate::logger::Logger::new("", true));
    if !global.log_file.is_empty() {
        logger
            .set_out_file(&global.exec_path, &global.log_file, global.quiet)
            .map_err(|e| RunError::Module(format!("failed to open log file: {e:#}")))?;
    }
    let resume = Arc::new(crate::signal::ConsoleResume::new());

    let (tx, rx) = mpsc::channel::<(String, Option<String>)>();
    let module_count = modules.len();

    // Round 14 (R14-5/R14-6/R14-2): keep every module thread's JoinHandle
    // instead of dropping it. `main()` calls `process::exit` right after
    // `run()` returns, so a module thread still printing its shutdown summary
    // when we returned would lose its "TotalLost" line. Joining all handles
    // before returning makes the summaries and the dropped-lines warning
    // final. None of the joins below can hang:
    //   - Interrupt (path 1): the moment the wait loop sees INTERRUPTED it
    //     breaks; each module's poll loop (100ms interval) also sees
    //     `interrupted()` and exits, prints its "shutting down"/"TotalLost"
    //     tail, and returns — join returns as soon as that tail is done.
    //   - First completion with an error (path 2): storing INTERRUPTED before
    //     breaking (below) makes any other module stop through the same
    //     interrupted() exit.
    //   - Disconnected (path 3): `recv_timeout` only reports Disconnected once
    //     every sender — one per module thread, all cloned from `tx` — has
    //     been dropped, i.e. every module thread has already returned, so
    //     join is immediate.
    //   - Spawn failure: see the spawn-error arm below (INTERRUPTED is stored
    //     before joining).
    // A module thread that panics before finishing is seen by join as Err;
    // its payload is printed as a diagnostic below, but a broken module can
    // never panic the main thread during cleanup.
    let mut handles = Vec::new();
    // A clone owned by this frame: each loop iteration shadows `logger` with
    // a clone that moves into the closure, so the spawn-error arm could not
    // read `logger` after a failed spawn (use-of-moved-value).
    let warn_logger = Arc::clone(&logger);
    for kind in modules {
        let tx = tx.clone();
        let global = global.clone();
        let target = target.clone();
        let table = table.clone();
        let selection = selection.clone();
        let w_points = w_points.clone();
        let logger = Arc::clone(&logger);
        let resume = Arc::clone(&resume);
        let name = kind.name();
        match std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                let result = match kind {
                    ModuleKind::Syscall => {
                        syscall_cmd::run(&global, &target, table, selection, logger, resume)
                    }
                    ModuleKind::Stack => {
                        stack_cmd::run(&global, &target, w_points.clone(), logger, resume)
                    }
                };
                // Report every exit, Ok or Err (R11-4): the wait loop treats
                // any non-interrupt completion as a failure.
                let err = result.err().map(|e| format!("{e:#}"));
                if let Err(mpsc::SendError((_, Some(e)))) = tx.send((name.to_string(), err)) {
                    // The main loop already returned (e.g. after
                    // INTERRUPTED), so the receiver is gone and this module
                    // error would vanish silently. Narrow window: only
                    // reachable once the receiver is dropped.
                    eprintln!("module {name} failed after shutdown: {e}");
                }
            }) {
            Ok(handle) => handles.push((name.to_string(), handle)),
            Err(e) => {
                // R14-6: stop the modules that already started before failing.
                // They sit in 100ms poll loops that respect interrupted(), so
                // they wind down, print their tails, and exit on their own;
                // joining them guarantees the teardown output is complete. (A
                // module still setting up BPF when the flag flips sees it on
                // its first poll.)
                INTERRUPTED.store(true, Ordering::SeqCst);
                // R18-B2b: a wind-down panic must not vanish when stderr is
                // dropped, so append it to the spawn error (like R18-B2).
                let panics = collect_joined_panics(handles);
                print_dropped_lines_warning(&warn_logger);
                return Err(spawn_failure_error(name, e, &panics));
            }
        }
    }
    drop(tx);

    // One stdin reader feeding every module's SignalManager (R11-5).
    crate::signal::spawn_console_resume(resume);

    // `start N modules` banner (dev `root.go:417`).
    println!("start {module_count} modules");

    // Round 14 / R13-2: the dropped-lines warning is presented exactly once
    // here, after the wait loop, for the whole process. Each module's `run()`
    // used to present it via `finish_run`, so a dual-module run printed it
    // twice — the second count including the first module's dropped lines.
    // The loop breaks with the outcome; the warning prints before returning
    // it, whether the run succeeded or failed (a failing run loses logs too,
    // and that is when the warning matters most).
    let mut outcome = loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            break Ok(());
        }
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok((name, error)) => {
                if let Some(err) =
                    handle_module_completion(&name, error, INTERRUPTED.load(Ordering::SeqCst))
                {
                    // Stop the other module before returning (R11-4): a trace
                    // module ends on its own only through an error or a poll
                    // failure, and neither is a success.
                    INTERRUPTED.store(true, Ordering::SeqCst);
                    break Err(err);
                }
                break Ok(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Every module thread ended without sending a completion
                // (panicked before the send) — not a success: a trace loop
                // only ends on a signal or a module failure.
                break Err(RunError::Module(
                    "all modules stopped without a signal, [skip it]".into(),
                ));
            }
        }
    };
    // Round 14 (R14-5/R14-2): the loop broke on one of the three outcomes
    // above; join every module thread before the final warning so the dropped-
    // lines count (and the shutdown summaries) are final — see the path-by-
    // path argument at the `handles` collection above.
    outcome = finalize_module_outcome(outcome, handles);
    print_dropped_lines_warning(&logger);
    outcome
}

/// Print the shared dropped-lines warning exactly once, after every module
/// thread has been joined (R14-2), on every exit path — run success, run
/// failure, or spawn failure. The count is only final after the join.
fn print_dropped_lines_warning(logger: &crate::logger::Logger) {
    if let Some(warning) = crate::logger::Logger::dropped_lines_warning(logger.failed_lines()) {
        eprintln!("{warning}");
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

    /// Round 11 / P1: `-w 'write[...]s'` binds `write` into the syscall
    /// table (and is removed from the uprobe list) while an unbound point
    /// rides along to the stack module.
    #[test]
    fn dispatch_w_points_binds_and_keeps_remainder() {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-w-binds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = dir.join("libtest.so");
        std::fs::write(&lib, b"").unwrap();
        let global = GlobalConfig {
            hook_point: vec![
                "write[int,buf:128,int]s".to_string(),
                "openat[int]".to_string(),
            ],
            library: "libtest.so".to_string(),
            ..Default::default()
        };
        let target = TargetConfig {
            library_dirs: vec![dir.to_string_lossy().to_string()],
            ..Default::default()
        };
        let mut table = crate::config::SyscallPointTable::embedded().unwrap();
        let dispatch = dispatch_w_points(&global, &target, &mut table).unwrap();
        assert_eq!(dispatch.bound_names, ["write"]);
        let (lib_path, remaining) = dispatch.w_points.expect("unbound point must remain");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "openat");
        assert!(!remaining[0].bind_syscall);
        assert!(lib_path.ends_with("libtest.so"));
        let enter_names: Vec<&str> = table
            .by_name("write")
            .unwrap()
            .enter_point_args
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(enter_names, ["arg_0", "arg_1", "arg_2"]);
        std::fs::remove_file(&lib).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// Round 11 / P1: binding an unknown syscall name fails the dispatch
    /// instead of silently hanging an ordinary uprobe.
    #[test]
    fn dispatch_w_points_unknown_bound_name_bails() {
        crate::argtype::init_argtypes();
        let dir = std::env::temp_dir().join(format!("stackplz-w-unknown-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = dir.join("libtest.so");
        std::fs::write(&lib, b"").unwrap();
        let global = GlobalConfig {
            hook_point: vec!["nosuchsyscall[int]s".to_string()],
            library: "libtest.so".to_string(),
            ..Default::default()
        };
        let target = TargetConfig {
            library_dirs: vec![dir.to_string_lossy().to_string()],
            ..Default::default()
        };
        let mut table = crate::config::SyscallPointTable::embedded().unwrap();
        let err = dispatch_w_points(&global, &target, &mut table).unwrap_err();
        assert!(
            format!("{err:#}").contains("unknown syscall name:nosuchsyscall"),
            "{err:#}"
        );
        std::fs::remove_file(&lib).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// Round 11 / P1: no `-w` input means no dispatch and no bound names.
    #[test]
    fn dispatch_w_points_empty_hook_point_is_noop() {
        let mut table = crate::config::SyscallPointTable::empty();
        let dispatch = dispatch_w_points(
            &GlobalConfig::default(),
            &TargetConfig::default(),
            &mut table,
        )
        .unwrap();
        assert!(dispatch.w_points.is_none());
        assert!(dispatch.bound_names.is_empty());
    }

    /// Round 16 / R15-3: join payloads preserve the panic text in both
    /// common downcast shapes (`&str` and `String`), and fall back to a
    /// placeholder for anything else.
    #[test]
    fn panic_message_recovers_text_from_str_and_string_payloads() {
        use std::any::Any;
        let from_str: Box<dyn Any + Send> = Box::new("boom");
        assert_eq!(panic_message(from_str), "boom");
        let from_string: Box<dyn Any + Send> = Box::new(String::from("boom"));
        assert_eq!(panic_message(from_string), "boom");
        let other: Box<dyn Any + Send> = Box::new(42u32);
        assert_eq!(panic_message(other), "unknown panic payload");
    }

    /// Round 11 / P1: bound names append to the `-s` spec (Go's
    /// `gconfig.SysCall += "," + u_syscall`); empty parts never leave a
    /// stray leading comma.
    #[test]
    fn merge_syscall_spec_joins_and_skips_empty() {
        assert_eq!(merge_syscall_spec("", &["write".to_string()]), "write");
        assert_eq!(
            merge_syscall_spec("read", &["write".to_string()]),
            "read,write"
        );
        assert_eq!(merge_syscall_spec("", &[]), "");
        assert_eq!(merge_syscall_spec("read", &[]), "read");
    }

    /// Round 12 / R11-4: a module that exits Ok (the K1 poll-error exit)
    /// without an interrupt is a failure — the single-module Disconnected
    /// fact generalizes to either module finishing.
    #[test]
    fn ok_module_completion_without_interrupt_is_failure() {
        let err = handle_module_completion("StackMod", None, false).expect("must fail");
        let msg = err.message();
        assert!(msg.contains("StackMod"), "{msg}");
        assert!(msg.contains("stopped without a signal"), "{msg}");
    }

    /// Round 12 / R11-4: an error completion keeps dev's exact failure
    /// wording (`root.go:405`: `module Run failed, [skip it]`).
    #[test]
    fn error_module_completion_reports_error_text() {
        let err = handle_module_completion("SyscallMod", Some("perf poll failed".into()), false)
            .expect("must fail");
        let msg = err.message();
        assert!(msg.contains("SyscallMod"), "{msg}");
        assert!(msg.contains("module Run failed, [skip it]"), "{msg}");
        assert!(msg.contains("perf poll failed"), "{msg}");
    }

    /// Round 12 / R11-4: after Ctrl-C (interrupt) a completion is clean —
    /// Ok or Err — the process exits 0, not with a module failure.
    #[test]
    fn module_completion_after_interrupt_is_clean() {
        assert!(handle_module_completion("StackMod", None, true).is_none());
        assert!(handle_module_completion("StackMod", Some("x".into()), true).is_none());
    }

    /// Round 18 / R17-B1: a module that panicked before sending its completion
    /// replaces the generic Disconnected error with the panic text; without a
    /// panic the Disconnected outcome is unchanged, and an explicit module
    /// error keeps its own cause even when another module panicked.
    #[test]
    fn finalize_replaces_disconnected_with_first_panic() {
        let disconnected = || {
            Err(RunError::Module(
                "all modules stopped without a signal, [skip it]".into(),
            ))
        };

        // Panic replaces the generic Disconnected error.
        let panicked = std::thread::Builder::new()
            .name("StackMod".into())
            .spawn(|| panic!("module boom"))
            .unwrap();
        let err = finalize_module_outcome(disconnected(), vec![("StackMod".to_string(), panicked)])
            .unwrap_err();
        let msg = err.message();
        assert!(msg.contains("StackMod"), "{msg}");
        assert!(msg.contains("panicked"), "{msg}");
        assert!(msg.contains("module boom"), "{msg}");
        assert!(!msg.contains("stopped without a signal"), "{msg}");

        // No panic: the Disconnected error stays as-is.
        let quiet = std::thread::Builder::new()
            .name("StackMod".into())
            .spawn(|| {})
            .unwrap();
        let err = finalize_module_outcome(disconnected(), vec![("StackMod".to_string(), quiet)])
            .unwrap_err();
        assert_eq!(
            err.message(),
            "all modules stopped without a signal, [skip it]"
        );

        // An explicit module error keeps its cause.
        let panicked = std::thread::Builder::new()
            .name("StackMod".into())
            .spawn(|| panic!("module boom"))
            .unwrap();
        let err = finalize_module_outcome(
            Err(RunError::Module(
                "SyscallMod\tmodule Run failed, [skip it]. error:perf poll failed".into(),
            )),
            vec![("StackMod".to_string(), panicked)],
        )
        .unwrap_err();
        let msg = err.message();
        assert!(msg.contains("perf poll failed"), "{msg}");
        assert!(!msg.contains("panicked"), "{msg}");
    }

    /// Round 19 / R18-B1: both module panics replace the generic Disconnected
    /// error — the second one must not be hidden behind the first.
    #[test]
    fn finalize_replaces_disconnected_with_all_panics() {
        let disconnected = || {
            Err(RunError::Module(
                "all modules stopped without a signal, [skip it]".into(),
            ))
        };
        let first = std::thread::Builder::new()
            .name("StackMod".into())
            .spawn(|| panic!("first module boom"))
            .unwrap();
        let second = std::thread::Builder::new()
            .name("SyscallMod".into())
            .spawn(|| panic!("second module boom"))
            .unwrap();
        let err = finalize_module_outcome(
            disconnected(),
            vec![
                ("StackMod".to_string(), first),
                ("SyscallMod".to_string(), second),
            ],
        )
        .unwrap_err();
        assert_eq!(
            err.message(),
            "module StackMod panicked: first module boom; module SyscallMod panicked: second module boom"
        );
    }

    /// Round 19 / R18-B2b: a module panicking during wind-down after a spawn
    /// failure appends its text to the spawn error; without a panic the
    /// spawn error is unchanged.
    #[test]
    fn spawn_failure_appends_wind_down_panics() {
        let first = std::thread::Builder::new()
            .name("StackMod".into())
            .spawn(|| panic!("wind-down boom"))
            .unwrap();
        let panics = collect_joined_panics(vec![("StackMod".to_string(), first)]);
        let err = spawn_failure_error("SyscallMod", "spawn failed", &panics);
        assert_eq!(
            err.message(),
            "failed to spawn SyscallMod module: spawn failed; also module(s) panicked: module StackMod panicked: wind-down boom"
        );

        let quiet = std::thread::Builder::new()
            .name("StackMod".into())
            .spawn(|| {})
            .unwrap();
        let panics = collect_joined_panics(vec![("StackMod".to_string(), quiet)]);
        let err = spawn_failure_error("SyscallMod", "spawn failed", &panics);
        assert_eq!(
            err.message(),
            "failed to spawn SyscallMod module: spawn failed"
        );
    }
}
