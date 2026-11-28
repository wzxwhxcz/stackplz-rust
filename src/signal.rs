//! Signal control for stopped processes (mirrors Go `user/event/ievent.go`).
//!
//! Event paths do two things, in Go order: record a stopped pid when the kill
//! signal is SIGSTOP ([`record_stopped_after_event`]), then optionally resume
//! it under `--auto` ([`auto_resume_after_event`]).

use anyhow::Result;
use std::collections::HashSet;

#[cfg(target_os = "linux")]
use nix::sys::signal::{kill, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;
use std::sync::{Arc, Mutex};

/// Manages stopped processes/threads for signal control.
///
/// Shared between the perf-event callbacks and the console-resume thread as an
/// `Arc<Mutex<SignalManager>>`: `&mut self` under the lock is the whole
/// synchronisation.
pub struct SignalManager {
    stopped_pids: HashSet<u32>,
}

impl SignalManager {
    pub fn new() -> Self {
        Self {
            stopped_pids: HashSet::new(),
        }
    }

    /// Add a PID to the stopped list
    pub fn add_stopped(&mut self, pid: u32) {
        self.stopped_pids.insert(pid);
    }

    /// Remove a PID from the stopped list
    pub fn remove_stopped(&mut self, pid: u32) {
        self.stopped_pids.remove(&pid);
    }

    /// Resume a single stopped process
    #[cfg(target_os = "linux")]
    pub fn resume_one(&mut self, pid: u32) -> Result<()> {
        match kill(Pid::from_raw(pid as i32), Signal::SIGCONT) {
            Ok(_) => {
                println!("Let {} Resume", pid);
                self.remove_stopped(pid);
                Ok(())
            }
            Err(nix::errno::Errno::ESRCH) => {
                println!("No such process -> {}", pid);
                self.remove_stopped(pid);
                Ok(())
            }
            Err(e) => {
                println!("LetItResume err: {}", e);
                self.remove_stopped(pid);
                Err(e.into())
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn resume_one(&mut self, pid: u32) -> Result<()> {
        println!("Signal control not supported on this platform");
        self.remove_stopped(pid);
        Ok(())
    }

    /// Resume all stopped processes
    #[cfg(target_os = "linux")]
    pub fn resume_all(&mut self) {
        println!("------LetItRun------");
        let pids: Vec<u32> = self.stopped_pids.iter().copied().collect();

        for pid in pids {
            match kill(Pid::from_raw(pid as i32), Signal::SIGCONT) {
                Ok(_) => {
                    println!("Let {} run", pid);
                    self.remove_stopped(pid);
                }
                Err(nix::errno::Errno::ESRCH) => {
                    println!("No such process -> {}", pid);
                    self.remove_stopped(pid);
                }
                Err(e) => {
                    println!("LetItRun err: {}", e);
                    self.remove_stopped(pid);
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn resume_all(&mut self) {
        println!("Signal control not supported on this platform");
        self.stopped_pids.clear();
    }

    /// Get count of stopped processes
    pub fn stopped_count(&self) -> usize {
        self.stopped_pids.len()
    }
}

impl Default for SignalManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Go `event_uprobe.go:77-78` / `event_raw_syscalls.go:72-73`: after each perf
/// event, `--auto` resumes that event's pid (`LetItResume(this.Pid)`).
///
/// `resume` is injected so tests can count calls; production passes a closure
/// over [`SignalManager::resume_one`], which already prints its own
/// diagnostics (so a failed resume needs no error channel here).
/// `pid == 0` never resumes: `kill(0, SIGCONT)` would signal the whole
/// process group, and 0 is never a real event pid.
pub fn auto_resume_after_event(resume: &mut dyn FnMut(u32), auto_resume: bool, pid: u32) {
    if auto_resume && pid != 0 {
        resume(pid);
    }
}

/// SIGSTOP as the numeric value modules carry (`parse_signal_name("SIGSTOP")`
/// in `stack_probe.rs`, = Go's `uint32(syscall.SIGSTOP)` on Linux).
const SIGSTOP_NUM: u32 = 19;

/// Go `event_uprobe.go:58-60` / `event_context.go:185`: before any resume, a
/// perf event records its pid as stopped iff the kill signal is SIGSTOP and
/// the pid is real (never 0, which would mean the whole process group).
/// Called before [`auto_resume_after_event`], mirroring Go's order
/// (AddStopped before LetItResume).
pub fn record_stopped_after_event(sig_mgr: &mut SignalManager, kill_signal: u32, pid: u32) {
    if kill_signal == SIGSTOP_NUM && pid != 0 {
        sig_mgr.add_stopped(pid);
    }
}

/// One shared console-resume fan-out for all modules (round 11 / R11-5):
/// every module registers its `SignalManager` and a single stdin thread calls
/// [`Self::resume_all`], so one `c` resumes every module's stopped pids —
/// the per-module `spawn_console_resume` threads raced for the same stdin
/// line and left the other module's pids frozen.
pub struct ConsoleResume {
    managers: Mutex<Vec<Arc<Mutex<SignalManager>>>>,
}

impl ConsoleResume {
    pub(crate) fn new() -> Self {
        Self {
            managers: Mutex::new(Vec::new()),
        }
    }

    /// Register a module's manager; later `c` lines resume its stopped pids.
    pub(crate) fn register(&self, mgr: Arc<Mutex<SignalManager>>) {
        self.managers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(mgr);
    }

    /// Resume every registered manager (the `c` fan-out).
    pub(crate) fn resume_all(&self) {
        let managers = self.managers.lock().unwrap_or_else(|p| p.into_inner());
        for mgr in managers.iter() {
            let mut g = mgr.lock().unwrap_or_else(|p| p.into_inner());
            g.resume_all();
        }
    }
}

impl Default for ConsoleResume {
    fn default() -> Self {
        Self::new()
    }
}

/// Dispatch one console line, mirroring Go `cli/cmd/root.go:429`: a trimmed
/// `"c"` resumes all stopped pids (Go's `event.LetItRun()`); any other line
/// (including empty) does nothing. Pure, so tests can drive it without the
/// stdin thread. Returns true iff the line triggered a resume.
pub fn handle_console_line(line: &str, mgr: &mut SignalManager) -> bool {
    if line.trim() == "c" {
        mgr.resume_all();
        true
    } else {
        false
    }
}

/// Fan one console line out to every registered module manager: `c` resumes
/// all of them, any other line does nothing. Pure, so tests drive it without
/// the stdin thread.
pub fn console_resume_line(resume: &ConsoleResume, line: &str) {
    if line.trim() == "c" {
        resume.resume_all();
    }
}

/// Spawn the console-resume thread reading stdin, mirroring Go
/// `cli/cmd/root.go:421-437`: on a scanner error we send ourselves SIGTERM
/// (as Go does); on EOF the thread quietly ends — Go busy-spins on EOF
/// instead, which is deliberately not reproduced.
///
/// `shortcut: non-interactive stdin (pipe/file) hits EOF immediately, so the
/// thread exits and console resume is unavailable; upgrade to a tty check if
/// that matters.`
#[cfg(target_os = "linux")]
pub fn spawn_console_resume(resume: Arc<ConsoleResume>) {
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.read_line(&mut line) {
                Ok(0) => return, // EOF: end the thread (documented deviation)
                Ok(_) => console_resume_line(&resume, &line),
                Err(_) => {
                    let _ = kill(Pid::this(), Signal::SIGTERM);
                    return;
                }
            }
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_console_resume(_resume: Arc<ConsoleResume>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_manager_add_remove() {
        let mut mgr = SignalManager::new();

        assert_eq!(mgr.stopped_count(), 0);

        mgr.add_stopped(1234);
        assert_eq!(mgr.stopped_count(), 1);

        mgr.add_stopped(5678);
        assert_eq!(mgr.stopped_count(), 2);

        mgr.add_stopped(1234); // duplicate
        assert_eq!(mgr.stopped_count(), 2);

        mgr.remove_stopped(1234);
        assert_eq!(mgr.stopped_count(), 1);

        mgr.remove_stopped(5678);
        assert_eq!(mgr.stopped_count(), 0);
    }

    /// Round 9 / H8: the hard-coded SIGSTOP number must agree with the signal
    /// name table (`--kill SIGSTOP` recording must not silently drift from
    /// `parse_signal_name`'s table).
    #[test]
    fn sigstop_num_matches_signal_table() {
        assert_eq!(
            SIGSTOP_NUM,
            crate::module::stack_probe::parse_signal_name("SIGSTOP")
        );
    }

    /// Round 9 / H24: `"c"` dispatches a resume (list drains), `"x"` and
    /// empty lines do nothing; the return value says whether it resumed.
    #[test]
    fn handle_console_line_resumes_on_c_and_ignores_others() {
        let mut mgr = SignalManager::new();
        mgr.add_stopped(4242);

        assert!(!handle_console_line("x", &mut mgr));
        assert!(!handle_console_line("", &mut mgr));
        assert!(!handle_console_line("  c extra", &mut mgr));
        assert_eq!(mgr.stopped_count(), 1);

        assert!(handle_console_line("c", &mut mgr));
        assert_eq!(mgr.stopped_count(), 0);
    }

    /// Round 11 / R11-5: one `c` line fans out to every registered manager —
    /// the dual-module fix (previously each module had its own stdin thread
    /// racing for the same line, so only one module resumed).
    #[test]
    fn console_resume_line_resumes_all_registered_managers() {
        let resume = ConsoleResume::new();
        let m1 = Arc::new(Mutex::new(SignalManager::new()));
        let m2 = Arc::new(Mutex::new(SignalManager::new()));
        m1.lock().unwrap().add_stopped(111);
        m2.lock().unwrap().add_stopped(222);
        resume.register(Arc::clone(&m1));
        resume.register(Arc::clone(&m2));

        console_resume_line(&resume, "x");
        assert_eq!(m1.lock().unwrap().stopped_count(), 1, "non-c line");
        assert_eq!(m2.lock().unwrap().stopped_count(), 1, "non-c line");

        console_resume_line(&resume, "c");
        assert_eq!(m1.lock().unwrap().stopped_count(), 0, "both must drain");
        assert_eq!(m2.lock().unwrap().stopped_count(), 0, "both must drain");
    }

    /// Round 7 / F4: `--auto` resumes the event pid exactly once per event;
    /// `--auto` off or pid 0 resumes nothing.
    #[test]
    fn auto_resume_after_event_calls_resume_once_per_event() {
        let mut calls: Vec<u32> = Vec::new();
        auto_resume_after_event(&mut |pid| calls.push(pid), true, 4242);
        assert_eq!(calls, vec![4242]);

        // A second event resumes its own pid, again exactly once.
        auto_resume_after_event(&mut |pid| calls.push(pid), true, 5151);
        assert_eq!(calls, vec![4242, 5151]);
    }

    #[test]
    fn auto_resume_after_event_is_a_noop_without_auto_or_pid() {
        let mut calls: Vec<u32> = Vec::new();
        auto_resume_after_event(&mut |pid| calls.push(pid), false, 4242);
        assert!(calls.is_empty(), "--auto off must not resume");
        auto_resume_after_event(&mut |pid| calls.push(pid), true, 0);
        assert!(calls.is_empty(), "pid 0 must never resume (process group)");
    }

    /// Round 8 / G3: `record_stopped_after_event` implements Go's record
    /// condition — SIGSTOP kill signal and a real (non-zero) pid only.
    #[test]
    fn record_stopped_after_event_records_only_sigstop_and_real_pids() {
        let mut mgr = SignalManager::new();
        record_stopped_after_event(&mut mgr, 19, 4242); // SIGSTOP
        assert_eq!(mgr.stopped_count(), 1);
        record_stopped_after_event(&mut mgr, 19, 4242); // duplicate
        assert_eq!(mgr.stopped_count(), 1);
        record_stopped_after_event(&mut mgr, 5, 5151); // SIGTRAP: not recorded
        assert_eq!(mgr.stopped_count(), 1);
        record_stopped_after_event(&mut mgr, 19, 0); // pid 0: never recorded
        assert_eq!(mgr.stopped_count(), 1);
    }

    /// Round 8 / G3, `--auto` on: record-then-resume calls resume exactly once
    /// per event and keeps the list empty (the injected resume mirrors
    /// `resume_one`'s remove-on-success contract).
    #[test]
    fn record_then_auto_resume_calls_resume_once_and_keeps_list_empty() {
        let mut mgr = SignalManager::new();
        let mut calls: Vec<u32> = Vec::new();
        for pid in [4242u32, 5151] {
            record_stopped_after_event(&mut mgr, 19, pid);
            auto_resume_after_event(
                &mut |p| {
                    calls.push(p);
                    mgr.remove_stopped(p);
                },
                true,
                pid,
            );
            assert_eq!(mgr.stopped_count(), 0, "list must stay empty under --auto");
        }
        assert_eq!(calls, vec![4242, 5151]);
    }

    #[cfg(target_os = "linux")]
    fn proc_state(pid: u32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit(')').next()?.trim_start().chars().next()
    }

    #[cfg(target_os = "linux")]
    fn wait_for_proc_state(pid: u32, ok: impl Fn(char) -> bool) {
        for _ in 0..200 {
            if let Some(state) = proc_state(pid) {
                if ok(state) {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("pid {pid} never reached the expected /proc state");
    }

    /// Round 8 / G3, `--auto` off: recorded pids stay in the list until
    /// `resume_all()` actually SIGCONTs them (real children, state asserted via
    /// `/proc/<pid>/stat`; `resume_all` tolerates ESRCH on its own).
    #[test]
    #[cfg(target_os = "linux")]
    fn resume_all_resumes_real_stopped_pids() {
        let mut kids = Vec::new();
        for _ in 0..2 {
            kids.push(
                std::process::Command::new("sleep")
                    .arg("60")
                    .spawn()
                    .unwrap(),
            );
        }
        let pids: Vec<u32> = kids.iter().map(|k| k.id()).collect();

        for &pid in &pids {
            kill(Pid::from_raw(pid as i32), Signal::SIGSTOP).expect("stop test child");
        }
        for &pid in &pids {
            wait_for_proc_state(pid, |st| st == 'T');
        }

        let mut mgr = SignalManager::new();
        for &pid in &pids {
            record_stopped_after_event(&mut mgr, 19, pid);
        }
        assert_eq!(mgr.stopped_count(), 2);

        mgr.resume_all();
        assert_eq!(mgr.stopped_count(), 0);
        for &pid in &pids {
            wait_for_proc_state(pid, |st| st == 'R' || st == 'S');
        }

        for mut kid in kids {
            let _ = kid.kill();
            let _ = kid.wait();
        }
    }

    /// Round 9 / H24: the console dispatch (`handle_console_line`) is what
    /// the stdin `"c"` thread calls; a non-`"c"` line must leave real stopped
    /// children in T, `"c"` must resume them to R/S.
    #[test]
    #[cfg(target_os = "linux")]
    fn handle_console_line_resumes_real_stopped_pids() {
        let mut kids = Vec::new();
        for _ in 0..2 {
            kids.push(
                std::process::Command::new("sleep")
                    .arg("60")
                    .spawn()
                    .unwrap(),
            );
        }
        let pids: Vec<u32> = kids.iter().map(|k| k.id()).collect();

        for &pid in &pids {
            kill(Pid::from_raw(pid as i32), Signal::SIGSTOP).expect("stop test child");
        }
        for &pid in &pids {
            wait_for_proc_state(pid, |st| st == 'T');
        }

        let mut mgr = SignalManager::new();
        for &pid in &pids {
            record_stopped_after_event(&mut mgr, 19, pid);
        }
        assert_eq!(mgr.stopped_count(), 2);

        assert!(!handle_console_line("x", &mut mgr));
        for &pid in &pids {
            wait_for_proc_state(pid, |st| st == 'T');
        }

        assert!(handle_console_line("c", &mut mgr));
        assert_eq!(mgr.stopped_count(), 0);
        for &pid in &pids {
            wait_for_proc_state(pid, |st| st == 'R' || st == 'S');
        }

        for mut kid in kids {
            let _ = kid.kill();
            let _ = kid.wait();
        }
    }
}
