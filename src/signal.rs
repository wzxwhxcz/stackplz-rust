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

/// Manages stopped processes/threads for signal control.
///
/// Single-threaded by design (the module run loop owns it), so it needs no
/// interior mutability: `&mut self` is the whole synchronisation.
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
    pub fn resume_all(&mut self) -> Result<()> {
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
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn resume_all(&mut self) -> Result<()> {
        println!("Signal control not supported on this platform");
        self.stopped_pids.clear();
        Ok(())
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

/// Parse signal name string to Signal enum
#[cfg(target_os = "linux")]
pub fn parse_signal(sig_name: &str) -> Option<Signal> {
    match sig_name.to_uppercase().as_str() {
        "SIGSTOP" => Some(Signal::SIGSTOP),
        "SIGCONT" => Some(Signal::SIGCONT),
        "SIGABRT" => Some(Signal::SIGABRT),
        "SIGTRAP" => Some(Signal::SIGTRAP),
        "SIGTERM" => Some(Signal::SIGTERM),
        "SIGKILL" => Some(Signal::SIGKILL),
        "SIGINT" => Some(Signal::SIGINT),
        "SIGUSR1" => Some(Signal::SIGUSR1),
        "SIGUSR2" => Some(Signal::SIGUSR2),
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn parse_signal(_sig_name: &str) -> Option<i32> {
    None
}

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

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_signal() {
        assert_eq!(parse_signal("SIGSTOP"), Some(Signal::SIGSTOP));
        assert_eq!(parse_signal("sigstop"), Some(Signal::SIGSTOP));
        assert_eq!(parse_signal("SIGCONT"), Some(Signal::SIGCONT));
        assert_eq!(parse_signal("SIGABRT"), Some(Signal::SIGABRT));
        assert_eq!(parse_signal("SIGTRAP"), Some(Signal::SIGTRAP));
        assert_eq!(parse_signal("INVALID"), None);
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

        mgr.resume_all().expect("resume_all");
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
