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

    /// Send a signal to a process
    #[cfg(target_os = "linux")]
    pub fn send_signal(&mut self, pid: u32, signal: Signal) -> Result<()> {
        kill(Pid::from_raw(pid as i32), signal)?;

        // Track stopped processes if SIGSTOP
        if signal == Signal::SIGSTOP {
            self.add_stopped(pid);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn send_signal(&mut self, _pid: u32, _signal: i32) -> Result<()> {
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
}
