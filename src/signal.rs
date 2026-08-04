use anyhow::Result;
use std::collections::HashSet;
use std::sync::Mutex;

#[cfg(target_os = "linux")]
use nix::sys::signal::{kill, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;

/// Manages stopped processes/threads for signal control
pub struct SignalManager {
    stopped_pids: Mutex<HashSet<u32>>,
}

impl SignalManager {
    pub fn new() -> Self {
        Self {
            stopped_pids: Mutex::new(HashSet::new()),
        }
    }

    /// Add a PID to the stopped list
    pub fn add_stopped(&self, pid: u32) {
        let mut stopped = self.stopped_pids.lock().unwrap();
        stopped.insert(pid);
    }

    /// Remove a PID from the stopped list
    pub fn remove_stopped(&self, pid: u32) {
        let mut stopped = self.stopped_pids.lock().unwrap();
        stopped.remove(&pid);
    }

    /// Resume a single stopped process
    #[cfg(target_os = "linux")]
    pub fn resume_one(&self, pid: u32) -> Result<()> {
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
    pub fn resume_one(&self, pid: u32) -> Result<()> {
        println!("Signal control not supported on this platform");
        self.remove_stopped(pid);
        Ok(())
    }

    /// Resume all stopped processes
    #[cfg(target_os = "linux")]
    pub fn resume_all(&self) -> Result<()> {
        println!("------LetItRun------");
        let pids: Vec<u32> = {
            let stopped = self.stopped_pids.lock().unwrap();
            stopped.iter().copied().collect()
        };

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
    pub fn resume_all(&self) -> Result<()> {
        println!("Signal control not supported on this platform");
        self.stopped_pids.lock().unwrap().clear();
        Ok(())
    }

    /// Send a signal to a process
    #[cfg(target_os = "linux")]
    pub fn send_signal(&self, pid: u32, signal: Signal) -> Result<()> {
        kill(Pid::from_raw(pid as i32), signal)?;

        // Track stopped processes if SIGSTOP
        if signal == Signal::SIGSTOP {
            self.add_stopped(pid);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn send_signal(&self, _pid: u32, _signal: i32) -> Result<()> {
        Ok(())
    }

    /// Get count of stopped processes
    pub fn stopped_count(&self) -> usize {
        self.stopped_pids.lock().unwrap().len()
    }
}

impl Default for SignalManager {
    fn default() -> Self {
        Self::new()
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
        let mgr = SignalManager::new();

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
}
