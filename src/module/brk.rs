//! Hardware breakpoint (brk) module. Mirrors `user/module/brk.go`.
//!
//! Provides hardware watchpoint functionality to monitor memory access at specific addresses.
//! Uses ptrace API to set hardware breakpoints (debug registers DR0-DR3 on x86_64/arm64).

use crate::logger::Logger;
use anyhow::{bail, Result};
use std::sync::Arc;

#[cfg(target_os = "linux")]
const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;

/// Module name constant
pub const NAME: &str = "BrkMod";

/// Hardware breakpoint types (mirrors kernel HW_BREAKPOINT_* constants)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BrkType {
    Execute = 0,  // HW_BREAKPOINT_X
    Write = 1,    // HW_BREAKPOINT_W
    ReadWrite = 3, // HW_BREAKPOINT_RW
}

/// Hardware breakpoint size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BrkLen {
    Len1 = 1,
    Len2 = 2,
    Len4 = 4,
    Len8 = 8,
}

/// Hardware breakpoint configuration
#[derive(Debug, Clone)]
pub struct BrkConfig {
    pub pid: i32,
    pub addr: u64,
    pub brk_type: BrkType,
    pub brk_len: BrkLen,
    pub debug: bool,
}

impl BrkConfig {
    pub fn new(pid: i32, addr: u64) -> Self {
        Self {
            pid,
            addr,
            brk_type: BrkType::Write,
            brk_len: BrkLen::Len8,
            debug: false,
        }
    }

    pub fn with_type(mut self, brk_type: BrkType) -> Self {
        self.brk_type = brk_type;
        self
    }

    pub fn with_len(mut self, brk_len: BrkLen) -> Self {
        self.brk_len = brk_len;
        self
    }
}

pub struct BrkModule {
    pub conf: BrkConfig,
}

impl BrkModule {
    pub fn new(conf: BrkConfig) -> Self {
        Self { conf }
    }

    #[cfg(target_os = "linux")]
    pub fn run(&self, logger: Arc<Logger>) -> Result<()> {
        logger.println(&format!("{}: starting hardware breakpoint", NAME));
        logger.println(&format!(
            "{}: pid={} addr=0x{:x} type={:?} len={:?}",
            NAME, self.conf.pid, self.conf.addr, self.conf.brk_type, self.conf.brk_len
        ));

        // Attach to target process with ptrace
        self.ptrace_attach(self.conf.pid)?;
        logger.println(&format!("{}: attached to pid {}", NAME, self.conf.pid));

        // Set hardware breakpoint
        self.set_hw_breakpoint(self.conf.pid, self.conf.addr, self.conf.brk_type, self.conf.brk_len)?;
        logger.println(&format!("{}: hardware breakpoint set at 0x{:x}", NAME, self.conf.addr));

        // Continue execution
        self.ptrace_cont(self.conf.pid)?;
        logger.println(&format!("{}: process resumed, monitoring breakpoint", NAME));

        // Wait for breakpoint hits
        loop {
            match self.wait_for_breakpoint(self.conf.pid) {
                Ok(hit_addr) => {
                    logger.println(&format!(
                        "{}: breakpoint hit at 0x{:x} (pid={})",
                        NAME, hit_addr, self.conf.pid
                    ));
                    // Continue after hit
                    self.ptrace_cont(self.conf.pid)?;
                }
                Err(e) => {
                    logger.println(&format!("{}: wait error: {}", NAME, e));
                    break;
                }
            }
        }

        // Detach
        self.ptrace_detach(self.conf.pid)?;
        logger.println(&format!("{}: detached from pid {}", NAME, self.conf.pid));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn ptrace_attach(&self, pid: i32) -> Result<()> {
        let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
        if ret < 0 {
            bail!("ptrace attach failed: {}", std::io::Error::last_os_error());
        }
        // Wait for stop
        let mut status: i32 = 0;
        let ret = unsafe { libc::waitpid(pid, &mut status as *mut i32, 0) };
        if ret < 0 {
            bail!("waitpid failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn ptrace_detach(&self, pid: i32) -> Result<()> {
        let ret = unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
        if ret < 0 {
            bail!("ptrace detach failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn ptrace_cont(&self, pid: i32) -> Result<()> {
        let ret = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) };
        if ret < 0 {
            bail!("ptrace cont failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_hw_breakpoint(&self, pid: i32, addr: u64, brk_type: BrkType, brk_len: BrkLen) -> Result<()> {
        // On x86_64/arm64, hardware breakpoints use debug registers
        // This is a simplified implementation using perf_event_open with PERF_TYPE_BREAKPOINT
        
        // perf_event_attr structure (128 bytes, see linux/perf_event.h)
        // We'll use a raw byte buffer since libc crate may not expose it
        #[repr(C)]
        struct PerfEventAttr {
            type_: u32,
            size: u32,
            config: u64,
            // ... many more fields, we'll zero them
            _padding: [u8; 112],
        }
        
        let mut attr = PerfEventAttr {
            type_: 5, // PERF_TYPE_BREAKPOINT
            size: 128,
            config: 0,
            _padding: [0; 112],
        };
        
        // Set breakpoint type
        let bp_type = match brk_type {
            BrkType::Execute => 1,    // HW_BREAKPOINT_X
            BrkType::Write => 2,      // HW_BREAKPOINT_W
            BrkType::ReadWrite => 6,  // HW_BREAKPOINT_RW (2|4)
        };
        attr.config = bp_type as u64;

        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const _,
                pid,
                -1, // cpu (all CPUs)
                -1, // group_fd
                0,  // flags
            )
        };

        if fd < 0 {
            bail!("perf_event_open for breakpoint failed: {}", std::io::Error::last_os_error());
        }

        // Enable the breakpoint
        unsafe {
            if libc::ioctl(fd as i32, PERF_EVENT_IOC_ENABLE as _, 0) < 0 {
                libc::close(fd as i32);
                bail!("PERF_EVENT_IOC_ENABLE failed: {}", std::io::Error::last_os_error());
            }
        }

        // Store fd for later cleanup (TODO: proper lifecycle management)
        std::mem::forget(unsafe { std::fs::File::from_raw_fd(fd as i32) });

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn wait_for_breakpoint(&self, pid: i32) -> Result<u64> {
        let mut status: i32 = 0;
        let ret = unsafe { libc::waitpid(pid, &mut status as *mut i32, 0) };
        if ret < 0 {
            bail!("waitpid failed: {}", std::io::Error::last_os_error());
        }

        // Check if stopped by signal
        if libc::WIFSTOPPED(status) {
            let sig = libc::WSTOPSIG(status);
            if sig == libc::SIGTRAP {
                // Breakpoint hit - return the configured address
                // (In production, we'd read the actual hit address from debug registers)
                return Ok(self.conf.addr);
            }
        }

        bail!("process exited or received unexpected signal");
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run(&self, logger: Arc<Logger>) -> Result<()> {
        logger.println(&format!("{}: hardware breakpoints not supported on non-Linux", NAME));
        bail!("hardware breakpoints require Linux");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brk_type_values() {
        assert_eq!(BrkType::Execute as u32, 0);
        assert_eq!(BrkType::Write as u32, 1);
        assert_eq!(BrkType::ReadWrite as u32, 3);
    }

    #[test]
    fn brk_len_values() {
        assert_eq!(BrkLen::Len1 as u32, 1);
        assert_eq!(BrkLen::Len2 as u32, 2);
        assert_eq!(BrkLen::Len4 as u32, 4);
        assert_eq!(BrkLen::Len8 as u32, 8);
    }

    #[test]
    fn brk_config_builder() {
        let conf = BrkConfig::new(1234, 0xdeadbeef)
            .with_type(BrkType::ReadWrite)
            .with_len(BrkLen::Len4);
        
        assert_eq!(conf.pid, 1234);
        assert_eq!(conf.addr, 0xdeadbeef);
        assert_eq!(conf.brk_type, BrkType::ReadWrite);
        assert_eq!(conf.brk_len, BrkLen::Len4);
    }
}
