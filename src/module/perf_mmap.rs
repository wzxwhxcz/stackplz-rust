//! Perf mmap2 event monitoring module. Mirrors `user/module/perf_mmap.go`.
//!
//! Monitors `PERF_RECORD_MMAP2` events to track dynamic library loading in target processes.
//! Used to update library base addresses for symbol resolution in uprobe hooks.

use crate::config::PerfMmapConfig;
use crate::logger::Logger;
use anyhow::{bail, Result};
use std::sync::Arc;

#[cfg(target_os = "linux")]
const PERF_TYPE_SOFTWARE: u32 = 1;
#[cfg(target_os = "linux")]
const PERF_COUNT_SW_DUMMY: u32 = 9;
#[cfg(target_os = "linux")]
const PERF_SAMPLE_IDENTIFIER: u64 = 1 << 16;
#[cfg(target_os = "linux")]
const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;

/// Module name constant
pub const NAME: &str = "PerfMmapMod";

/// PERF_RECORD_MMAP2 event structure (mirrors kernel perf_event.h)
/// Layout matches the kernel structure for parsing perf buffer events
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Mmap2Event {
    pub pid: u32,
    pub tid: u32,
    pub addr: u64,
    pub len: u64,
    pub pgoff: u64,
    pub maj: u32,
    pub min: u32,
    pub ino: u64,
    pub ino_generation: u64,
    pub prot: u32,
    pub flags: u32,
    // filename follows as variable-length null-terminated string
}

pub struct PerfMmapModule {
    pub conf: PerfMmapConfig,
}

impl PerfMmapModule {
    pub fn new(conf: PerfMmapConfig) -> Self {
        Self { conf }
    }

    #[cfg(target_os = "linux")]
    pub fn run(&self, logger: Arc<Logger>) -> Result<()> {
        logger.println(&format!("{}: starting perf mmap2 monitoring", NAME));

        // Open perf_event for PERF_RECORD_MMAP2
        let perf_fd = self.open_perf_event()?;

        logger.println(&format!(
            "{}: opened perf_event (simplified stub implementation)",
            NAME
        ));
        logger.println(&format!(
            "{}: TODO: implement full mmap ring buffer reading",
            NAME
        ));

        // TODO: Full implementation would:
        // 1. mmap() the perf_event fd to get ring buffer
        // 2. Parse perf_event_header from ring buffer
        // 3. Handle PERF_RECORD_MMAP2 events
        // 4. Update symbol resolution tables

        // For now, just keep the fd open
        std::mem::forget(perf_fd);

        logger.println(&format!("{}: monitoring active (stub)", NAME));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn open_perf_event(&self) -> Result<std::fs::File> {
        use std::os::unix::io::FromRawFd;

        // perf_event_attr structure (128 bytes, simplified version)
        #[repr(C)]
        struct PerfEventAttr {
            type_: u32,
            size: u32,
            config: u64,
            sample_period_freq: u64,
            sample_type: u64,
            read_format: u64,
            flags: u64, // bitfield containing disabled, mmap2, task, etc.
            _padding: [u8; 80],
        }

        let attr = PerfEventAttr {
            type_: PERF_TYPE_SOFTWARE,
            size: 128,
            config: PERF_COUNT_SW_DUMMY as u64,
            sample_period_freq: 0,
            sample_type: PERF_SAMPLE_IDENTIFIER,
            read_format: 0,
            flags: (1u64 << 0) | (1u64 << 13) | (1u64 << 3), // disabled=1, mmap2=1, task=1
            _padding: [0; 80],
        };

        // Filter by PID if configured
        let pid = if self.conf.sconfig.pid > 0 {
            self.conf.sconfig.pid as i32
        } else {
            -1 // All processes
        };

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
            bail!(
                "perf_event_open failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Enable the event
        unsafe {
            if libc::ioctl(fd as i32, PERF_EVENT_IOC_ENABLE as _, 0) < 0 {
                libc::close(fd as i32);
                bail!(
                    "PERF_EVENT_IOC_ENABLE failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) })
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn handle_mmap2_event(data: &[u8], logger: &Logger) -> Result<()> {
        if data.len() < std::mem::size_of::<Mmap2Event>() {
            bail!("mmap2 event too short: {} bytes", data.len());
        }

        // Parse the fixed-size header
        let event: &Mmap2Event = unsafe { &*(data.as_ptr() as *const Mmap2Event) };

        // Extract filename (variable-length null-terminated string after header)
        let filename_offset = std::mem::size_of::<Mmap2Event>();
        let filename_bytes = &data[filename_offset..];
        let filename_end = filename_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(filename_bytes.len());
        let filename = String::from_utf8_lossy(&filename_bytes[..filename_end]);

        // Filter: only interested in .so files (dynamic libraries)
        if !filename.contains(".so") {
            return Ok(());
        }

        // Log the mmap2 event
        logger.println(&format!(
            "{}: pid={} tid={} addr=0x{:x} len=0x{:x} file={}",
            NAME, event.pid, event.tid, event.addr, event.len, filename
        ));

        // TODO: Update library base address map for symbol resolution
        // This would integrate with the uprobe module's symbol resolver

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run(&self, logger: Arc<Logger>) -> Result<()> {
        logger.println(&format!("{}: perf_event not supported on non-Linux", NAME));
        bail!("perf_event requires Linux");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmap2_event_size() {
        // Verify struct size matches kernel PERF_RECORD_MMAP2 layout
        // 4 + 4 + 8 + 8 + 8 + 4 + 4 + 8 + 8 + 4 + 4 = 64 bytes
        assert_eq!(std::mem::size_of::<Mmap2Event>(), 64);
    }
}
