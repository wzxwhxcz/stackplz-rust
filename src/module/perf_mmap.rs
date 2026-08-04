//! Perf mmap2 event monitoring module. Mirrors `user/module/perf_mmap.go`.
//!
//! Monitors `PERF_RECORD_MMAP2` events to track dynamic library loading in target processes.
//! Used to update library base addresses for symbol resolution in uprobe hooks.

use crate::config::PerfMmapConfig;
use crate::logger::Logger;
use anyhow::{bail, Result};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use libbpf_rs::{MapFlags, PerfBufferBuilder};

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
        use std::os::unix::io::AsRawFd;

        logger.println(&format!("{}: starting perf mmap2 monitoring", NAME));

        // Open perf_event for PERF_RECORD_MMAP2
        let perf_fd = self.open_perf_event()?;
        
        logger.println(&format!("{}: opened perf_event fd={}", NAME, perf_fd.as_raw_fd()));

        // Create perf buffer to read mmap2 events
        let perf_buffer = PerfBufferBuilder::new(&perf_fd)
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                if let Err(e) = Self::handle_mmap2_event(data, &logger) {
                    logger.println(&format!("{}: event parse error: {}", NAME, e));
                }
            })
            .lost_cb(|_cpu: i32, count: u64| {
                eprintln!("{}: lost {} mmap2 events", NAME, count);
            })
            .build()?;

        logger.println(&format!("{}: polling mmap2 events (Ctrl-C to stop)", NAME));

        // Poll loop
        loop {
            match perf_buffer.poll(std::time::Duration::from_millis(100)) {
                Ok(_) => {}
                Err(e) => {
                    logger.println(&format!("{}: poll error: {}", NAME, e));
                    break;
                }
            }
        }

        logger.println(&format!("{}: shutting down", NAME));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn open_perf_event(&self) -> Result<std::fs::File> {
        use std::os::unix::io::FromRawFd;
        
        // perf_event_attr for PERF_RECORD_MMAP2
        let mut attr: libc::perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = libc::PERF_TYPE_SOFTWARE;
        attr.size = std::mem::size_of::<libc::perf_event_attr>() as u32;
        attr.config = libc::PERF_COUNT_SW_DUMMY as u64;
        attr.set_disabled(1);
        attr.set_mmap2(1); // Enable PERF_RECORD_MMAP2
        attr.set_task(1);  // Track fork/exit
        attr.sample_type = libc::PERF_SAMPLE_IDENTIFIER as u64;

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
            bail!("perf_event_open failed: {}", std::io::Error::last_os_error());
        }

        // Enable the event
        unsafe {
            if libc::ioctl(fd as i32, libc::PERF_EVENT_IOC_ENABLE as _, 0) < 0 {
                libc::close(fd as i32);
                bail!("PERF_EVENT_IOC_ENABLE failed: {}", std::io::Error::last_os_error());
            }
        }

        Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) })
    }

    #[cfg(target_os = "linux")]
    fn handle_mmap2_event(data: &[u8], logger: &Logger) -> Result<()> {
        if data.len() < std::mem::size_of::<Mmap2Event>() {
            bail!("mmap2 event too short: {} bytes", data.len());
        }

        // Parse the fixed-size header
        let event: &Mmap2Event = unsafe {
            &*(data.as_ptr() as *const Mmap2Event)
        };

        // Extract filename (variable-length null-terminated string after header)
        let filename_offset = std::mem::size_of::<Mmap2Event>();
        let filename_bytes = &data[filename_offset..];
        let filename_end = filename_bytes.iter().position(|&b| b == 0).unwrap_or(filename_bytes.len());
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
        // Verify struct size matches kernel expectations
        assert_eq!(std::mem::size_of::<Mmap2Event>(), 72);
    }
}
