//! Struct formatters for complex argument types
//!
//! This module provides Format implementations for all struct-based argument types,
//! ported from Go's config_struct.go Format() methods.

// ============================================================================
// Basic time-related structs
// ============================================================================

/// Timespec - nanosecond-precision timestamp
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

impl Timespec {
    pub fn format(&self) -> String {
        format!("(sec={}, nsec={})", self.sec, self.nsec)
    }
}

/// Timeval - microsecond-precision timestamp
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Timeval {
    pub sec: i64,
    pub usec: i64,
}

impl Timeval {
    pub fn format(&self) -> String {
        format!("{{sec={}, usec={}}}", self.sec, self.usec)
    }
}

/// TimeZone_t - timezone information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TimeZone {
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
}

impl TimeZone {
    pub fn format(&self) -> String {
        format!(
            "{{tz_minuteswest={}, tz_dsttime={}}}",
            self.tz_minuteswest, self.tz_dsttime
        )
    }
}

/// ItTmerspec - interval timer specification
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ItTmerspec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

impl ItTmerspec {
    pub fn format(&self) -> String {
        format!(
            "{{it_interval={{sec={}, nsec={}}}, it_value={{sec={}, nsec={}}}}}",
            self.it_interval.sec, self.it_interval.nsec, self.it_value.sec, self.it_value.nsec
        )
    }
}

// ============================================================================
// Signal-related structs
// ============================================================================

/// Sigaction - signal action structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Sigaction {
    pub sa_handler: u64,
    pub sa_sigaction: u64,
    pub sa_mask: u64,
    pub sa_flags: u64,
    pub sa_restorer: u64,
}

impl Sigaction {
    pub fn format(&self) -> String {
        format!(
            "{{sa_handler=0x{:x}, sa_sigaction=0x{:x}, sa_mask=0x{:x}, sa_flags=0x{:x}, sa_restorer=0x{:x}}}",
            self.sa_handler, self.sa_sigaction, self.sa_mask, self.sa_flags, self.sa_restorer
        )
    }
}

/// SigInfo - signal information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad: i32,
    pub sifields: [u8; 112], // Flexible union field
}

impl SigInfo {
    pub fn format(&self) -> String {
        format!(
            "{{si_signo=0x{:x}, si_errno=0x{:x}, si_code=0x{:x}, sifields=0x{:x}}}",
            self.si_signo,
            self.si_errno,
            self.si_code,
            // Show first 8 bytes of sifields as u64
            u64::from_ne_bytes(self.sifields[..8].try_into().unwrap_or([0; 8]))
        )
    }
}

/// Stack_t - signal stack
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StackT {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub ss_size: i32,
}

impl StackT {
    pub fn format(&self) -> String {
        format!(
            "{{ss_sp=0x{:x}, ss_flags={}, ss_size={}}}",
            self.ss_sp, self.ss_flags, self.ss_size
        )
    }
}

// ============================================================================
// I/O and polling structs
// ============================================================================

/// Pollfd - poll file descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Pollfd {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
}

impl Pollfd {
    pub fn format(&self) -> String {
        format!(
            "(fd={}, events={}, revents={})",
            self.fd, self.events, self.revents
        )
    }
}

/// EpollEvent - epoll event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub fd: i32,
    pub pad: i32,
}

impl EpollEvent {
    pub fn format(&self) -> String {
        format!("{{events=0x{:x}, fd={}}}", self.events, self.fd)
    }
}

/// Iovec - I/O vector (pointer-based)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Iovec {
    pub base: u64,
    pub buflen: u64,
}

impl Iovec {
    pub fn format(&self) -> String {
        format!("{{base=0x{:x}, len=0x{:x}}}", self.base, self.buflen)
    }

    pub fn format_with_buf(&self, buf: &[u8]) -> String {
        format!(
            "{{base=0x{:x}, len=0x{:x}, buf=({})}}",
            self.base,
            self.buflen,
            pretty_byte_slice(buf)
        )
    }
}

/// Msghdr - message header for sendmsg/recvmsg
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Msghdr {
    pub name: u64,
    pub namelen: u32,
    pub _pad_cgo_0: [u8; 4],
    pub iov: u64,
    pub iovlen: u64,
    pub control: u64,
    pub controllen: u64,
    pub flags: i32,
    pub _pad_cgo_1: [u8; 4],
}

impl Msghdr {
    pub fn format(&self) -> String {
        format!(
            "(name=0x{:x}, namelen=0x{:x}, *iov=0x{:x}, iovlen=0x{:x}, *control=0x{:x}, controllen=0x{:x}, flags=0x{:x})",
            self.name, self.namelen, self.iov, self.iovlen, self.control, self.controllen, self.flags
        )
    }
}

// ============================================================================
// File system and resource structs
// ============================================================================

/// Stat_t - file status
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatT {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub _pad0: i32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atim: Timespec,
    pub mtim: Timespec,
    pub ctim: Timespec,
    pub _unused: [i64; 3],
}

impl StatT {
    pub fn format(&self) -> String {
        format!(
            "{{dev={}, ino={}, nlink={}, mode={}, uid={}, gid={}, rdev={}, size={}, blksize={}, blocks={}, atim={{tv_sec={}, tv_nsec={}}}, mtim={{tv_sec={}, tv_nsec={}}}, ctim={{tv_sec={}, tv_nsec={}}}}}",
            self.dev, self.ino, self.nlink, self.mode, self.uid, self.gid, self.rdev,
            self.size, self.blksize, self.blocks,
            self.atim.sec, self.atim.nsec,
            self.mtim.sec, self.mtim.nsec,
            self.ctim.sec, self.ctim.nsec
        )
    }
}

/// Statfs_t - filesystem statistics
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatfsT {
    pub r#type: i64,
    pub bsize: i64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: [i32; 2],
    pub namelen: i64,
    pub frsize: i64,
    pub flags: i64,
    pub spare: [i64; 4],
}

impl StatfsT {
    pub fn format(&self) -> String {
        format!(
            "{{type={}, bsize={}, blocks={}, bfree={}, bavail={}, files={}, ffree={}, fsid={},{}, namelen={}, frsize={}, flags={}, spare=0x{:x},0x{:x},0x{:x},0x{:x}}}",
            self.r#type, self.bsize, self.blocks, self.bfree, self.bavail,
            self.files, self.ffree, self.fsid[0], self.fsid[1],
            self.namelen, self.frsize, self.flags,
            self.spare[0], self.spare[1], self.spare[2], self.spare[3]
        )
    }
}

/// Rusage - resource usage
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rusage {
    pub utime: Timeval,
    pub stime: Timeval,
    pub maxrss: i64,
    pub ixrss: i64,
    pub idrss: i64,
    pub isrss: i64,
    pub minflt: i64,
    pub majflt: i64,
    pub nswap: i64,
    pub inblock: i64,
    pub oublock: i64,
    pub msgsnd: i64,
    pub msgrcv: i64,
    pub nsignals: i64,
    pub nvcsw: i64,
    pub nivcsw: i64,
}

impl Rusage {
    pub fn format(&self) -> String {
        format!(
            "{{utime=timeval{{sec={}, usec={}}}, stime=timeval{{sec={}, usec={}}}, Maxrss=0x{:x}, Ixrss=0x{:x}, Idrss=0x{:x}, Isrss=0x{:x}, Minflt=0x{:x}, Majflt=0x{:x}, Nswap=0x{:x}, Inblock=0x{:x}, Oublock=0x{:x}, Msgsnd=0x{:x}, Msgrcv=0x{:x}, Nsignals=0x{:x}, Nvcsw=0x{:x}, Nivcsw=0x{:x}}}",
            self.utime.sec, self.utime.usec, self.stime.sec, self.stime.usec,
            self.maxrss, self.ixrss, self.idrss, self.isrss, self.minflt,
            self.majflt, self.nswap, self.inblock, self.oublock, self.msgsnd,
            self.msgrcv, self.nsignals, self.nvcsw, self.nivcsw
        )
    }
}

/// Sysinfo_t - system information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysinfoT {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub unit: u32,
    pub _f: [i8; 0],
}

impl SysinfoT {
    pub fn format(&self) -> String {
        format!(
            "{{uptime=0x{:x}, loads=0x{:x},0x{:x},0x{:x}, totalram=0x{:x}, freeram=0x{:x}, sharedram=0x{:x}, bufferram=0x{:x}, totalswap=0x{:x}, freeswap=0x{:x}, procs=0x{:x}, pad=0x{:x}, totalhigh=0x{:x}, freehigh=0x{:x}, unit=0x{:x}}}",
            self.uptime, self.loads[0], self.loads[1], self.loads[2],
            self.totalram, self.freeram, self.sharedram, self.bufferram,
            self.totalswap, self.freeswap, self.procs, self.pad,
            self.totalhigh, self.freehigh, self.unit
        )
    }
}

/// Pthread_attr_t - pthread attribute (opaque)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PthreadAttrT {
    pub _data: [u8; 56], // Platform-dependent size
}

impl PthreadAttrT {
    pub fn format(&self) -> String {
        // Show first 16 bytes as hex
        format!(
            "{{_data=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} ...]}}",
            self._data[0],
            self._data[1],
            self._data[2],
            self._data[3],
            self._data[4],
            self._data[5],
            self._data[6],
            self._data[7]
        )
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Format byte slice as pretty string (max 32 bytes shown)
fn pretty_byte_slice(buf: &[u8]) -> String {
    if buf.is_empty() {
        return "[]".to_string();
    }

    let len = buf.len().min(32);
    let mut result = String::new();

    // Try to show as string if printable
    if buf.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        result.push('"');
        for &b in &buf[..len] {
            result.push(b as char);
        }
        result.push('"');
    } else {
        // Show as hex
        result.push('[');
        for (i, &b) in buf[..len].iter().enumerate() {
            if i > 0 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x}", b));
        }
        result.push(']');
    }

    if buf.len() > 32 {
        result.push_str(&format!(" ...({} bytes total)", buf.len()));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timespec_format() {
        let ts = Timespec {
            sec: 1234567890,
            nsec: 123456789,
        };
        assert_eq!(ts.format(), "(sec=1234567890, nsec=123456789)");
    }

    #[test]
    fn test_pollfd_format() {
        let pfd = Pollfd {
            fd: 3,
            events: 1,
            revents: 0,
        };
        assert_eq!(pfd.format(), "(fd=3, events=1, revents=0)");
    }

    #[test]
    fn test_sigaction_format() {
        let sa = Sigaction {
            sa_handler: 0x12345678,
            sa_sigaction: 0,
            sa_mask: 0xffffffff,
            sa_flags: 0x04000000,
            sa_restorer: 0,
        };
        assert!(sa.format().contains("sa_handler=0x12345678"));
    }
}
