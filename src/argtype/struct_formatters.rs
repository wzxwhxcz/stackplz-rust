//! Struct argument formatting, payload-driven.
//!
//! Port of the `Format()` methods in `user/argtype/config_struct.go` (+ the
//! arm64 `syscall.*` structs they embed: `Stat_t`, `Statfs_t`, `Rusage`,
//! `Sysinfo_t`, `EpollEvent`, `RawSockaddrUnix`).
//!
//! Each formatter takes the exact bytes the eBPF side saved for one struct
//! (`[u32 len][payload]`, payload length == the type's `sizeof`) and returns
//! the text Go appends after `0x%x` of the argument address. Layouts follow the
//! definitions Go reads (the arm64 kernel ABI), not a Rust struct mirror, so
//! field offsets are written out explicitly.
//!
//! `iovec`, `msghdr` and `string_array` are *not* here: they consume several
//! TLVs (see [`crate::argtype::parse`]).

use crate::util::hexdump::hex_dump_pure;
use crate::util::COLOR_GREEN;

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(d: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(off..off + 8)?.try_into().ok()?))
}

fn i64_at(d: &[u8], off: usize) -> Option<i64> {
    Some(i64::from_le_bytes(d.get(off..off + 8)?.try_into().ok()?))
}

fn i32_at(d: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(d.get(off..off + 4)?.try_into().ok()?))
}

fn be_u16_at(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(off..off + 2)?.try_into().ok()?))
}

/// Go `%x` on a signed value keeps the sign (`-42` -> `-2a`).
fn hex_i64(v: i64) -> String {
    if v < 0 {
        format!("-{:x}", v.unsigned_abs())
    } else {
        format!("{v:x}")
    }
}

/// `B2S`: decode a `[N]int8` C string (trim NUL/space from both ends).
fn cstr(d: &[u8]) -> String {
    super::render::b2s_trim(d)
}

/// `Arg_Timespec.Format`: `(sec=.., nsec=..)`.
fn timespec(d: &[u8]) -> Option<String> {
    Some(format!("(sec={}, nsec={})", i64_at(d, 0)?, i64_at(d, 8)?))
}

/// `Arg_Timeval.Format`: `{sec=.., usec=..}`.
fn timeval(d: &[u8], off: usize) -> Option<String> {
    Some(format!(
        "{{sec={}, usec={}}}",
        i64_at(d, off)?,
        i64_at(d, off + 8)?
    ))
}

/// Format one struct payload by its registered type name. `None` means the
/// payload is too short for the struct (the caller turns that into a decode
/// error) or the name has no formatter (the caller falls back).
///
/// Each arm mirrors the matching Go `Format()` field list, `"{%s}"` /
/// `"(%s)"` wrapper included.
pub fn format_struct(name: &str, d: &[u8]) -> Option<String> {
    match name {
        "timespec" => timespec(d),
        "timeval" => timeval(d, 0),
        "ittmerspec" => {
            let fields = vec![
                format!(
                    "it_interval={{{}}}",
                    timespec(d.get(0..16)?)?.trim_matches(['(', ')'])
                ),
                format!(
                    "it_value={{{}}}",
                    timespec(d.get(16..32)?)?.trim_matches(['(', ')'])
                ),
            ];
            Some(braced(&fields))
        }
        "sigaction" => {
            let fields = vec![
                format!("sa_handler=0x{:x}", u64_at(d, 0)?),
                format!("sa_sigaction=0x{:x}", u64_at(d, 8)?),
                format!("sa_mask=0x{:x}", u64_at(d, 16)?),
                format!("sa_flags=0x{:x}", u64_at(d, 24)?),
                format!("sa_restorer=0x{:x}", u64_at(d, 32)?),
            ];
            Some(braced(&fields))
        }
        "siginfo" => {
            let fields = vec![
                format!("si_signo=0x{:x}", i32_at(d, 0)?),
                format!("si_errno=0x{:x}", i32_at(d, 4)?),
                format!("si_code=0x{:x}", i32_at(d, 8)?),
                format!("sifields=0x{:x}", u64_at(d, 16)?),
            ];
            Some(braced(&fields))
        }
        "stack_t" => {
            let fields = vec![
                format!("ss_sp=0x{:x}", u64_at(d, 0)?),
                format!("ss_flags={}", i32_at(d, 8)?),
                format!("ss_size={}", i32_at(d, 12)?),
            ];
            Some(braced(&fields))
        }
        "pollfd" => Some(format!(
            "(fd={}, events={}, revents={})",
            i32_at(d, 0)?,
            u16_at(d, 4)?,
            u16_at(d, 6)?
        )),
        "epoll_event" => {
            let fields = vec![
                format!("events=0x{:x}", u32_at(d, 0)?),
                format!("fd={}", i32_at(d, 4)?),
            ];
            Some(braced(&fields))
        }
        // Go reads `syscall.Stat_t` (linux/arm64): dev, ino, mode, nlink, uid,
        // gid, rdev, __pad1, size, blksize, __pad2, blocks, atim, mtim, ctim.
        "stat" => {
            let fields = vec![
                format!("dev={}", u64_at(d, 0)?),
                format!("ino={}", u64_at(d, 8)?),
                format!("nlink={}", u32_at(d, 20)?),
                format!("mode={}", u32_at(d, 16)?),
                format!("uid={}", u32_at(d, 24)?),
                format!("gid={}", u32_at(d, 28)?),
                format!("rdev={}", u64_at(d, 32)?),
                format!("size={}", i64_at(d, 48)?),
                format!("blksize={}", i32_at(d, 56)?),
                format!("blocks={}", i64_at(d, 64)?),
                format!(
                    "atim={{tv_sec={}, tv_nsec={}}}",
                    i64_at(d, 72)?,
                    i64_at(d, 80)?
                ),
                format!(
                    "mtim={{tv_sec={}, tv_nsec={}}}",
                    i64_at(d, 88)?,
                    i64_at(d, 96)?
                ),
                format!(
                    "ctim={{tv_sec={}, tv_nsec={}}}",
                    i64_at(d, 104)?,
                    i64_at(d, 112)?
                ),
            ];
            Some(braced(&fields))
        }
        "statfs" => {
            let fields = vec![
                format!("type={}", i64_at(d, 0)?),
                format!("bsize={}", i64_at(d, 8)?),
                format!("blocks={}", u64_at(d, 16)?),
                format!("bfree={}", u64_at(d, 24)?),
                format!("bavail={}", u64_at(d, 32)?),
                format!("files={}", u64_at(d, 40)?),
                format!("ffree={}", u64_at(d, 48)?),
                format!("fsid={},{}", i32_at(d, 56)?, i32_at(d, 60)?),
                format!("namelen={}", i64_at(d, 64)?),
                format!("frsize={}", i64_at(d, 72)?),
                format!("flags={}", i64_at(d, 80)?),
                format!(
                    "spare=0x{:x},0x{:x},0x{:x},0x{:x}",
                    i64_at(d, 88)?,
                    i64_at(d, 96)?,
                    i64_at(d, 104)?,
                    i64_at(d, 112)?
                ),
            ];
            Some(braced(&fields))
        }
        "rusage" => {
            let mut fields = vec![
                format!(
                    "utime=timeval{{sec={}, usec={}}}",
                    i64_at(d, 0)?,
                    i64_at(d, 8)?
                ),
                format!(
                    "stime=timeval{{sec={}, usec={}}}",
                    i64_at(d, 16)?,
                    i64_at(d, 24)?
                ),
            ];
            for (label, off) in [
                ("Maxrss", 32usize),
                ("Ixrss", 40),
                ("Idrss", 48),
                ("Isrss", 56),
                ("Minflt", 64),
                ("Majflt", 72),
                ("Nswap", 80),
                ("Inblock", 88),
                ("Oublock", 96),
                ("Msgsnd", 104),
                ("Msgrcv", 112),
                ("Nsignals", 120),
                ("Nvcsw", 128),
                ("Nivcsw", 136),
            ] {
                fields.push(format!("{label}=0x{}", hex_i64(i64_at(d, off)?)));
            }
            Some(braced(&fields))
        }
        // Go reads `syscall.Utsname` as six [65]int8 C strings.
        "utsname" => {
            if d.len() < 390 {
                return None;
            }
            let fields = vec![
                format!("sysname={}", cstr(&d[0..65])),
                format!("nodename={}", cstr(&d[65..130])),
                format!("release={}", cstr(&d[130..195])),
                format!("version={}", cstr(&d[195..260])),
                format!("machine={}", cstr(&d[260..325])),
                format!("domainname={}", cstr(&d[325..390])),
            ];
            Some(braced(&fields))
        }
        "timezone" => {
            let fields = vec![
                format!("tz_minuteswest={}", i32_at(d, 0)?),
                format!("tz_dsttime={}", i32_at(d, 4)?),
            ];
            Some(braced(&fields))
        }
        // Go reads `syscall.Sysinfo_t` (linux/arm64): every field printed as hex.
        "sysinfo" => {
            let fields = vec![
                format!("uptime=0x{}", hex_i64(i64_at(d, 0)?)),
                format!(
                    "loads=0x{:x},0x{:x},0x{:x}",
                    u64_at(d, 8)?,
                    u64_at(d, 16)?,
                    u64_at(d, 24)?
                ),
                format!("totalram=0x{:x}", u64_at(d, 32)?),
                format!("freeram=0x{:x}", u64_at(d, 40)?),
                format!("sharedram=0x{:x}", u64_at(d, 48)?),
                format!("bufferram=0x{:x}", u64_at(d, 56)?),
                format!("totalswap=0x{:x}", u64_at(d, 64)?),
                format!("freeswap=0x{:x}", u64_at(d, 72)?),
                format!("procs=0x{:x}", u16_at(d, 80)?),
                format!("pad=0x{:x}", u16_at(d, 82)?),
                format!("totalhigh=0x{:x}", u64_at(d, 88)?),
                format!("freehigh=0x{:x}", u64_at(d, 96)?),
                format!("unit=0x{:x}", u32_at(d, 104)?),
            ];
            Some(braced(&fields))
        }
        "sockaddr" => sockaddr(d),
        _ => None,
    }
}

/// `"{%s}"` around Go's `strings.Join(fields, ", ")`.
fn braced(fields: &[String]) -> String {
    format!("{{{}}}", fields.join(", "))
}

/// Colour-wrapped hex dump used by the `AF_UNSPEC` / unknown-family sockaddr
/// branches (`util.HexDump(I2B(path), COLORGREEN)`).
fn green_hex_dump(d: &[u8]) -> String {
    format!(
        "{}{}{}",
        COLOR_GREEN,
        hex_dump_pure(d),
        crate::util::COLOR_RESET
    )
}

/// `Arg_RawSockaddrUnix.Format` (`config_struct.go:528-566`).
///
/// Go branches on the *host-endian* `Family` (`syscall.RawSockaddrUnix` embeds
/// `Family int16` and `Path [108]int8`). The `AF_INET6` branch re-serialises the
/// struct big-endian and re-reads fields from that buffer (an upstream quirk:
/// `Family` is read back LE while `Port`/`Flowinfo`/`Scope_id` are BE), so the
/// byte swaps below reproduce those exact steps.
fn sockaddr(d: &[u8]) -> Option<String> {
    if d.len() < 110 {
        return None;
    }
    let family = u16_at(d, 0)?;
    let path = &d[2..110];
    let out = match family {
        1 => format!("(family=AF_FILE, path={})", cstr(path)),
        2 => {
            // RawSockaddrInet4 { Family uint16; Port uint16; Addr [4]byte; Zero [8]byte }
            let port = u16_at(d, 2)?;
            let addr = std::net::Ipv4Addr::new(d[4], d[5], d[6], d[7]);
            format!("(family=AF_INET, port={port}, addr={addr})")
        }
        10 => {
            // Reproduce `binary.Write(BigEndian, RawSockaddrUnix)` then the
            // mixed-endian reads of `RawSockaddrInet6`.
            let mut buf = vec![0u8; 110];
            buf[0..2].copy_from_slice(&family.to_be_bytes());
            buf[2..110].copy_from_slice(path);
            // `Family` is read back little-endian from that big-endian buffer;
            // its value is not printed, only used to pick the branch above.
            let _family_from_be_buffer = u16::from_le_bytes([buf[0], buf[1]]);
            let port = be_u16_at(&buf, 2)?;
            let flowinfo =
                u32::from_be_bytes([*buf.get(4)?, *buf.get(5)?, *buf.get(6)?, *buf.get(7)?]);
            let addr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?);
            let scope_id =
                u32::from_be_bytes([*buf.get(24)?, *buf.get(25)?, *buf.get(26)?, *buf.get(27)?]);
            format!(
                "(family=AF_INET6, port={port}, flowinfo={flowinfo}, addr={addr}, scope_id={scope_id})"
            )
        }
        0 => format!("(family=AF_UNSPEC, path=\n{})", green_hex_dump(path)),
        other => format!("(family=0x{other:x}, path=\n{})", green_hex_dump(path)),
    };
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timespec_matches_go() {
        let mut d = [0u8; 16];
        d[0..8].copy_from_slice(&1234567890i64.to_le_bytes());
        d[8..16].copy_from_slice(&123456789i64.to_le_bytes());
        assert_eq!(
            format_struct("timespec", &d).unwrap(),
            "(sec=1234567890, nsec=123456789)"
        );
    }

    #[test]
    fn timezone_and_pollfd() {
        let mut d = [0u8; 8];
        d[0..4].copy_from_slice(&(-60i32).to_le_bytes());
        d[4..8].copy_from_slice(&(1i32).to_le_bytes());
        assert_eq!(
            format_struct("timezone", &d).unwrap(),
            "{tz_minuteswest=-60, tz_dsttime=1}"
        );
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&3i32.to_le_bytes());
        p[4..6].copy_from_slice(&1u16.to_le_bytes());
        p[6..8].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            format_struct("pollfd", &p).unwrap(),
            "(fd=3, events=1, revents=0)"
        );
    }

    #[test]
    fn short_payload_is_none() {
        assert!(format_struct("timespec", &[0u8; 8]).is_none());
        assert!(format_struct("sockaddr", &[0u8; 100]).is_none());
    }

    #[test]
    fn unknown_name_is_none() {
        assert!(format_struct("not_a_struct", &[0u8; 64]).is_none());
    }

    #[test]
    fn sockaddr_unix() {
        let mut d = [0u8; 110];
        d[0..2].copy_from_slice(&1u16.to_le_bytes()); // AF_FILE
        d[2..10].copy_from_slice(b"/tmp/foo");
        assert_eq!(
            format_struct("sockaddr", &d).unwrap(),
            "(family=AF_FILE, path=/tmp/foo)"
        );
    }

    #[test]
    fn sockaddr_inet() {
        let mut d = [0u8; 110];
        d[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
        d[2..4].copy_from_slice(&8080u16.to_le_bytes());
        d[4..8].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            format_struct("sockaddr", &d).unwrap(),
            "(family=AF_INET, port=8080, addr=1.2.3.4)"
        );
    }

    #[test]
    fn stat_uses_go_arm64_offsets() {
        let mut d = [0u8; 128];
        d[0..8].copy_from_slice(&7u64.to_le_bytes()); // dev
        d[8..16].copy_from_slice(&9u64.to_le_bytes()); // ino
        d[16..20].copy_from_slice(&0o100644u32.to_le_bytes()); // mode
        d[20..24].copy_from_slice(&1u32.to_le_bytes()); // nlink
        d[24..28].copy_from_slice(&1000u32.to_le_bytes()); // uid
        d[28..32].copy_from_slice(&1000u32.to_le_bytes()); // gid
        let s = format_struct("stat", &d).unwrap();
        assert!(
            s.starts_with("{dev=7, ino=9, nlink=1, mode=33188, uid=1000, gid=1000"),
            "{s}"
        );
    }

    #[test]
    fn rusage_uses_hex_like_go() {
        let mut d = [0u8; 144];
        d[32..40].copy_from_slice(&42i64.to_le_bytes()); // Maxrss
        let s = format_struct("rusage", &d).unwrap();
        assert!(s.contains("Maxrss=0x2a"), "{s}");
    }

    #[test]
    fn utf16_string_from_render_dependency_exists() {
        // sanity: the formatter uses render::b2s_trim
        assert_eq!(super::cstr(b"abc\0\0"), "abc");
    }
}
