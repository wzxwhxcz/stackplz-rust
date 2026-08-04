//! Argument value rendering — port of `user/argtype/argtype_base.go` (Parse methods)
//! and `user/argtype/config_struct.go` (Format/HexFormat methods).
//!
//! Each arg type knows how to render its value from the raw TLV bytes:
//! - Numbers: `42`, `0x2a`, `0b101010`, `0o52`
//! - Strings: `(hello world)`
//! - Buffers: `(68656c6c6f)` or hex dump
//! - Structs: `{sa_handler=0x1234, sa_flags=0x100}`

use crate::argtype::consts::*;
use crate::argtype::struct_formatters::*;

/// Format a number value according to the format_type.
/// Mirrors `ARG_INT::Parse` / `ARG_UINT::Parse` etc. in argtype_base.go.
pub fn format_num(value: u64, format_type: u32, is_signed: bool, byte_size: u32) -> String {
    // Mask to the effective byte size.
    let masked = mask_to_size(value, byte_size);
    let signed_val = if is_signed {
        sign_extend(masked, byte_size) as i64
    } else {
        0
    };

    match format_type {
        FORMAT_NUM | FORMAT_DEC => {
            if is_signed {
                format!("{signed_val}")
            } else {
                format!("{masked}")
            }
        }
        FORMAT_HEX => {
            if is_signed {
                format!("0x{:x}", signed_val as u64)
            } else {
                format!("0x{masked:x}")
            }
        }
        FORMAT_HEX_PURE => {
            if is_signed {
                format!("{:x}", signed_val as u64)
            } else {
                format!("{masked:x}")
            }
        }
        FORMAT_OCT => {
            if is_signed {
                format!("0o{:03o}", signed_val as u64)
            } else {
                format!("0o{masked:03o}")
            }
        }
        FORMAT_BIN => {
            if is_signed {
                format!("0b{:b}", signed_val as u64)
            } else {
                format!("0b{masked:b}")
            }
        }
        _ => {
            if is_signed {
                format!("{signed_val}")
            } else {
                format!("{masked}")
            }
        }
    }
}

/// Format a pointer value: `0x{addr:x}`.
pub fn format_ptr(addr: u64) -> String {
    format!("0x{addr:x}")
}

/// Format a buffer as a compact hex string: `(68656c6c6f)`.
/// Mirrors `Arg_buffer::Format()`.
pub fn format_buffer(data: &[u8]) -> String {
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    format!("({hex})")
}

/// Format a buffer as a hex dump with newlines.
/// Mirrors `Arg_buffer::HexFormat(color)`.
pub fn format_buffer_hexdump(data: &[u8], _color: bool) -> String {
    if data.is_empty() {
        return "()".to_string();
    }
    let mut lines = Vec::new();
    for chunk in data.chunks(16) {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (32..=126).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(format!("  {hex:<48} {ascii}"));
    }
    format!("(\n{}\n)", lines.join("\n"))
}

/// Format a UTF-8 string: `(hello world)`.
/// Mirrors `Arg_string::Format()`.
pub fn format_string(data: &[u8]) -> String {
    let s = trim_nul(data);
    format!("({s})")
}

/// Format a UTF-16LE string: `(hello)`.
/// Mirrors `Arg_string16::Format()`.
pub fn format_string16(data: &[u8]) -> String {
    let s = utf16le_to_utf8(data);
    format!("({s})")
}

/// Trim trailing NULs and spaces, returning a UTF-8 string.
/// Mirrors `util.B2STrim`.
pub fn trim_nul(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map(|i| i + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Convert UTF-16LE bytes to UTF-8 string, stopping at first NUL.
/// Mirrors `utf16leToUtf8` in config_struct.go.
pub fn utf16le_to_utf8(b: &[u8]) -> String {
    if b.len() < 2 {
        return String::new();
    }
    let mut u16s: Vec<u16> = Vec::new();
    for chunk in b.chunks_exact(2) {
        let v = u16::from_le_bytes([chunk[0], chunk[1]]);
        if v == 0 {
            break;
        }
        u16s.push(v);
    }
    String::from_utf16_lossy(&u16s)
}

// ---- Helpers ----

fn mask_to_size(value: u64, byte_size: u32) -> u64 {
    match byte_size {
        1 => value & 0xFF,
        2 => value & 0xFFFF,
        4 => value & 0xFFFFFFFF,
        _ => value, // 8 or 0 (pointer)
    }
}

fn sign_extend(value: u64, byte_size: u32) -> i64 {
    match byte_size {
        1 => (value as u8) as i8 as i64,
        2 => (value as u16) as i16 as i64,
        4 => (value as u32) as i32 as i64,
        _ => value as i64,
    }
}

/// Render a struct value by type index.
/// Returns formatted string if the type index is recognized, None otherwise.
pub fn render_struct_by_type_index(type_index: u32, data: &[u8]) -> Option<String> {
    // Helper to read u64 at offset
    let read_u64 = |offset: usize| -> u64 {
        if offset + 8 <= data.len() {
            u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7],
            ])
        } else {
            0
        }
    };
    
    // Helper to read i64 at offset
    let read_i64 = |offset: usize| -> i64 {
        read_u64(offset) as i64
    };
    
    // Helper to read u32 at offset
    let read_u32 = |offset: usize| -> u32 {
        if offset + 4 <= data.len() {
            u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
        } else {
            0
        }
    };
    
    // Helper to read i32 at offset
    let read_i32 = |offset: usize| -> i32 {
        read_u32(offset) as i32
    };
    
    // Helper to read u16 at offset
    let read_u16 = |offset: usize| -> u16 {
        if offset + 2 <= data.len() {
            u16::from_le_bytes([data[offset], data[offset+1]])
        } else {
            0
        }
    };
    
    match type_index {
        TIMESPEC => {
            if data.len() >= SIZEOF_TIMESPEC as usize {
                let ts = Timespec {
                    sec: read_i64(0),
                    nsec: read_i64(8),
                };
                Some(ts.format())
            } else {
                None
            }
        }
        TIMEVAL => {
            if data.len() >= SIZEOF_TIMEVAL as usize {
                let tv = Timeval {
                    sec: read_i64(0),
                    usec: read_i64(8),
                };
                Some(tv.format())
            } else {
                None
            }
        }
        SIGACTION => {
            if data.len() >= SIZEOF_SIGACTION as usize {
                let sa = Sigaction {
                    sa_handler: read_u64(0),
                    sa_sigaction: read_u64(8),
                    sa_mask: read_u64(16),
                    sa_flags: read_u64(24),
                    sa_restorer: read_u64(32),
                };
                Some(sa.format())
            } else {
                None
            }
        }
        POLLFD => {
            if data.len() >= SIZEOF_POLLFD as usize {
                let pfd = Pollfd {
                    fd: read_i32(0),
                    events: read_u16(4),
                    revents: read_u16(6),
                };
                Some(pfd.format())
            } else {
                None
            }
        }
        STACK_T => {
            if data.len() >= SIZEOF_STACK_T as usize {
                let st = StackT {
                    ss_sp: read_u64(0),
                    ss_flags: read_i32(8),
                    ss_size: read_i32(12),
                };
                Some(st.format())
            } else {
                None
            }
        }
        MSGHDR => {
            if data.len() >= SIZEOF_MSGHDR as usize {
                let msg = Msghdr {
                    name: read_u64(0),
                    namelen: read_u32(8),
                    _pad_cgo_0: [0; 4],
                    iov: read_u64(16),
                    iovlen: read_u64(24),
                    control: read_u64(32),
                    controllen: read_u64(40),
                    flags: read_i32(48),
                    _pad_cgo_1: [0; 4],
                };
                Some(msg.format())
            } else {
                None
            }
        }
        RUSAGE => {
            if data.len() >= SIZEOF_RUSAGE as usize {
                let ru = Rusage {
                    utime: Timeval { sec: read_i64(0), usec: read_i64(8) },
                    stime: Timeval { sec: read_i64(16), usec: read_i64(24) },
                    maxrss: read_i64(32),
                    ixrss: read_i64(40),
                    idrss: read_i64(48),
                    isrss: read_i64(56),
                    minflt: read_i64(64),
                    majflt: read_i64(72),
                    nswap: read_i64(80),
                    inblock: read_i64(88),
                    oublock: read_i64(96),
                    msgsnd: read_i64(104),
                    msgrcv: read_i64(112),
                    nsignals: read_i64(120),
                    nvcsw: read_i64(128),
                    nivcsw: read_i64(136),
                };
                Some(ru.format())
            } else {
                None
            }
        }
        STAT => {
            if data.len() >= SIZEOF_STAT_T as usize {
                let st = StatT {
                    dev: read_u64(0),
                    ino: read_u64(8),
                    nlink: read_u64(16),
                    mode: read_u32(24),
                    uid: read_u32(28),
                    gid: read_u32(32),
                    _pad0: read_i32(36),
                    rdev: read_u64(40),
                    size: read_i64(48),
                    blksize: read_i64(56),
                    blocks: read_i64(64),
                    atim: Timespec { sec: read_i64(72), nsec: read_i64(80) },
                    mtim: Timespec { sec: read_i64(88), nsec: read_i64(96) },
                    ctim: Timespec { sec: read_i64(104), nsec: read_i64(112) },
                    _unused: [0; 3],
                };
                Some(st.format())
            } else {
                None
            }
        }
        STATFS => {
            if data.len() >= SIZEOF_STATFS_T as usize {
                let sfs = StatfsT {
                    r#type: read_i64(0),
                    bsize: read_i64(8),
                    blocks: read_u64(16),
                    bfree: read_u64(24),
                    bavail: read_u64(32),
                    files: read_u64(40),
                    ffree: read_u64(48),
                    fsid: [read_i32(56), read_i32(60)],
                    namelen: read_i64(64),
                    frsize: read_i64(72),
                    flags: read_i64(80),
                    spare: [read_i64(88), read_i64(96), read_i64(104), read_i64(112)],
                };
                Some(sfs.format())
            } else {
                None
            }
        }
        EPOLLEVENT => {
            if data.len() >= SIZEOF_EPOLL_EVENT as usize {
                let ev = EpollEvent {
                    events: read_u32(0),
                    fd: read_i32(4),
                    pad: read_i32(8),
                };
                Some(ev.format())
            } else {
                None
            }
        }
        IOVEC => {
            if data.len() >= SIZEOF_IOVEC as usize {
                let iov = Iovec {
                    base: read_u64(0),
                    buflen: read_u64(8),
                };
                Some(iov.format())
            } else {
                None
            }
        }
        ITTMERSPEC => {
            if data.len() >= SIZEOF_ITTMERSPEC as usize {
                let its = ItTmerspec {
                    it_interval: Timespec { sec: read_i64(0), nsec: read_i64(8) },
                    it_value: Timespec { sec: read_i64(16), nsec: read_i64(24) },
                };
                Some(its.format())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Render a single arg value from the raw bytes based on its base_type.
///
/// This is the top-level dispatch that mirrors the Go `ARG_*.Parse()` methods.
/// Returns `(formatted_string, bytes_consumed)`.
pub fn render_arg_value(
    base_type: u32,
    type_index: u32,
    type_size: u32,
    format_type: u32,
    data: &[u8],
    dump_hex: bool,
) -> String {
    match base_type {
        TYPE_INT | TYPE_INT8 | TYPE_INT16 | TYPE_INT32 | TYPE_INT64 => {
            if data.len() >= 8 {
                let v = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                format_num(v, format_type, true, type_size)
            } else {
                "?".to_string()
            }
        }
        TYPE_UINT | TYPE_UINT8 | TYPE_UINT16 | TYPE_UINT32 | TYPE_UINT64 | TYPE_POINTER => {
            if data.len() >= 8 {
                let v = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                if base_type == TYPE_POINTER {
                    format_ptr(v)
                } else {
                    format_num(v, format_type, false, type_size)
                }
            } else {
                "?".to_string()
            }
        }
        TYPE_STRING => format_string(data),
        TYPE_BUFFER => {
            if dump_hex {
                format_buffer_hexdump(data, false)
            } else {
                format_buffer(data)
            }
        }
        TYPE_STRUCT => {
            // Try to render as a known struct type first
            if let Some(formatted) = render_struct_by_type_index(type_index, data) {
                formatted
            } else {
                // Unknown struct: fallback to hex dump
                format_buffer(data)
            }
        }
        _ => format_buffer(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_int_decimal() {
        assert_eq!(format_num(42, FORMAT_NUM, true, 4), "42");
        assert_eq!(format_num(42, FORMAT_DEC, false, 4), "42");
    }

    #[test]
    fn format_int_hex() {
        assert_eq!(format_num(0x2a, FORMAT_HEX, true, 4), "0x2a");
        assert_eq!(format_num(0x2a, FORMAT_HEX_PURE, false, 4), "2a");
    }

    #[test]
    fn format_int_oct_bin() {
        assert_eq!(format_num(42, FORMAT_OCT, false, 4), "0o052");
        assert_eq!(format_num(42, FORMAT_BIN, false, 4), "0b101010");
    }

    #[test]
    fn format_int_signed() {
        // -1 as i32 in two's complement = 0xFFFFFFFF
        assert_eq!(format_num(0xFFFFFFFF, FORMAT_NUM, true, 4), "-1");
        assert_eq!(format_num(0xFFFF, FORMAT_NUM, true, 2), "-1");
        assert_eq!(format_num(0xFF, FORMAT_NUM, true, 1), "-1");
    }

    #[test]
    fn format_ptr_value() {
        assert_eq!(format_ptr(0x7fff1234), "0x7fff1234");
    }

    #[test]
    fn format_buffer_basic() {
        assert_eq!(format_buffer(b"hello"), "(68656c6c6f)");
        assert_eq!(format_buffer(b""), "()");
    }

    #[test]
    fn format_string_basic() {
        assert_eq!(format_string(b"hello world\0\0"), "(hello world)");
        assert_eq!(format_string(b"test "), "(test)");
    }

    #[test]
    fn format_string16_basic() {
        // "hi" in UTF-16LE: h=0x6800, i=0x6900
        let data = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        assert_eq!(format_string16(&data), "(hi)");
    }

    #[test]
    fn trim_nul_basic() {
        assert_eq!(trim_nul(b"hello\0\0\0"), "hello");
        assert_eq!(trim_nul(b"test  "), "test");
        assert_eq!(trim_nul(b"\0\0"), "");
    }

    #[test]
    fn render_int_value() {
        let data = 42u64.to_le_bytes();
        assert_eq!(
            render_arg_value(TYPE_INT, 0, 4, FORMAT_NUM, &data, false),
            "42"
        );
    }

    #[test]
    fn render_uint_hex() {
        let data = 0xDEADu64.to_le_bytes();
        assert_eq!(
            render_arg_value(TYPE_UINT, 0, 4, FORMAT_HEX, &data, false),
            "0xdead"
        );
    }

    #[test]
    fn render_string_value() {
        let data = b"hello\0";
        assert_eq!(
            render_arg_value(TYPE_STRING, 0, 0, FORMAT_NUM, data, false),
            "(hello)"
        );
    }
}
