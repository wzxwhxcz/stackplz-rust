//! Argument value rendering — port of `user/argtype/argtype_base.go` (Parse methods)
//! and `user/argtype/config_struct.go` (Format/HexFormat methods).
//!
//! Each arg type knows how to render its value from the raw TLV bytes:
//! - Numbers: `42`, `0x2a`, `0b101010`, `0o52`
//! - Strings: `(hello world)`
//! - Buffers: `(68656c6c6f)` or hex dump
//! - Structs: `{sa_handler=0x1234, sa_flags=0x100}`

use crate::argtype::consts::*;

/// Format a number value according to the format_type.
/// Mirrors `ARG_INT::Parse` / `ARG_UINT::Parse` etc. in argtype_base.go.
pub fn format_num(value: u64, format_type: u32, is_signed: bool, byte_size: u32) -> String {
    // Mask to the effective byte size.
    let masked = mask_to_size(value, byte_size);
    let signed_val = if is_signed { sign_extend(masked, byte_size) as i64 } else { 0 };

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
            .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
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

/// Render a single arg value from the raw bytes based on its base_type.
///
/// This is the top-level dispatch that mirrors the Go `ARG_*.Parse()` methods.
/// Returns `(formatted_string, bytes_consumed)`.
pub fn render_arg_value(
    base_type: u32,
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
            // Generic struct: just hex dump.
            format_buffer(data)
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
            render_arg_value(TYPE_INT, 4, FORMAT_NUM, &data, false),
            "42"
        );
    }

    #[test]
    fn render_uint_hex() {
        let data = 0xDEADu64.to_le_bytes();
        assert_eq!(
            render_arg_value(TYPE_UINT, 4, FORMAT_HEX, &data, false),
            "0xdead"
        );
    }

    #[test]
    fn render_string_value() {
        let data = b"hello\0";
        assert_eq!(
            render_arg_value(TYPE_STRING, 0, FORMAT_NUM, data, false),
            "(hello)"
        );
    }
}
