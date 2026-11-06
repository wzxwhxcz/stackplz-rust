//! Value-formatting primitives shared by the userspace parse layer.
//!
//! Port of the formatting halves of `user/argtype/argtype_base.go`
//! (`ARG_*.Parse`) and `user/argtype/config_struct.go` (`Format`/`HexFormat`),
//! plus the `user/util/helper.go` text helpers they rely on. The TLV-driven
//! dispatch lives in [`super::parse`].
//!
//! Everything here is *output formatting only*: no argument payload is read.
//! The goal is byte-for-byte parity with upstream `dev`'s printed values, which
//! is why the per-type quirks are preserved (see [`format_num`]).

use super::consts::*;
use crate::util::hexdump::{hex_dump_pure, pretty_byte_slice};

/// `util.B2STrim` (`user/util/helper.go:261`): trim NUL bytes from both ends,
/// then whitespace from both ends.
pub fn b2s_trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches('\0')
        .trim()
        .to_string()
}

/// `utf16leToUtf8` (`user/argtype/config_struct.go:161`): decode UTF-16LE up to
/// (not including) the first NUL code unit.
pub fn utf16le_to_utf8(bytes: &[u8]) -> String {
    let mut u16s: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.as_chunks::<2>().0 {
        let v = u16::from_le_bytes(*chunk);
        if v == 0 {
            break;
        }
        u16s.push(v);
    }
    String::from_utf16_lossy(&u16s)
}

/// Format a buffer payload: `(<printable-with-\xNN-escapes>)`, or the hex dump
/// form `(\n<offset/hex/ascii dump>\n)` when `dump_hex` is set.
///
/// Mirrors `Arg_buffer.Format()` / `Arg_buffer.HexFormat()`.
pub fn format_buffer(payload: &[u8], dump_hex: bool) -> String {
    if dump_hex {
        if payload.is_empty() {
            // Upstream keeps the empty-buffer case as `()` even with --dumphex.
            "()".to_string()
        } else {
            format!("(\n{})", hex_dump_pure(payload))
        }
    } else {
        format!("({})", pretty_byte_slice(payload))
    }
}

/// `Ag_string.Format()` / `Arg_string16.Format()`: `(<trimmed text>)`.
pub fn format_string(payload: &[u8]) -> String {
    format!("({})", b2s_trim(payload))
}

/// `Arg_string16.Format()`: `(<utf16 decoded text>)`.
pub fn format_string16(payload: &[u8]) -> String {
    format!("({})", utf16le_to_utf8(payload))
}

/// `0x%x` pointer formatting, used by every pointer-ish argument type.
pub fn format_ptr(ptr: u64) -> String {
    format!("0x{ptr:x}")
}

/// Format a numeric argument value exactly like Go's `ARG_*.Parse`.
///
/// `ptr` is the raw register value; each concrete Go type casts it to its own
/// width first (`int32(ptr)`, `uint8(ptr)`, ...). Two upstream quirks are
/// reproduced on purpose:
///
/// - only `ARG_INT`/`ARG_UINT`/`ARG_UINT64` honour `format_type`; the sized
///   types (`ARG_INT8`..`ARG_INT64`, `ARG_UINT8`..`ARG_UINT32`) always print
///   decimal unless a flags config is attached, and the Rust port has no flags
///   configs (`user/argtype/argtype_flags.go`) — so they stay decimal.
/// - `%x`/`%o`/`%b` on a *signed* Go value keeps its sign (`-2a`, `-52`, `-101010`)
///   instead of printing two's complement.
pub fn format_num(base_type: u32, format_type: u32, ptr: u64) -> String {
    match base_type {
        TYPE_INT => signed_with_format(i64::from(ptr as u32 as i32), format_type),
        TYPE_UINT => unsigned_with_format(u64::from(ptr as u32), format_type),
        TYPE_INT8 => i64::from(ptr as u8 as i8).to_string(),
        TYPE_INT16 => i64::from(ptr as u16 as i16).to_string(),
        TYPE_INT32 => i64::from(ptr as u32 as i32).to_string(),
        TYPE_INT64 => (ptr as i64).to_string(),
        TYPE_UINT8 => u64::from(ptr as u8).to_string(),
        TYPE_UINT16 => u64::from(ptr as u16).to_string(),
        TYPE_UINT32 => u64::from(ptr as u32).to_string(),
        TYPE_UINT64 => unsigned_with_format(ptr, format_type),
        _ => unsigned_with_format(ptr, format_type),
    }
}

fn signed_with_format(v: i64, format_type: u32) -> String {
    match format_type {
        FORMAT_HEX_PURE => signed_radix(v, 16),
        FORMAT_HEX => format!("0x{}", signed_radix(v, 16)),
        FORMAT_OCT => format!("0o{}", pad3(&signed_radix(v, 8))),
        FORMAT_BIN => format!("0b{}", signed_radix(v, 2)),
        // FORMAT_NUM | FORMAT_DEC | anything else
        _ => v.to_string(),
    }
}

fn unsigned_with_format(v: u64, format_type: u32) -> String {
    match format_type {
        FORMAT_HEX_PURE => format!("{v:x}"),
        FORMAT_HEX => format!("0x{v:x}"),
        FORMAT_OCT => format!("0o{}", pad3(&format!("{v:o}"))),
        FORMAT_BIN => format!("0b{v:b}"),
        // FORMAT_NUM | FORMAT_DEC | anything else
        _ => v.to_string(),
    }
}

/// Go's `strconv.FormatInt(v, radix)`: a leading `-` for negative values.
fn signed_radix(v: i64, radix: u32) -> String {
    if v < 0 {
        format!("-{}", format_radix(v.unsigned_abs(), radix))
    } else {
        format_radix(v as u64, radix)
    }
}

fn format_radix(v: u64, radix: u32) -> String {
    match radix {
        16 => format!("{v:x}"),
        8 => format!("{v:o}"),
        2 => format!("{v:b}"),
        _ => v.to_string(),
    }
}

/// Go's `%03s` zero-pads short strings (`"5"` -> `"005"`, `"-1"` -> `"0-1"`).
fn pad3(s: &str) -> String {
    format!("{s:0>3}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b2s_trim_trims_nuls_and_whitespace() {
        assert_eq!(b2s_trim(b"hello\x00\x00"), "hello");
        assert_eq!(b2s_trim(b"  hi  "), "hi");
        assert_eq!(b2s_trim(b"\x00\x00"), "");
        assert_eq!(b2s_trim(b"a\tb"), "a\tb");
    }

    #[test]
    fn utf16le_roundtrip_stops_at_nul() {
        let data = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        assert_eq!(utf16le_to_utf8(&data), "hi");
        assert_eq!(utf16le_to_utf8(&[0x00]), "");
    }

    /// Go's numeric `Parse` output for every concrete type/format we ship.
    #[test]
    fn format_num_matches_go_semantics() {
        // ARG_INT: int32(ptr), honours the format.
        assert_eq!(format_num(TYPE_INT, FORMAT_NUM, 42), "42");
        assert_eq!(format_num(TYPE_INT, FORMAT_DEC, 42), "42");
        assert_eq!(format_num(TYPE_INT, FORMAT_HEX, 0x2a), "0x2a");
        assert_eq!(format_num(TYPE_INT, FORMAT_HEX_PURE, 0x2a), "2a");
        assert_eq!(format_num(TYPE_INT, FORMAT_OCT, 42), "0o052");
        assert_eq!(format_num(TYPE_INT, FORMAT_BIN, 42), "0b101010");
        // Negative signed values keep the sign in Go's %x/%o/%b.
        assert_eq!(
            format_num(TYPE_INT, FORMAT_NUM, u64::from(0xffff_ffffu32)),
            "-1"
        );
        assert_eq!(
            format_num(TYPE_INT, FORMAT_HEX, u64::from(0xffff_ffd6u32)),
            "0x-2a"
        );
        assert_eq!(
            format_num(TYPE_INT, FORMAT_OCT, u64::from(0xffff_ffd6u32)),
            "0o-52"
        );

        // ARG_UINT: uint32(ptr), honours the format.
        assert_eq!(format_num(TYPE_UINT, FORMAT_HEX, 0xdead), "0xdead");
        assert_eq!(
            format_num(TYPE_UINT, FORMAT_NUM, u64::from(u32::MAX)),
            "4294967295"
        );

        // ARG_UINT64 honours the format too.
        assert_eq!(
            format_num(TYPE_UINT64, FORMAT_HEX, 0x1_0000_0000),
            "0x100000000"
        );

        // Sized types ignore the format (no flags config in this port).
        assert_eq!(format_num(TYPE_INT8, FORMAT_HEX, 0xff), "-1");
        assert_eq!(format_num(TYPE_INT16, FORMAT_HEX, 0xffff), "-1");
        assert_eq!(format_num(TYPE_UINT8, FORMAT_HEX, 0xff), "255");
        assert_eq!(format_num(TYPE_UINT16, FORMAT_HEX, 0xffff), "65535");
        assert_eq!(format_num(TYPE_UINT32, FORMAT_HEX, 0xdead), "57005");
    }

    #[test]
    fn buffer_formatting_matches_go() {
        // Arg_buffer.Format: printable bytes kept, others \xNN.
        assert_eq!(format_buffer(b"hello", false), "(hello)");
        assert_eq!(format_buffer(b"a\x00b", false), "(a\\x00b)");
        assert_eq!(format_buffer(b"", false), "()");
        // Arg_buffer.HexFormat: offset/hex/ascii dump inside parens.
        assert_eq!(
            format_buffer(b"hello", true),
            "(\n0000  68 65 6C 6C 6F                                   |hello           |\n)"
        );
        assert_eq!(format_buffer(b"", true), "()");
    }

    #[test]
    fn string_formatting_matches_go() {
        assert_eq!(format_string(b"hello world\0\0"), "(hello world)");
        assert_eq!(format_string(b"test "), "(test)");
        let data = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        assert_eq!(format_string16(&data), "(hi)");
    }
}
