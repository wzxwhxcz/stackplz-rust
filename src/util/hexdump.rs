//! Hex-dump helpers and ANSI color constants. Mirrors the color constants and
//! `HexDump` (`helper.go:424`) / `HexDumpPure` (`:430`) / `PrettyByteSlice`
//! (`:387`) / `dumpByteSlice` (`:336-377`) in `user/util/helper.go` (dev).

pub const COLOR_BLACK: &str = "\x1b[30m";
pub const COLOR_RED: &str = "\x1b[31m";
pub const COLOR_GREEN: &str = "\x1b[32m";
pub const COLOR_YELLOW: &str = "\x1b[33m";
pub const COLOR_BLUE: &str = "\x1b[34m";
pub const COLOR_PURPLE: &str = "\x1b[35m";
pub const COLOR_CYAN: &str = "\x1b[36m";
pub const COLOR_WHITE: &str = "\x1b[37m";
pub const COLOR_RESET: &str = "\x1b[0m";

/// Bytes per line in [`hex_dump`] (Go `util.CHUNK_SIZE`, `helper.go:322`).
const CHUNK_SIZE: usize = 16;

/// Render a byte slice as the classic offset/hex/ascii dump.
/// Mirrors `dumpByteSlice` (`helper.go:336-377`), i.e. the body of
/// `HexDumpPure(buf, "")` / `HexDumpGreen(buf)`.
///
/// Layout per line: `%04x ` offset, then ` %02X` per byte (three spaces for the
/// padding bytes of a partial last line), then `  |ascii|` + newline. The
/// returned string always ends with a newline (every line is terminated).
pub fn hex_dump_pure(buf: &[u8]) -> String {
    let mut out = String::new();
    let mut ascii = [b' '; CHUNK_SIZE];
    let n = buf.len().div_ceil(CHUNK_SIZE) * CHUNK_SIZE;
    for i in 0..n {
        if i % CHUNK_SIZE == 0 {
            out.push_str(&format!("{i:04x} "));
        }
        if i < buf.len() {
            let b = buf[i];
            out.push_str(&format!(" {b:02X}"));
            ascii[i % CHUNK_SIZE] = if (32..=126).contains(&b) { b } else { b'.' };
        } else {
            out.push_str("   ");
            ascii[i % CHUNK_SIZE] = b' ';
        }
        if i % CHUNK_SIZE == CHUNK_SIZE - 1 {
            out.push_str(&format!(
                "  |{}|\n",
                String::from_utf8_lossy(&ascii[..]).into_owned()
            ));
        }
    }
    out
}

/// Render a byte slice with each byte: printable ASCII kept verbatim, everything
/// else escaped as lowercase `\xNN`. Mirrors `util.PrettyByteSlice`
/// (`helper.go:387-397`).
pub fn pretty_byte_slice(buf: &[u8]) -> String {
    let mut out = String::with_capacity(buf.len());
    for &b in buf {
        if (32..=126).contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_byte_slice_escapes_non_printables() {
        assert_eq!(pretty_byte_slice(b"hello"), "hello");
        assert_eq!(pretty_byte_slice(b"a\x00\x01Z"), "a\\x00\\x01Z");
        assert_eq!(pretty_byte_slice(b""), "");
        // 0x7f (DEL) is outside 32..=126 and is escaped.
        assert_eq!(pretty_byte_slice(b"\x7f"), "\\x7f");
    }

    #[test]
    fn hex_dump_pure_matches_go_layout() {
        // One full line: offset, 16 uppercase byte cells, ascii gutter.
        let line = hex_dump_pure(b"0123456789abcdef");
        assert_eq!(
            line,
            "0000  30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66  |0123456789abcdef|\n"
        );

        // Partial line is padded with three spaces per missing byte.
        let line = hex_dump_pure(b"hi");
        assert_eq!(
            line,
            "0000  68 69                                            |hi              |\n"
        );

        assert_eq!(hex_dump_pure(b""), "");
    }
}
