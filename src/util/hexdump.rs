//! Hex-dump helpers and ANSI color constants. Mirrors the color constants and
//! `HexDump`/`PrettyByteSlice` in `pkg/util/helper.go:20-...`.

pub const COLOR_BLACK: &str = "\x1b[30m";
pub const COLOR_RED: &str = "\x1b[31m";
pub const COLOR_GREEN: &str = "\x1b[32m";
pub const COLOR_YELLOW: &str = "\x1b[33m";
pub const COLOR_BLUE: &str = "\x1b[34m";
pub const COLOR_PURPLE: &str = "\x1b[35m";
pub const COLOR_CYAN: &str = "\x1b[36m";
pub const COLOR_WHITE: &str = "\x1b[37m";
pub const COLOR_RESET: &str = "\x1b[0m";

/// Render a byte slice as a space-separated hex string with the given ANSI
/// color wrapping. Mirrors `HexDump(buffer, color)`.
pub fn hex_dump(buf: &[u8], color: &str) -> String {
    let mut s = String::with_capacity(buf.len() * 3);
    s.push_str(color);
    for (i, b) in buf.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s.push_str(COLOR_RESET);
    s
}

/// Render a byte slice as a pretty hex dump (offsets + ascii gutter).
/// Mirrors `PrettyByteSlice`.
pub fn pretty_byte_slice(buf: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in buf.iter().enumerate() {
        if i % 16 == 0 {
            if i != 0 {
                out.push('\n');
            }
            out.push_str(&format!("{:08x}  ", i));
        } else if i % 8 == 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:02x} ", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dump_basic() {
        let s = hex_dump(&[0x00, 0xff, 0x42], COLOR_RED);
        assert!(s.starts_with("\x1b[31m"));
        assert!(s.ends_with("\x1b[0m"));
        assert!(s.contains("00 ff 42"));
    }
}
