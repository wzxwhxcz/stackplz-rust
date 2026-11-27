//! Shared base-0 numeric parser, mirroring Go `strconv.ParseUint(s, 0, bits)`.
//!
//! Used wherever a config value can carry an integer literal: buf/array sizes,
//! read-op tokens, and filter values. The prefix picks the base (`0x`/`0X`
//! hex, `0b`/`0B` binary, `0o`/`0O`/`0` octal, else decimal); underscores are
//! accepted between digits, or right after the base prefix, like Go literals.

/// Go's underscore rule for integer literals: `_` may appear between digits,
/// or immediately after the base prefix, but never leading/trailing/
/// consecutive.
fn underscore_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(b[1], b'x' | b'X' | b'b' | b'B' | b'o' | b'O') {
        hex = matches!(b[1], b'x' | b'X');
        i = 2;
        saw = b'0';
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && c.is_ascii_hexdigit()) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            return false;
        }
        i += 1;
    }
    saw != b'_'
}

/// Parse `s` like Go `strconv.ParseUint(s, 0, 64)`. Errors are returned as
/// strings so each caller maps them onto its own error type.
pub fn parse_base0_u64(s: &str) -> Result<u64, String> {
    if !underscore_ok(s) {
        return Err(format!("invalid number literal: {s}"));
    }
    let cleaned: String = s.chars().filter(|&c| c != '_').collect();
    let parsed = if let Some(rest) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u64::from_str_radix(rest, 16)
    } else if let Some(rest) = cleaned
        .strip_prefix("0b")
        .or_else(|| cleaned.strip_prefix("0B"))
    {
        u64::from_str_radix(rest, 2)
    } else if let Some(rest) = cleaned
        .strip_prefix("0o")
        .or_else(|| cleaned.strip_prefix("0O"))
    {
        u64::from_str_radix(rest, 8)
    } else if cleaned.len() > 1 && cleaned.starts_with('0') {
        u64::from_str_radix(&cleaned[1..], 8)
    } else {
        cleaned.parse::<u64>()
    };
    parsed.map_err(|e| format!("invalid number literal: {s}: {e}"))
}
