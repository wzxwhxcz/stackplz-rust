//! `--reg` offset resolution. Mirrors `util.ParseReg` (`helper.go:185-214`).
//!
//! Reads `/proc/{pid}/maps`, finds the segment containing the given register
//! value, and returns `"<path> + 0x<offset>"` where
//! `offset = seg_file_offset + (value - seg_start)`.

use anyhow::{anyhow, Result};

/// One parsed maps line.
#[derive(Debug, Clone)]
struct MapSegment {
    start: u64,
    end: u64,
    offset: u64,
    path: String,
}

/// Parse `/proc/{pid}/maps` and resolve `value` to `"<path> + 0x<offset>"`.
///
/// Equivalent to Go's `fmt.Fscanf(reader, "%x-%x %s %x %s %d %s", ...)`.
pub fn parse_reg(pid: u32, value: u64) -> Result<String> {
    let content = super::read_maps_by_pid(pid)?;
    for line in content.lines() {
        if let Some(seg) = parse_maps_line(line) {
            if value >= seg.start && value < seg.end {
                let off = seg.offset + (value - seg.start);
                return Ok(format!("{} + 0x{:x}", seg.path, off));
            }
        }
    }
    Err(anyhow!(
        "can not find segment for value 0x{:x} in /proc/{}/maps",
        value,
        pid
    ))
}

/// Parse a single `/proc/pid/maps` line.
///
/// Format: `start-end perm offset dev inode   path`
/// e.g.   `7e8a000000-7e8a010000 r-xp 00000000 fe:00 1234  /apex/.../libc.so`
fn parse_maps_line(line: &str) -> Option<MapSegment> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // Split into address-range + perms + offset + dev + inode + path (6 tokens,
    // path may contain spaces).
    let mut parts = line.splitn(6, ' ').filter(|s| !s.is_empty());
    let range = parts.next()?;
    let _perms = parts.next()?;
    let offset = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.next()?.trim().to_string();
    if path.is_empty() {
        return None;
    }
    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s.trim(), 16).ok()?;
    let end = u64::from_str_radix(end_s.trim(), 16).ok()?;
    let offset = u64::from_str_radix(offset.trim(), 16).ok()?;
    Some(MapSegment { start, end, offset, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_maps_line() {
        let seg = parse_maps_line(
            "7e8a000000-7e8a010000 r-xp 00000000 fe:00 1234  /apex/.../libc.so",
        )
        .unwrap();
        assert_eq!(seg.start, 0x7e8a000000);
        assert_eq!(seg.end, 0x7e8a010000);
        assert_eq!(seg.offset, 0);
        assert_eq!(seg.path, "/apex/.../libc.so");
    }

    #[test]
    fn parse_maps_line_with_offset() {
        let seg = parse_maps_line(
            "7e8a010000-7e8a020000 r--p 00010000 fe:00 1234  /data/app/libfoo.so",
        )
        .unwrap();
        assert_eq!(seg.offset, 0x00010000);
    }

    #[test]
    fn parse_maps_line_garbage_returns_none() {
        assert!(parse_maps_line("garbage line").is_none());
        assert!(parse_maps_line("").is_none());
    }

    #[test]
    fn resolve_offset_within_segment() {
        // Build the offset math directly: value = start + 0x1234, offset=0x1000.
        let seg = MapSegment {
            start: 0x1000,
            end: 0x2000,
            offset: 0x1000,
            path: "/lib.so".into(),
        };
        let value = 0x1234u64;
        let off = seg.offset + (value - seg.start);
        assert_eq!(off, 0x1234);
    }
}
