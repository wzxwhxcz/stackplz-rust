//! Argument filter parser and helper
//!
//! This module implements the filter parsing logic from config_filter.go,
//! supporting various filter types: equal, greater, less, whitelist, blacklist, etc.

use crate::config::base0::parse_base0_u64;
use crate::contract::MAX_STRCMP_LEN;
use std::net::Ipv4Addr;
use std::str::FromStr;

// Filter type constants (matching Go's IOTA enum)
pub const UNKNOWN_FILTER: u32 = 0;
pub const EQUAL_FILTER: u32 = 1;
pub const GREATER_FILTER: u32 = 2;
pub const LESS_FILTER: u32 = 3;
pub const WHITELIST_FILTER: u32 = 4;
pub const BLACKLIST_FILTER: u32 = 5;
pub const REPLACE_FILTER: u32 = 6;

/// Argument filter configuration
#[derive(Clone, Debug)]
pub struct ArgFilter {
    /// Original filter string (e.g., "eq:0x100")
    pub filter_str: String,
    /// Filter type (EQUAL_FILTER, WHITELIST_FILTER, etc.)
    pub filter_type: u32,
    /// Filter index (1-based, 0 means unassigned)
    pub filter_index: u32,
    /// Numeric value for numeric filters
    pub num_val: u64,
    /// String value for string filters
    pub str_val: [u8; 256],
    /// String length
    pub str_len: u32,
}

impl ArgFilter {
    /// Check if this filter matches the given name (e.g., "f0", "f1")
    pub fn matches(&self, name: &str) -> bool {
        if self.filter_index == 0 {
            return false;
        }
        name == format!("f{}", self.filter_index - 1)
    }

    /// Check if this is a string-based filter
    pub fn is_str(&self) -> bool {
        self.filter_type == WHITELIST_FILTER || self.filter_type == BLACKLIST_FILTER
    }

    /// Convert to eBPF filter format
    pub fn to_ebpf_value(&self) -> EArgFilter {
        let mut str_val = [0u8; MAX_STRCMP_LEN];
        str_val[..MAX_STRCMP_LEN.min(256)]
            .copy_from_slice(&self.str_val[..MAX_STRCMP_LEN.min(256)]);

        EArgFilter {
            filter_type: self.filter_type,
            str_val,
            str_len: self.str_len,
            num_val: self.num_val,
        }
    }
}

/// eBPF-compatible filter structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EArgFilter {
    pub filter_type: u32,
    pub str_val: [u8; MAX_STRCMP_LEN],
    pub str_len: u32,
    pub num_val: u64,
}

/// Filter helper for managing filters
pub struct FilterHelper {
    filters: Vec<ArgFilter>,
}

impl Default for FilterHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterHelper {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Get all filters
    pub fn get_filters(&self) -> &[ArgFilter] {
        &self.filters
    }

    /// Get filter by name (e.g., "f0", "f1")
    pub fn get_filter_by_name(&self, filter_name: &str) -> Option<&ArgFilter> {
        self.filters.iter().find(|f| f.matches(filter_name))
    }

    /// Get filter index by filter name (e.g., `"f0"`), like Go's
    /// `GetFilterIndex` (`config_filter.go:178-180`), which looks the filter
    /// up by name via `GetFilterByName` — not by its filter string (H20).
    pub fn get_filter_index(&self, filter_name: &str) -> Option<u32> {
        self.filters
            .iter()
            .find(|f| f.matches(filter_name))
            .map(|f| f.filter_index)
    }

    /// Add a filter and return its index
    ///
    /// Filter format: "type:value"
    /// Supported types:
    /// - addr:IP        - IPv4 address filter
    /// - bx:HEX         - Hex buffer filter
    /// - bufhex:HEX     - Alias for bx
    /// - eq:NUM         - Equal filter
    /// - equal:NUM      - Alias for eq
    /// - gt:NUM         - Greater than filter
    /// - greater:NUM    - Alias for gt
    /// - lt:NUM         - Less than filter
    /// - less:NUM       - Alias for lt
    /// - w:STR          - Whitelist string filter
    /// - white:STR      - Alias for w
    /// - b:STR          - Blacklist string filter
    /// - black:STR      - Alias for b
    pub fn add_filter(&mut self, filter: &str) -> Result<u32, String> {
        // Check if filter already exists
        if let Some(existing) = self.filters.iter().find(|f| f.filter_str == filter) {
            return Ok(existing.filter_index);
        }

        // Parse filter string
        let parts: Vec<&str> = filter.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!(
                "AddFilter failed, invalid filter format: {}",
                filter
            ));
        }

        let filter_type_str = parts[0];
        let value_str = parts[1];

        let mut arg_filter = ArgFilter {
            filter_str: filter.to_string(),
            filter_type: UNKNOWN_FILTER,
            filter_index: 0,
            num_val: 0,
            str_val: [0u8; 256],
            str_len: 0,
        };

        match filter_type_str {
            "addr" => {
                // IPv4 address filter
                arg_filter.filter_type = WHITELIST_FILTER;
                let ipv4 = Ipv4Addr::from_str(value_str)
                    .map_err(|e| format!("Failed to parse IPv4 address: {}", e))?;
                let octets = ipv4.octets();

                // Convert to big-endian u32, then to the LE-shifted form Go
                // computes (`config_filter.go:115-119`: BE-put the u32 into 8
                // bytes, LE-read it back, shift right by `Str_len` — the same
                // shape as the bx branch below).
                let big_endian_u32 = u32::from_be_bytes(octets);
                // H19: Go's `Str_len = (8 - len(ipv4_addr)) * 8`; a full IPv4
                // address is 4 bytes, so this is 32, not 0 — the eBPF mask
                // comparison (`ebpf/utils.h:216`) only compares the low 32
                // bits of the 8-byte read. (The old `0` plus the comment "No
                // shift for full IP" were both wrong.)
                arg_filter.str_len = (8 - 4) * 8;
                let be_u64 = (big_endian_u32 as u64).to_be_bytes();
                arg_filter.num_val = u64::from_le_bytes(be_u64) >> arg_filter.str_len;
            }
            "bx" | "bufhex" => {
                // Hex buffer filter. The input is always hex (H17): strip one
                // optional "0x" prefix first, then parse as hex. Go
                // (`config_filter.go:128`) prepends "0x" before base-0
                // parsing, so a bare `deadbeef` means 0xdeadbeef; accepting a
                // redundant `0x` prefix here is a convenience beyond Go (Go's
                // `hex.DecodeString("0x…")` rejects it), kept so
                // `bx:0xdeadbeef` works like `bx:deadbeef`. Do NOT route this
                // through the shared base-0 parser: bx input is hex-only, so
                // `0b`/`0o` must not leak in here (H16 stays separate).
                let hex_str = value_str
                    .strip_prefix("0x")
                    .or_else(|| value_str.strip_prefix("0X"))
                    .unwrap_or(value_str);
                arg_filter.filter_type = WHITELIST_FILTER;
                let hex_bytes = hex::decode(hex_str)
                    .map_err(|e| format!("Failed to decode hex string: {}", e))?;

                if hex_bytes.len() > 8 {
                    return Err("Hex string is too long, max bytes length is 8".to_string());
                }

                arg_filter.str_len = ((8 - hex_bytes.len()) * 8) as u32;
                arg_filter.num_val = u64::from_str_radix(hex_str, 16)
                    .map_err(|e| format!("Failed to parse hex number: {}", e))?;

                // Convert big-endian to little-endian with shift
                let be_u64 = arg_filter.num_val.to_be_bytes();
                arg_filter.num_val = u64::from_le_bytes(be_u64) >> arg_filter.str_len;
            }
            "eq" | "equal" => {
                arg_filter.filter_type = EQUAL_FILTER;
                arg_filter.num_val = parse_num(value_str)?;
            }
            "gt" | "greater" => {
                arg_filter.filter_type = GREATER_FILTER;
                arg_filter.num_val = parse_num(value_str)?;
            }
            "lt" | "less" => {
                arg_filter.filter_type = LESS_FILTER;
                arg_filter.num_val = parse_num(value_str)?;
            }
            "w" | "white" => {
                arg_filter.filter_type = WHITELIST_FILTER;
                let bytes = value_str.as_bytes();
                if bytes.len() > 256 {
                    return Err("String is too long, max length is 256".to_string());
                }
                arg_filter.str_len = bytes.len() as u32;
                arg_filter.str_val[..bytes.len()].copy_from_slice(bytes);
            }
            "b" | "black" => {
                arg_filter.filter_type = BLACKLIST_FILTER;
                let bytes = value_str.as_bytes();
                if bytes.len() > 256 {
                    return Err("String is too long, max length is 256".to_string());
                }
                arg_filter.str_len = bytes.len() as u32;
                arg_filter.str_val[..bytes.len()].copy_from_slice(bytes);
            }
            _ => {
                return Err(format!(
                    "AddFilter failed, unknown filter type: {}",
                    filter_type_str
                ));
            }
        }

        // Assign filter index (1-based)
        arg_filter.filter_index = (self.filters.len() + 1) as u32;
        let filter_index = arg_filter.filter_index;
        self.filters.push(arg_filter);

        Ok(filter_index)
    }
}

/// Parse a numeric string like Go `strconv.ParseUint(s, 0, 64)` (H16): the
/// shared base-0 parser accepts `0x` hex, `0b` binary, `0o`/leading-`0`
/// octal, decimal, and Go-style underscores.
fn parse_num(s: &str) -> Result<u64, String> {
    parse_base0_u64(s).map_err(|e| format!("Failed to parse number: {e}"))
}

// Global filter helper instance
use once_cell::sync::Lazy;
use std::sync::Mutex;

static FILTER_HELPER: Lazy<Mutex<FilterHelper>> = Lazy::new(|| Mutex::new(FilterHelper::new()));

/// Lock the global filter helper. A poisoned lock means an accessor panicked
/// while holding it; recover the guard instead of unwrap-panicking (err-no-
/// unwrap-prod). (H18: the old code said this but called `.expect()`, which
/// panics on a poisoned lock — the opposite of what the comment promised.)
fn filter_helper() -> std::sync::MutexGuard<'static, FilterHelper> {
    FILTER_HELPER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Get filter index by filter name (e.g., `"f0"`), like Go's `GetFilterIndex`
/// (H20). Passing a filter string such as `"eq:100"` returns `None`.
pub fn get_filter_index(filter_name: &str) -> Option<u32> {
    filter_helper().get_filter_index(filter_name)
}

/// Add filter (global API)
pub fn add_filter(filter: &str) -> Result<u32, String> {
    filter_helper().add_filter(filter)
}

/// Get all filters (global API)
pub fn get_filters() -> Vec<ArgFilter> {
    filter_helper().get_filters().to_vec()
}

/// Get filter by name (global API)
pub fn get_filter_by_name(name: &str) -> Option<ArgFilter> {
    filter_helper().get_filter_by_name(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_filter() {
        let mut helper = FilterHelper::new();
        let idx = helper.add_filter("eq:100").unwrap();
        assert_eq!(idx, 1);

        let filter = &helper.get_filters()[0];
        assert_eq!(filter.filter_type, EQUAL_FILTER);
        assert_eq!(filter.num_val, 100);
    }

    #[test]
    fn test_hex_filter() {
        let mut helper = FilterHelper::new();
        let idx = helper.add_filter("eq:0x100").unwrap();
        assert_eq!(idx, 1);

        let filter = &helper.get_filters()[0];
        assert_eq!(filter.filter_type, EQUAL_FILTER);
        assert_eq!(filter.num_val, 256);
    }

    #[test]
    fn test_string_whitelist() {
        let mut helper = FilterHelper::new();
        let idx = helper.add_filter("w:hello").unwrap();
        assert_eq!(idx, 1);

        let filter = &helper.get_filters()[0];
        assert_eq!(filter.filter_type, WHITELIST_FILTER);
        assert_eq!(filter.str_len, 5);
        assert_eq!(&filter.str_val[..5], b"hello");
    }

    #[test]
    fn test_filter_match() {
        let mut helper = FilterHelper::new();
        helper.add_filter("eq:100").unwrap();

        let filter = &helper.get_filters()[0];
        assert!(filter.matches("f0"));
        assert!(!filter.matches("f1"));
    }

    /// Roundtrip through all four global accessors (each goes through
    /// `filter_helper`, covering the recover paths). Index values depend on what
    /// other tests registered concurrently in the global helper, so assert
    /// consistency, not an absolute index. H20: `get_filter_index` looks up
    /// by name (`"f0"`), like Go's `GetFilterIndex` — a filter string such as
    /// `"eq:1"` is not a name and returns `None`.
    #[test]
    fn global_filter_api_roundtrip() {
        assert_eq!(get_filter_index("eq:1"), None);
        let idx = add_filter("eq:1").expect("add_filter succeeds");
        assert!(idx >= 1);
        assert_eq!(get_filter_index("eq:1"), None);
        let name = format!("f{}", idx - 1);
        assert_eq!(get_filter_index(&name), Some(idx));
        assert!(!get_filters().is_empty());
        let f = get_filter_by_name(&name).expect("filter found by name");
        assert_eq!(f.filter_str, "eq:1");
    }

    /// H16: `eq`/`gt`/`lt` accept Go base-0 literals — `0b`/`0o`/underscores
    /// and leading-`0` octal — via the shared `parse_base0_u64`; `"08"` is
    /// still rejected (illegal octal under Go base-0, same as H13).
    #[test]
    fn numeric_filters_accept_base0_literals() {
        let mut helper = FilterHelper::new();
        helper.add_filter("eq:0b101").unwrap();
        assert_eq!(helper.get_filters()[0].num_val, 5);
        helper.add_filter("eq:0o17").unwrap();
        assert_eq!(helper.get_filters()[1].num_val, 15);
        helper.add_filter("eq:1_000").unwrap();
        assert_eq!(helper.get_filters()[2].num_val, 1000);
        helper.add_filter("eq:010").unwrap();
        assert_eq!(helper.get_filters()[3].num_val, 8);
        assert!(helper.add_filter("eq:08").is_err());
    }

    /// H17 + H19: bx and addr share the eBPF mask comparison
    /// (`ebpf/utils.h:216`), so both are checked here against Go's numbers:
    /// `bx:deadbeef` → `0xefbeadde` with `str_len` 32, `addr:1.2.3.4` →
    /// `0x04030201` with `str_len` 32. The two fixes do not overlap (bx had
    /// the right mask but the wrong value source; addr had the right value
    /// but the wrong mask).
    #[test]
    fn bx_filter_matches_go_hex_values() {
        let mut helper = FilterHelper::new();
        helper.add_filter("bx:deadbeef").unwrap();
        let f = &helper.get_filters()[0];
        assert_eq!(f.num_val, 0xefbeadde);
        assert_eq!(f.str_len, 32);

        // A redundant "0x" prefix parses to the same value.
        helper.add_filter("bx:0xdeadbeef").unwrap();
        let f = &helper.get_filters()[1];
        assert_eq!(f.num_val, 0xefbeadde);
        assert_eq!(f.str_len, 32);

        helper.add_filter("bx:1234").unwrap();
        let f = &helper.get_filters()[2];
        assert_eq!(f.num_val, 0x3412);
        assert_eq!(f.str_len, 48);

        helper.add_filter("bx:00ff").unwrap();
        let f = &helper.get_filters()[3];
        assert_eq!(f.num_val, 0xff00);
        assert_eq!(f.str_len, 48);

        helper.add_filter("bx:ff").unwrap();
        let f = &helper.get_filters()[4];
        assert_eq!(f.num_val, 0xff);
        assert_eq!(f.str_len, 56);

        helper.add_filter("bx:00").unwrap();
        assert_eq!(helper.get_filters()[5].num_val, 0x00);

        assert!(helper.add_filter("bx:zz").is_err());
    }

    /// H19: `addr:1.2.3.4` keeps `num_val == 0x04030201` but now carries
    /// `str_len == 32`, so the eBPF mask only compares the low 32 bits (an
    /// IP followed by nonzero bytes still matches, like Go).
    #[test]
    fn addr_filter_uses_go_str_len_32() {
        let mut helper = FilterHelper::new();
        helper.add_filter("addr:1.2.3.4").unwrap();
        let f = &helper.get_filters()[0];
        assert_eq!(f.str_len, 32);
        assert_eq!(f.num_val, 0x04030201);
    }

    /// H18: poisoning the global lock (an accessor panicking while holding
    /// it) must not make later accessors panic — `filter_helper()` recovers
    /// the guard, as its comment promises.
    #[test]
    fn poisoned_filter_helper_lock_recovers() {
        let t = std::thread::spawn(|| {
            let _guard = FILTER_HELPER.lock().unwrap();
            panic!("boom while holding the filter lock");
        });
        assert!(t.join().is_err());
        // Accessors must recover the guard, not panic on the poisoned lock.
        let _ = get_filters();
        assert!(add_filter("eq:4242").is_ok());
    }
}
