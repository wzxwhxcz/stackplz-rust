//! Argument filter parser and helper
//! 
//! This module implements the filter parsing logic from config_filter.go,
//! supporting various filter types: equal, greater, less, whitelist, blacklist, etc.

use std::net::Ipv4Addr;
use std::str::FromStr;
use crate::contract::MAX_STRCMP_LEN;

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
        str_val[..MAX_STRCMP_LEN.min(256)].copy_from_slice(&self.str_val[..MAX_STRCMP_LEN.min(256)]);
        
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

    /// Get filter index by filter string
    pub fn get_filter_index(&self, filter: &str) -> Option<u32> {
        self.filters.iter()
            .find(|f| f.filter_str == filter)
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
            return Err(format!("AddFilter failed, invalid filter format: {}", filter));
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
                
                // Convert to big-endian u32, then swap to little-endian with shift
                let big_endian_u32 = u32::from_be_bytes(octets);
                arg_filter.str_len = 0; // No shift for full IP
                arg_filter.num_val = big_endian_u32 as u64;
                
                // Convert big-endian to little-endian representation
                let be_bytes = big_endian_u32.to_be_bytes();
                let le_u64 = u64::from_le_bytes([be_bytes[0], be_bytes[1], be_bytes[2], be_bytes[3], 0, 0, 0, 0]);
                arg_filter.num_val = le_u64 >> arg_filter.str_len;
            }
            "bx" | "bufhex" => {
                // Hex buffer filter
                arg_filter.filter_type = WHITELIST_FILTER;
                let hex_bytes = hex::decode(value_str)
                    .map_err(|e| format!("Failed to decode hex string: {}", e))?;
                
                if hex_bytes.len() > 8 {
                    return Err("Hex string is too long, max bytes length is 8".to_string());
                }
                
                arg_filter.str_len = ((8 - hex_bytes.len()) * 8) as u32;
                arg_filter.num_val = parse_num(value_str)?;
                
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
                return Err(format!("AddFilter failed, unknown filter type: {}", filter_type_str));
            }
        }

        // Assign filter index (1-based)
        arg_filter.filter_index = (self.filters.len() + 1) as u32;
        let filter_index = arg_filter.filter_index;
        self.filters.push(arg_filter);
        
        Ok(filter_index)
    }
}

/// Parse numeric string (supports decimal, hex with 0x prefix, octal with 0 prefix)
fn parse_num(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|e| format!("Failed to parse hex number: {}", e))
    } else if s.starts_with("0") && s.len() > 1 {
        u64::from_str_radix(&s[1..], 8)
            .map_err(|e| format!("Failed to parse octal number: {}", e))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("Failed to parse decimal number: {}", e))
    }
}

// Global filter helper instance
use std::sync::Mutex;
use once_cell::sync::Lazy;

static FILTER_HELPER: Lazy<Mutex<FilterHelper>> = Lazy::new(|| {
    Mutex::new(FilterHelper::new())
});

/// Get filter index by filter string (global API)
pub fn get_filter_index(filter: &str) -> Option<u32> {
    FILTER_HELPER.lock().unwrap().get_filter_index(filter)
}

/// Add filter (global API)
pub fn add_filter(filter: &str) -> Result<u32, String> {
    FILTER_HELPER.lock().unwrap().add_filter(filter)
}

/// Get all filters (global API)
pub fn get_filters() -> Vec<ArgFilter> {
    FILTER_HELPER.lock().unwrap().get_filters().to_vec()
}

/// Get filter by name (global API)
pub fn get_filter_by_name(name: &str) -> Option<ArgFilter> {
    FILTER_HELPER.lock().unwrap().get_filter_by_name(name).cloned()
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
}
