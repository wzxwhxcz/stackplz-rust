//! JSON hook-config DTOs for the `stack --config` file.
//! Master-era DTOs (`BaseHookConfig`, `LibHookConfig`, `HookConfig` in
//! `origin/master:cli/cmd/stack.go:28-44`; `parseConfig` at `stack.go:199-307`).
//! Dev has no such file: hook JSON there is parsed by `config_file.go` +
//! `GlobalConfig.Parse_Libinfo` (`config_global.go:160`).
//!
//! Schema (matches the shipped `config.json`):
//! ```jsonc
//! {
//!   "library_dirs": ["/apex/com.android.runtime/lib64"],
//!   "libs": [
//!     {
//!       "library": "bionic/libc.so",
//!       "disable": false,
//!       "configs": [
//!         { "symbols": ["open"], "offsets": [] },
//!         { "symbols": ["read"], "offsets": ["0xF37C"] }
//!       ]
//!     }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Symbols and offsets for one hook point. Unknown fields are rejected so an
/// old config carrying `"regs"`/`"stack"` fails loudly instead of being
/// silently ignored (master-era `BaseHookConfig` at
/// `origin/master:cli/cmd/stack.go:28-33` had those switches, but nothing in
/// this crate reads them).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseHookConfig {
    #[serde(default)]
    pub symbols: Vec<String>,
    #[serde(default)]
    pub offsets: Vec<String>,
}

/// A library's full hook config. Master-era `LibHookConfig`
/// (`origin/master:cli/cmd/stack.go:35-39`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LibHookConfig {
    pub library: String,
    #[serde(default)]
    pub disable: bool,
    #[serde(default)]
    pub configs: Vec<BaseHookConfig>,
}

/// Top-level hook config. Master-era `HookConfig`
/// (`origin/master:cli/cmd/stack.go:41-44`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookConfig {
    #[serde(rename = "library_dirs", default)]
    pub library_dirs: Vec<String>,
    #[serde(default)]
    pub libs: Vec<LibHookConfig>,
}

/// Decode a hex offset string like `"0xF37C"` / `"0xf37c"` to a u64.
/// Master-era `hex2int` (`origin/master:cli/cmd/stack.go:46-50`): strip the
/// `0x` prefix then parse
/// base-16. Invalid input yields 0 (matching Go's ignored error).
pub fn hex2int(hex: &str) -> u64 {
    let cleaned = hex.replace("0x", "").replace("0X", "");
    u64::from_str_radix(&cleaned, 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_config_json() {
        let json =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.json")).unwrap();
        let cfg: HookConfig = serde_json::from_str(&json).unwrap();
        assert!(!cfg.library_dirs.is_empty());
        assert_eq!(cfg.libs.len(), 2);
        assert_eq!(cfg.libs[0].library, "bionic/libc.so");
        assert_eq!(cfg.libs[0].configs.len(), 2);
        assert_eq!(cfg.libs[0].configs[0].symbols, vec!["open"]);
        assert_eq!(cfg.libs[0].configs[1].symbols, vec!["read", "send", "recv"]);
        assert_eq!(cfg.libs[1].library, "libnative-lib.so");
        assert_eq!(cfg.libs[1].configs[0].symbols, vec!["_Z5func1v"]);
        assert_eq!(cfg.libs[1].configs[0].offsets, vec!["0xF37C"]);
    }

    #[test]
    fn hex2int_values() {
        assert_eq!(hex2int("0xF37C"), 0xF37C);
        assert_eq!(hex2int("0xf37c"), 0xF37C);
        assert_eq!(hex2int("F37C"), 0xF37C);
        assert_eq!(hex2int("0"), 0);
        assert_eq!(hex2int("garbage"), 0);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = HookConfig {
            library_dirs: vec!["/a".into()],
            libs: vec![LibHookConfig {
                library: "libc.so".into(),
                disable: false,
                configs: vec![BaseHookConfig {
                    symbols: vec!["open".into()],
                    offsets: vec![],
                }],
            }],
        };
        let s = serde_json::to_string(&cfg).unwrap();
        let back: HookConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.libs[0].configs[0].symbols, vec!["open"]);
    }

    /// `deny_unknown_fields` pins the round-8 decision: configs that carry the
    /// removed `"regs"`/`"stack"` switches fail parsing instead of being
    /// silently dropped.
    #[test]
    fn removed_hook_keys_are_rejected() {
        for json in [r#"{"regs": true}"#, r#"{"stack": true}"#] {
            let err = serde_json::from_str::<BaseHookConfig>(json).unwrap_err();
            assert!(err.to_string().contains("unknown field"), "{err}");
        }
    }
}
