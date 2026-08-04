//! Configuration types. Mirrors package `config` (`user/config/*.go`).
//!
//! - `SConfig` / `StackFilter` / `SyscallFilter` => `iconfig.go`
//! - `GlobalConfig`  => `config_global.go`
//! - `TargetConfig`  => `config_target.go`
//! - `StackConfig` / `ProbeConfig` => `config_stack.go` / `config_hook.go`
//! - `SyscallConfig` => `config_syscall.go`
//! - `filter`        => `config_filter.go`
//! - `file_parser`   => `config_file.go` (YAML/JSON config files)
//! - JSON DTOs       => `hook_json.rs` (mirrors `cli/cmd/stack.go` structs)

pub mod file_parser;
pub mod filter;
pub mod global;
pub mod hook_json;
pub mod point_arg;
pub mod point_parser;
pub mod sconfig;
pub mod stack;
pub mod syscall;
pub mod target;

pub use file_parser::{ParamConfig, PointConfig, SyscallPointConfig, FileConfig, 
                       UprobeFileConfig, SyscallFileConfig, load_syscall_config, load_uprobe_config};
pub use filter::{ArgFilter, FilterHelper, EArgFilter, add_filter, get_filter_by_name, get_filter_index, get_filters};
pub use filter::{UNKNOWN_FILTER, EQUAL_FILTER, GREATER_FILTER, LESS_FILTER, WHITELIST_FILTER, BLACKLIST_FILTER, REPLACE_FILTER};
pub use global::GlobalConfig;
pub use hook_json::{BaseHookConfig, HookConfig, LibHookConfig};
pub use point_arg::{PointArg, UprobeArgs, EBPF_SYS_ENTER, EBPF_UPROBE_ENTER};
pub use point_parser::{parse_arg_type, parse_hook_point};
pub use sconfig::{SConfig, StackFilter, SyscallFilter, MAX_TID_BLACKLIST_COUNT};
pub use stack::{ProbeConfig, StackConfig};
pub use syscall::SyscallConfig;
pub use target::TargetConfig;
