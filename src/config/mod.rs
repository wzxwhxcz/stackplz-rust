//! Configuration types. Mirrors package `config` (`user/config/*.go`).
//!
//! - `SConfig` / `StackFilter` / `SyscallFilter` => `iconfig.go`
//! - `GlobalConfig`  => `config_global.go`
//! - `TargetConfig`  => `config_target.go`
//! - `StackConfig` / `ProbeConfig` => `config_stack.go` / `config_hook.go`
//! - `SyscallConfig` => `config_syscall.go`
//! - JSON DTOs       => `hook_json.rs` (mirrors `cli/cmd/stack.go` structs)

pub mod global;
pub mod hook_json;
pub mod point_arg;
pub mod point_parser;
pub mod sconfig;
pub mod stack;
pub mod syscall;
pub mod target;

pub use global::GlobalConfig;
pub use hook_json::{BaseHookConfig, HookConfig, LibHookConfig};
pub use point_arg::{PointArg, UprobeArgs, EBPF_SYS_ENTER, EBPF_UPROBE_ENTER};
pub use point_parser::{parse_arg_type, parse_hook_point};
pub use sconfig::{SConfig, StackFilter, SyscallFilter, MAX_TID_BLACKLIST_COUNT};
pub use stack::{ProbeConfig, StackConfig};
pub use syscall::SyscallConfig;
pub use target::TargetConfig;
