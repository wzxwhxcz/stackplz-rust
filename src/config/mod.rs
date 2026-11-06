//! Configuration types. Mirrors package `config` (`user/config/*.go`).
//!
//! - `SConfig` / `StackFilter` / `SyscallFilter` => master shape, no dev
//!   carrier (`origin/master:user/config/iconfig.go:5-46`; kept here for the
//!   legacy `filter_map` wire layout). Dev writes one shared `CommonFilter`
//!   (`config_filter.go:18-24`) instead of per-module filter structs.
//! - `GlobalConfig`  => `config_global.go`
//! - `TargetConfig`  => master shape, no dev carrier
//!   (`origin/master:user/config/config_target.go:3-12`); dev resolves the
//!   target inline in `persistentPreRunEFunc` (`cli/cmd/root.go:209-250`).
//! - `StackConfig` / `ProbeConfig` => master shape, no dev carrier
//!   (`origin/master:user/config/config_stack.go:3-11`,
//!   `origin/master:user/config/config_hook.go:10-16`); dev's carriers are `StackUprobeConfig`
//!   (`config_module.go:23`) and `ModuleConfig` (`config_module.go:752-799`).
//! - `SyscallConfig` => `config_module.go:437-447` (dev moved it out of
//!   `config_syscall.go`)
//! - `filter`        => `config_filter.go`
//! - `file_parser`   => `config_file.go` (YAML/JSON config files)
//! - JSON DTOs       => `hook_json.rs` (master shape, no dev carrier:
//!   `origin/master:cli/cmd/stack.go:28-50`)

pub mod file_parser;
pub mod filter;
pub mod global;
pub mod hook_json;
pub mod point_arg;
pub mod point_parser;
pub mod sconfig;
pub mod stack;
pub mod syscall;
pub mod syscall_points;
pub mod syscall_select;
pub mod target;
pub mod thread_blacklist;

pub use crate::cli::root::{ResolvedFilters, TidBlacklist};
pub use file_parser::{
    load_syscall_config, load_uprobe_config, FileConfig, ParamConfig, PointConfig,
    SyscallFileConfig, SyscallPointConfig, UprobeFileConfig,
};
pub use filter::{
    add_filter, get_filter_by_name, get_filter_index, get_filters, ArgFilter, EArgFilter,
    FilterHelper,
};
pub use filter::{
    BLACKLIST_FILTER, EQUAL_FILTER, GREATER_FILTER, LESS_FILTER, REPLACE_FILTER, UNKNOWN_FILTER,
    WHITELIST_FILTER,
};
pub use global::{GlobalConfig, MAX_LIST_COUNT};
pub use hook_json::{BaseHookConfig, HookConfig, LibHookConfig};
pub use point_arg::{PointArg, UprobeArgs, EBPF_SYS_ENTER, EBPF_UPROBE_ENTER};
pub use point_parser::{parse_arg_type, parse_hook_point};
pub use sconfig::{SConfig, StackFilter, SyscallFilter, MAX_TID_BLACKLIST_COUNT};
pub use stack::{ProbeConfig, StackConfig};
pub use syscall::SyscallConfig;
pub use syscall_points::{SyscallPoint, SyscallPointOpConfig, SyscallPointTable};
pub use syscall_select::{select as select_syscalls, SyscallSelection};
pub use target::TargetConfig;
pub use thread_blacklist::{default_thread_blacklist, thread_filter_key, validate_thread_name};
