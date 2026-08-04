//! `syscall` subcommand config. Mirrors `ModuleConfig` + `SyscallConfig` (`config_module.go`).

use super::sconfig::{syscall_filter_from, HookConfig, SConfig, SyscallFilter};

/// Syscall tracepoint module configuration. Mirrors `ModuleConfig` + `SyscallConfig`.
#[derive(Debug, Clone)]
pub struct SyscallConfig {
    pub sconfig: SConfig,
    /// Syscall hook config file path (currently unused beyond CLI parsing).
    pub config: String,
    /// Syscall number to filter on. -1 means "match none" (default).
    pub nr: i64,

    // Filter lists (mirrors ModuleConfig fields)
    pub debug: bool,
    pub uid_whitelist: Vec<u32>,
    pub uid_blacklist: Vec<u32>,
    pub pid_whitelist: Vec<u32>,
    pub pid_blacklist: Vec<u32>,
    pub tid_whitelist: Vec<u32>,
    pub tid_blacklist: Vec<u32>,
    pub tname_whitelist: Vec<String>,
    pub tname_blacklist: Vec<String>,

    // Syscall-specific config (mirrors SyscallConfig fields)
    pub sys_whitelist: Vec<u32>,
    pub sys_blacklist: Vec<u32>,
    pub dump_hex: bool,
    pub color: bool,
}

impl SyscallConfig {
    pub fn new() -> Self {
        SyscallConfig {
            sconfig: SConfig::default(),
            config: String::new(),
            nr: -1,
            debug: false,
            uid_whitelist: Vec::new(),
            uid_blacklist: Vec::new(),
            pid_whitelist: Vec::new(),
            pid_blacklist: Vec::new(),
            tid_whitelist: Vec::new(),
            tid_blacklist: Vec::new(),
            tname_whitelist: Vec::new(),
            tname_blacklist: Vec::new(),
            sys_whitelist: Vec::new(),
            sys_blacklist: Vec::new(),
            dump_hex: false,
            color: false,
        }
    }

    /// Produce the on-wire `SyscallFilter` for `filter_map`.
    /// Mirrors `SyscallConfig.GetFilter()` (`config_syscall.go:26-35`).
    pub fn get_filter(&self) -> SyscallFilter {
        syscall_filter_from(&self.sconfig, self.nr)
    }

    /// Human-readable hook label, used for log lines.
    /// Mirrors `SyscallConfig.Info()` (`config_syscall.go`).
    pub fn info(&self) -> String {
        format!("nr:{}", self.nr)
    }

    /// Convert to base_config map value (C struct bytes).
    /// Mirrors `config_entry_t` in `src/types.h`:
    /// ```c
    /// typedef struct config_entry {
    ///     u32 stackplz_pid;
    ///     u32 thread_whitelist;
    /// } config_entry_t;
    /// ```
    pub fn to_base_config_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        // stackplz_pid: current process ID
        bytes.extend_from_slice(&std::process::id().to_ne_bytes());
        // thread_whitelist: 1 if whitelist mode is enabled, 0 otherwise
        let thread_whitelist: u32 = if !self.tname_whitelist.is_empty() {
            1
        } else {
            0
        };
        bytes.extend_from_slice(&thread_whitelist.to_ne_bytes());
        bytes
    }

    /// Convert to common_filter map value (C struct bytes).
    /// Mirrors `common_filter_t` in `src/types.h`:
    /// ```c
    /// typedef struct common_filter {
    ///     u32 is_32bit;
    ///     u32 trace_mode;
    ///     u32 trace_uid_group;
    ///     u32 signal;
    ///     u32 tsignal;
    /// } common_filter_t;
    /// ```
    pub fn to_common_filter_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);

        // is_32bit: 0 for 64-bit (ARM64/x86_64)
        bytes.extend_from_slice(&0u32.to_ne_bytes());

        // trace_mode: determines filter logic (whitelist vs blacklist)
        // 1 = whitelist mode, 2 = blacklist mode
        let trace_mode: u32 = if !self.uid_whitelist.is_empty()
            || !self.pid_whitelist.is_empty()
            || !self.tid_whitelist.is_empty()
        {
            1 // WHITELIST_FILTER
        } else {
            2 // BLACKLIST_FILTER
        };
        bytes.extend_from_slice(&trace_mode.to_ne_bytes());

        // trace_uid_group: UID filtering flags (not used in current implementation)
        bytes.extend_from_slice(&0u32.to_ne_bytes());

        // signal: signal number to send (0 = no signal)
        bytes.extend_from_slice(&0u32.to_ne_bytes());

        // tsignal: target signal (0 = no target)
        bytes.extend_from_slice(&0u32.to_ne_bytes());

        bytes
    }

    /// Default thread name blacklist. Mirrors `DefaultThreadBlacklist()`.
    pub fn default_thread_blacklist(&self) -> Vec<&str> {
        vec![
            "pool-",
            "RenderThread",
            "mali-",
            "GPU completion",
            "hwuiTask",
            "Jit thread pool",
            "Signal Catcher",
            "HeapTaskDaemon",
            "FinalizerDaemon",
            "Binder:",
        ]
    }
}

impl Default for SyscallConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HookConfig for SyscallConfig {
    fn sconfig(&self) -> &SConfig {
        &self.sconfig
    }
    fn sconfig_mut(&mut self) -> &mut SConfig {
        &mut self.sconfig
    }
    fn info(&self) -> String {
        SyscallConfig::info(self)
    }
}
