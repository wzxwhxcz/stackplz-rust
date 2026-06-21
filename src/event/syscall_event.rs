//! Syscall tracepoint event formatter. Mirrors `SyscallDataEvent`
//! (`event_raw_syscalls.go`).
//!
//! Differs from `HookDataEvent` only in the leading ` NR:<nr>` segment:
//! ```text
//! [<pid>|<tid>|<comm>] NR:<nr>, Regs:\n{...}, Stackinfo:\n<unwind>
//! ```

use super::context::ContextEvent;
use crate::config::SyscallConfig;

/// Full syscall event state. Mirrors `SyscallDataEvent { ContextEvent, NR }`
/// (`event_raw_syscalls.go`). `NR` lives on the config in Go; we keep it here
/// for the render path.
#[derive(Debug)]
pub struct SyscallDataEvent {
    pub ctx: ContextEvent,
    pub nr: i64,
    pub show_regs: bool,
    pub unwind_stack: bool,
    pub reg_name: String,
    /// Pre-resolved stack text from the native unwinder.
    pub stack_info: String,
}

impl SyscallDataEvent {
    pub fn from_config(ctx: ContextEvent, conf: &SyscallConfig, stack_info: String) -> Self {
        SyscallDataEvent {
            ctx,
            nr: conf.nr,
            show_regs: conf.sconfig.show_regs,
            unwind_stack: conf.sconfig.unwind_stack,
            reg_name: conf.sconfig.reg_name.clone(),
            stack_info,
        }
    }

    /// Render the event line. Mirrors `SyscallDataEvent.String()`
    /// (`event_raw_syscalls.go:41-54`).
    pub fn render(&self) -> String {
        let mut out = self.ctx.uuid();
        out.push_str(&format!(" NR:{}", self.nr));

        let show_regs = self.show_regs || !self.reg_name.is_empty();
        if show_regs {
            if let Some(json) = self.ctx.regs_json() {
                out.push_str(", Regs:\n");
                out.push_str(&json);
            }
        }
        if self.unwind_stack {
            out.push_str(", Stackinfo:\n");
            out.push_str(&self.stack_info);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::COMM_LEN;

    fn ctx() -> ContextEvent {
        let mut comm = [0u8; COMM_LEN];
        comm[..2].copy_from_slice(b"sh");
        ContextEvent {
            sample_size: 0,
            pid: 10,
            tid: 20,
            timestamp_ns: 0,
            comm,
            unwind: None,
            regs_only: None,
        }
    }

    #[test]
    fn syscall_uuid_with_nr() {
        let e = SyscallDataEvent {
            ctx: ctx(),
            nr: 63,
            show_regs: false,
            unwind_stack: false,
            reg_name: String::new(),
            stack_info: String::new(),
        };
        assert_eq!(e.render(), "[10|20|sh] NR:63");
    }
}
