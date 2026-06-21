//! Uprobe (stack) event formatter. Mirrors `HookDataEvent` (`event_stack.go`).
//!
//! Output format (`HookDataEvent.String()`, `event_stack.go:103-117`):
//! ```text
//! [<pid>|<tid>|<comm>], Regs:
//! {"x0":"0x..",...,"pc":"0x.."}, Stackinfo:
//! <unwound stack text>
//! ```
//! - The `, Regs:\n{...}` block is appended only when `show_regs` (or `reg_name`
//!   forces it).
//! - If `reg_name` is set, an extra `, Reg <name> Info:\n<path + 0xoff>` line
//!   is inserted before Regs (resolved via `util::parse_reg`).
//! - `Stackinfo` is the result of the native `StackPlz` FFI call (when
//!   `unwind_stack` is set) or empty.

use super::context::ContextEvent;
use crate::config::ProbeConfig;
use crate::util::parse_reg;

/// Full event state: decoded common header + probe config.
/// Mirrors `HookDataEvent { ContextEvent, *ProbeConfig }` (`event_stack.go`).
#[derive(Debug)]
pub struct HookDataEvent {
    pub ctx: ContextEvent,
    pub probe: ProbeConfig,
    /// Pre-resolved stack text from the native unwinder (may be empty).
    pub stack_info: String,
}

impl HookDataEvent {
    /// Render the event line. Mirrors `HookDataEvent.String()`.
    pub fn render(&self) -> String {
        let uuid = self.ctx.uuid();
        let mut out = String::new();
        out.push_str(&uuid);

        // --reg forces the regs block to be shown.
        let show_regs = self.probe.sconfig.show_regs || !self.probe.sconfig.reg_name.is_empty();

        if !self.probe.sconfig.reg_name.is_empty() {
            // Resolve the named register value via /proc/<pid>/maps.
            let reg_idx = reg_name_to_index(&self.probe.sconfig.reg_name);
            if let Some(idx) = reg_idx {
                if let Some(regs) = self.ctx.unwind.as_ref().map(|u| &u.regs).or_else(|| self.ctx.regs_only.as_ref().map(|r| &r.regs)) {
                    let value = regs[idx];
                    match parse_reg(self.ctx.pid, value) {
                        Ok(info) => {
                            out.push_str(&format!(", Reg {} Info:\n{}", self.probe.sconfig.reg_name, info));
                        }
                        Err(e) => {
                            out.push_str(&format!(", Reg {} Info:\n<resolve failed: {}>", self.probe.sconfig.reg_name, e));
                        }
                    }
                }
            }
        }

        if show_regs {
            if let Some(json) = self.ctx.regs_json() {
                out.push_str(", Regs:\n");
                out.push_str(&json);
            }
        }

        if self.probe.sconfig.unwind_stack {
            out.push_str(", Stackinfo:\n");
            out.push_str(&self.stack_info);
        }
        out
    }
}

/// Map a `--reg` name (x0..x29, lr) to its index in the regs array.
/// `sp`/`pc` are not accepted as `--reg` inputs (only emitted in output).
fn reg_name_to_index(name: &str) -> Option<usize> {
    if name == "lr" {
        return Some(30);
    }
    if let Some(rest) = name.strip_prefix('x') {
        let n: usize = rest.parse().ok()?;
        if n < 30 {
            return Some(n);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SConfig;
    use crate::event::COMM_LEN;

    fn ctx() -> ContextEvent {
        let mut comm = [0u8; COMM_LEN];
        comm[..3].copy_from_slice(b"app");
        ContextEvent {
            sample_size: 0,
            pid: 1,
            tid: 2,
            timestamp_ns: 0,
            comm,
            unwind: None,
            regs_only: None,
        }
    }

    #[test]
    fn uuid_only_when_no_flags() {
        let probe = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: String::new(),
            symbol: "x".into(),
            offset: 0,
        };
        let e = HookDataEvent { ctx: ctx(), probe, stack_info: String::new() };
        assert_eq!(e.render(), "[1|2|app]");
    }

    #[test]
    fn reg_name_maps_correctly() {
        assert_eq!(reg_name_to_index("x0"), Some(0));
        assert_eq!(reg_name_to_index("x29"), Some(29));
        assert_eq!(reg_name_to_index("lr"), Some(30));
        assert_eq!(reg_name_to_index("sp"), None);
        assert_eq!(reg_name_to_index("pc"), None);
        assert_eq!(reg_name_to_index("garbage"), None);
    }
}
