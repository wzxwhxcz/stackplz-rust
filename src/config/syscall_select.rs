//! `-s/--syscall` and `--no-syscall` spec parsing.
//!
//! Mirrors upstream `dev`'s `SyscallConfig.Parse_SyscallNames` +
//! `SyscallConfig.Parse_Syscall` (`user/config/config_module.go:560-732`).
//!
//! Upstream accepts three token kinds in the comma-separated list:
//!
//! 1. `all` — trace every syscall (`TRACE_ALL`, no whitelist gate);
//! 2. a `%group` alias (`%file`, `%attr`, `%net`, … — 21 groups) expanding to a
//!    fixed set of syscall names;
//! 3. a syscall name, optionally with a filter group: `openat:f0.f2` applies the
//!    argument filters registered by `-f` to that syscall's arguments, and
//!    `readlinkat:|f1` skips the first argument (`|` is a positional
//!    placeholder).
//!
//! The previous Rust CLI accepted only `all` and raw numbers, so every name and
//! every `%group` from the documented usage was a hard error (report W6/F5).
//!
//! A raw syscall **number** is still accepted as an extension: earlier rounds of
//! this crate (and their tests) use `-s 63,64`, which upstream would reject.
//! The number must exist in the point table, so `-s 9999` still fails loudly.

use anyhow::{anyhow, bail, Result};

use super::filter::get_filter_by_name;
use super::point_arg::{EBPF_SYS_ENTER, EBPF_SYS_EXIT};
use super::syscall_points::{SyscallPoint, SyscallPointTable};
use crate::argtype::consts::STRING;
use crate::contract::consts::{TRACE_ALL, TRACE_COMMON};

/// One `%group` alias and the syscall names it expands to.
///
/// Copied verbatim from `Parse_SyscallNames` (`config_module.go:560-644`); the
/// grouping is upstream's, not a reconstruction. Order is preserved so `-s all`
/// produces the same whitelist order.
pub const SYSCALL_GROUPS: &[(&str, &[&str])] = &[
    (
        "%attr",
        &[
            "setxattr",
            "lsetxattr",
            "fsetxattr",
            "getxattr",
            "lgetxattr",
            "fgetxattr",
            "listxattr",
            "llistxattr",
            "flistxattr",
            "removexattr",
            "lremovexattr",
            "fremovexattr",
        ],
    ),
    (
        "%file",
        &[
            "openat",
            "openat2",
            "faccessat",
            "faccessat2",
            "mknodat",
            "mkdirat",
            "unlinkat",
            "symlinkat",
            "linkat",
            "renameat",
            "renameat2",
            "readlinkat",
            "chdir",
            "fchdir",
            "chroot",
            "fchmod",
            "fchmodat",
            "fchownat",
            "fchown",
        ],
    ),
    (
        "%fileop",
        &[
            "mknodat",
            "mkdirat",
            "linkat",
            "unlinkat",
            "symlinkat",
            "renameat",
        ],
    ),
    ("%clone", &["clone", "clone3"]),
    ("%exec", &["execve", "execveat"]),
    (
        "%mount",
        &["umount2", "mount", "move_mount", "fsmount", "mount_setattr"],
    ),
    ("%fsop", &["fsopen", "fsconfig", "fsmount", "fspick"]),
    (
        "%process",
        &[
            "clone",
            "clone3",
            "execve",
            "execveat",
            "wait4",
            "waitid",
            "exit",
            "exit_group",
            "rt_sigqueueinfo",
            "pidfd_send_signal",
            "pidfd_open",
            "pidfd_getfd",
        ],
    ),
    (
        "%net",
        &[
            "socket",
            "socketpair",
            "bind",
            "listen",
            "accept",
            "accept4",
            "connect",
            "getsockname",
            "getpeername",
            "setsockopt",
            "getsockopt",
            "shutdown",
        ],
    ),
    ("%send", &["sendto", "sendmsg", "sendmmsg"]),
    ("%recv", &["recvfrom", "recvmsg", "recvmmsg"]),
    ("%read", &["read", "readv", "pread64", "preadv", "preadv2"]),
    (
        "%write",
        &["write", "writev", "pwrite64", "pwritev", "pwritev2"],
    ),
    (
        "%signal",
        &[
            "sigaltstack",
            "rt_sigsuspend",
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigpending",
            "rt_sigtimedwait",
            "rt_sigqueueinfo",
            "rt_sigreturn",
            "rt_tgsigqueueinfo",
        ],
    ),
    ("%kill", &["kill", "tkill", "tgkill"]),
    ("%exit", &["exit", "exit_group"]),
    (
        "%sched",
        &[
            "sched_setparam",
            "sched_setscheduler",
            "sched_getscheduler",
            "sched_getparam",
            "sched_setaffinity",
            "sched_getaffinity",
            "sched_yield",
            "sched_get_priority_max",
            "sched_get_priority_min",
            "sched_rr_get_interval",
            "sched_setattr",
            "sched_getattr",
        ],
    ),
    ("%dup", &["dup", "dup3"]),
    (
        "%inotify",
        &["inotify_init1", "inotify_add_watch", "inotify_rm_watch"],
    ),
    (
        "%epoll",
        &["epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2"],
    ),
    (
        "%stat",
        &["statfs", "fstatfs", "newfstatat", "fstat", "statx"],
    ),
];

/// Result of parsing `-s` / `--no-syscall`.
#[derive(Debug, Clone)]
pub struct SyscallSelection {
    /// `SysCallConf.Enable`: false means "do not run the syscall module"
    /// (upstream: `--no-syscall all`, or an empty whitelist → `hook nothing`).
    pub enable: bool,
    /// `SysCallConf.TraceMode`: `TRACE_ALL` after `-s all`, otherwise
    /// `TRACE_COMMON` (gate on the per-sysno whitelist in `common_list`).
    pub trace_mode: u32,
    /// Syscall numbers in `SysWhitelist`.
    pub whitelist: Vec<u32>,
    /// Syscall numbers in `SysBlacklist`.
    pub blacklist: Vec<u32>,
}

impl Default for SyscallSelection {
    fn default() -> Self {
        Self {
            enable: false,
            trace_mode: TRACE_COMMON,
            whitelist: Vec::new(),
            blacklist: Vec::new(),
        }
    }
}

/// Expand one comma-separated spec into syscall names, the way
/// `Parse_SyscallNames` does: `all` sets the "saw all" flag, `%group` tokens
/// expand, everything else is copied verbatim. Duplicates are removed while
/// keeping the first occurrence.
///
/// Returns `(names, saw_all)`.
fn expand_spec(spec: &str) -> (Vec<String>, bool) {
    let mut names: Vec<String> = Vec::new();
    let mut saw_all = false;

    for item in spec.split(',') {
        if item.is_empty() {
            continue;
        }
        if item == "all" {
            saw_all = true;
            // Upstream clears what it collected so far and keeps parsing; the
            // caller replaces the list with every table entry when `saw_all`.
            names.clear();
            continue;
        }
        if let Some((_, members)) = SYSCALL_GROUPS.iter().find(|(alias, _)| *alias == item) {
            for name in *members {
                if !names.iter().any(|n| n == name) {
                    names.push((*name).to_string());
                }
            }
            continue;
        }
        // Numeric tokens are this crate's extension over upstream. They are
        // deliberately *not* deduped here so a repeated number (`-s 63,63`)
        // reaches the duplicate check below and fails, as the brief requires.
        if item.parse::<u32>().is_ok() || !names.iter().any(|n| n == item) {
            names.push(item.to_string());
        }
    }

    (names, saw_all)
}

/// Parse `-s`/`--no-syscall` into a [`SyscallSelection`] and attach the
/// `name:f0.f2` filters to the corresponding points in `table`.
///
/// Mirrors `Parse_Syscall` (`config_module.go:647-732`).
pub fn select(
    table: &mut SyscallPointTable,
    syscall_spec: &str,
    no_syscall_spec: &str,
) -> Result<SyscallSelection> {
    let mut selection = SyscallSelection {
        // Upstream starts with `Enable = true; TraceMode = TRACE_COMMON` and
        // turns `Enable` off again when the whitelist ends up empty.
        enable: true,
        trace_mode: TRACE_COMMON,
        whitelist: Vec::new(),
        blacklist: Vec::new(),
    };

    // 1. Blacklist first (`Parse_Syscall` lines 651-666).
    let (black_names, black_all) = expand_spec(no_syscall_spec);
    if black_all {
        // Upstream: "if this.TraceMode == TRACE_ALL { this.Enable = false; return }"
        // — a `/all` blacklist means "everything is excluded", so the module is
        // simply not started (report §4.3, W14).
        return Ok(SyscallSelection {
            enable: false,
            trace_mode: TRACE_ALL,
            whitelist: Vec::new(),
            blacklist: Vec::new(),
        });
    }
    for name in &black_names {
        let point = table.resolve(name)?;
        if !selection.blacklist.contains(&point.nr) {
            selection.blacklist.push(point.nr);
        }
    }

    // 2. Whitelist (`Parse_Syscall` lines 668-732).
    let (mut white_names, white_all) = expand_spec(syscall_spec);
    if white_all {
        selection.trace_mode = TRACE_ALL;
        white_names = table.names().map(str::to_string).collect();
    }

    for token in &white_names {
        // `name:f0.f2` / `name:|f1` — the filter group is everything after the
        // first ':' and groups are separated by '|'.
        let (name, filter_groups) = match token.split_once(':') {
            Some((name, groups)) => (
                name,
                groups.split('|').map(str::to_string).collect::<Vec<_>>(),
            ),
            None => (token.as_str(), Vec::new()),
        };

        let point = table.resolve(name)?;
        let nr = point.nr;

        // A syscall present in both lists is skipped (upstream `continue`s).
        if selection.blacklist.contains(&nr) {
            continue;
        }
        if selection.whitelist.contains(&nr) {
            // Upstream `panic("nr:%d name:%s duplicate, bug ?")`. Report W19:
            // this crate used to accept `-s 63,63` silently.
            bail!("nr:{} name:{} duplicate, bug ?", nr, name);
        }
        selection.whitelist.push(nr);

        if !filter_groups.is_empty() {
            let point = if table.by_name(name).is_some() {
                table.point_mut(name)
            } else {
                table.point_mut_by_nr(nr)
            }
            .ok_or_else(|| anyhow!("unknown syscall name:{}", name))?;
            apply_filter_groups(point, &filter_groups)?;
        }
    }

    // `if len(this.SysWhitelist) == 0 { this.Enable = false }`.
    if selection.whitelist.is_empty() {
        selection.enable = false;
    }

    Ok(selection)
}

/// Attach `-f` filter indices to one syscall point's enter-side arguments.
///
/// Mirrors `Parse_Syscall` (`config_module.go:700-730`) exactly, including the
/// two different placements:
/// - a single group (`openat:f0.f2`) applies its filters to the **first matching**
///   argument — the first `string` argument for string filters, else the first
///   argument at all;
/// - multiple groups (`readlinkat:|f1`, i.e. a `|` placeholder) apply group *i*
///   to argument *i*.
fn apply_filter_groups(point: &mut SyscallPoint, filter_groups: &[String]) -> Result<()> {
    if filter_groups.len() == 1 {
        for filter_name in filter_groups[0].split('.').filter(|s| !s.is_empty()) {
            let filter = get_filter_by_name(filter_name)
                .ok_or_else(|| anyhow!("{} not match any filter", filter_name))?;
            if filter.is_str() {
                // String filters go to the first string argument that is read
                // at this point type.
                if let Some(arg) = point
                    .enter_point_args
                    .iter_mut()
                    .find(|arg| arg.type_index == STRING && arg.point_type == EBPF_SYS_ENTER)
                {
                    arg.add_filter_index(filter.filter_index);
                }
            } else if let Some(arg) = point.enter_point_args.first_mut() {
                arg.add_filter_index(filter.filter_index);
            }
        }
        return Ok(());
    }

    // Multiple groups: `|` keeps positions aligned with the argument index.
    for (group_index, filter_group) in filter_groups.iter().enumerate() {
        if filter_group.is_empty() {
            continue;
        }
        for filter_name in filter_group.split('.').filter(|s| !s.is_empty()) {
            let filter = get_filter_by_name(filter_name)
                .ok_or_else(|| anyhow!("{} not match any filter", filter_name))?;
            if let Some(arg) = point.enter_point_args.get_mut(group_index) {
                arg.add_filter_index(filter.filter_index);
            }
        }
    }
    let _ = EBPF_SYS_EXIT;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argtype::init_argtypes;
    #[allow(unused_imports)]
    use crate::config::filter::add_filter as _add_filter;

    fn fresh_table() -> SyscallPointTable {
        init_argtypes();
        SyscallPointTable::embedded().unwrap()
    }

    #[test]
    fn group_aliases_expand_to_the_dev_syscall_sets() {
        let (names, all) = expand_spec("%file,%write");
        assert!(!all);
        assert!(names.contains(&"openat".to_string()));
        assert!(names.contains(&"readlinkat".to_string()));
        assert!(names.contains(&"write".to_string()));
        // `%file` and `%write` do not overlap; no duplicates survive.
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), names.len(), "expansion must dedupe");
    }

    #[test]
    fn all_expands_to_every_point_and_sets_trace_all() {
        let mut table = fresh_table();
        let selection = select(&mut table, "all", "").unwrap();
        assert!(selection.enable);
        assert_eq!(selection.trace_mode, TRACE_ALL);
        assert_eq!(selection.whitelist.len(), table.len());
        assert!(selection.blacklist.is_empty());
    }

    #[test]
    fn syscall_names_resolve_and_duplicates_are_rejected() {
        let mut table = fresh_table();
        let selection = select(&mut table, "openat,read", "").unwrap();
        assert!(selection.enable);
        assert_eq!(selection.trace_mode, TRACE_COMMON);
        assert_eq!(selection.whitelist, vec![56, 63]);

        // Repeated *names* are deduped silently, exactly like upstream's
        // `Parse_SyscallNames` de-dup loop (`config_module.go:640-646`).
        let deduped = select(&mut table, "read,read", "").unwrap();
        assert_eq!(deduped.whitelist, vec![63]);

        // Report W19 / brief item 5: `-s 63,63` used to be accepted silently.
        // Upstream panics "duplicate, bug ?" when two tokens resolve to the same
        // nr; numbers are this crate's extension, so repeated numbers must be a
        // hard error rather than a silent dedupe.
        let err = select(&mut table, "63,63", "").unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn unknown_name_and_number_are_errors() {
        let mut table = fresh_table();
        assert!(select(&mut table, "open", "").is_err());
        assert!(select(&mut table, "9999", "").is_err());
        assert!(select(&mut table, "", "nosuchsyscall").is_err());
    }

    #[test]
    fn no_syscall_all_disables_the_module() {
        let mut table = fresh_table();
        let selection = select(&mut table, "openat", "all").unwrap();
        assert!(
            !selection.enable,
            "dev: --no-syscall all => Enable=false (report §4.3 W14)"
        );
        assert_eq!(selection.trace_mode, TRACE_ALL);
        assert!(selection.whitelist.is_empty());
    }

    #[test]
    fn blacklist_filters_the_whitelist() {
        let mut table = fresh_table();
        let selection = select(&mut table, "%file", "openat").unwrap();
        assert!(!selection.whitelist.contains(&56), "openat is blacklisted");
        assert!(!selection.whitelist.contains(&63));
        assert!(selection.blacklist.contains(&56));
    }

    #[test]
    fn empty_spec_disables_the_module() {
        let mut table = fresh_table();
        let selection = select(&mut table, "", "").unwrap();
        assert!(!selection.enable, "no -s => nothing to trace");
    }

    /// Filter *names* are positional (`f0` = filter_index 1), and the global
    /// registry is shared with other tests, so this test derives the expected
    /// index from the registry instead of assuming registration order.
    fn filter_name_of(index: u32) -> String {
        format!("f{}", index - 1)
    }

    #[test]
    fn filter_groups_attach_filter_indices_to_arguments() {
        // A string filter (`w:` is a WHITELIST/str filter) attaches to the
        // first plain `str` argument — `setxattr(pathname, ...)` has one.
        let str_index = crate::config::add_filter("w:/data").unwrap();
        let mut table = fresh_table();
        let token = format!("setxattr:{}", filter_name_of(str_index));
        select(&mut table, &token, "").unwrap();
        let setxattr = table.by_name("setxattr").unwrap();
        let pathname = &setxattr.enter_point_args[0];
        assert_eq!(pathname.name, "pathname");
        assert_eq!(pathname.filter_index_list, vec![str_index]);

        // A non-string filter (`eq:` is EQUAL) attaches to the first argument
        // whatever its type is.
        let num_index = crate::config::add_filter("eq:42").unwrap();
        let mut table = fresh_table();
        let token = format!("openat:{}", filter_name_of(num_index));
        select(&mut table, &token, "").unwrap();
        let openat = table.by_name("openat").unwrap();
        assert_eq!(openat.enter_point_args[0].name, "dirfd");
        assert_eq!(
            openat.enter_point_args[0].filter_index_list,
            vec![num_index]
        );

        // `*str` also matches: `to_pointer_type()` on the string builder keeps
        // the `STRING` type index (the pointer-ness lives in `parent_index`), so
        // `openat`'s `*pathname` receives the filter just like `setxattr`'s
        // `pathname`. This is the case the documented usage `-s openat:f0` relies
        // on, so it must be locked down.
        let mut table = fresh_table();
        let token = format!("openat:{}", filter_name_of(str_index));
        select(&mut table, &token, "").unwrap();
        let openat = table.by_name("openat").unwrap();
        let pathname = &openat.enter_point_args[1];
        assert_eq!(pathname.name, "*pathname");
        assert_eq!(pathname.filter_index_list, vec![str_index]);
        // Scalar arguments must not have received the string filter.
        assert!(openat.enter_point_args[0].filter_index_list.is_empty());
    }

    #[test]
    fn positional_filter_groups_apply_per_argument() {
        let mut table = fresh_table();
        let f1 = crate::config::add_filter("w:/apex").unwrap();
        // `readlinkat:|fN` — group 0 empty, group 1 applies to argument 1.
        let token = format!("readlinkat:|{}", filter_name_of(f1));
        let selection = select(&mut table, &token, "").unwrap();
        assert_eq!(selection.whitelist.len(), 1);
        let point = table.by_name("readlinkat").unwrap();
        assert!(
            point.enter_point_args[0].filter_index_list.is_empty(),
            "group 0 is a placeholder"
        );
        assert_eq!(point.enter_point_args[1].filter_index_list, vec![f1]);
    }

    #[test]
    fn unknown_filter_name_is_an_error() {
        let mut table = fresh_table();
        // Pick a name that is guaranteed absent: one past the registry size.
        let missing = format!("f{}", crate::config::get_filters().len() + 10);
        let token = format!("openat:{missing}");
        let err = select(&mut table, &token, "").unwrap_err();
        assert!(err.to_string().contains("not match any filter"), "{err}");
    }
}
