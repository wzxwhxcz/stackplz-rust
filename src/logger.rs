//! Logging helper. Mirrors the Go `log.New(writer, prefix, log.Ltime)` usage
//! in `cli/cmd/{stack,syscall}.go`.
//!
//! - `stack`   subcommand: prefix `""`,      flags `Ltime`  -> `HH:MM:SS msg`
//! - `syscall` subcommand: prefix `syscall_`, flags `Ltime` -> `HH:MM:SS syscall_msg`
//!
//! `-o/--out <file>` writes to a file under the executable's directory.
//! `--quiet` suppresses terminal output (file only).

use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Output sinks: terminal and/or file. Mirrors the `MultiWriter`/`SetOutput`
/// behavior in the Go subcommand handlers.
pub struct Logger {
    inner: Mutex<LoggerInner>,
}

struct LoggerInner {
    prefix: String,
    show_time: bool,
    show_terminal: bool,
    file: Option<File>,
}

impl Logger {
    pub fn new(prefix: &str, show_time: bool) -> Self {
        Logger {
            inner: Mutex::new(LoggerInner {
                prefix: prefix.to_string(),
                show_time,
                show_terminal: true,
                file: None,
            }),
        }
    }

    /// Open `<exec_dir>/<path>` for writing (create/truncate), mirroring the
    /// Go `os.Create(log_path)` quirk where the path is **exec-dir relative**.
    /// If `quiet`, terminal output is suppressed.
    pub fn set_out_file(&self, exec_dir: &str, path: &str, quiet: bool) -> Result<()> {
        let mut p = PathBuf::from(exec_dir);
        p.push(path);
        // Reproduce the (buggy) Go logic: if the file doesn't exist, os.Remove
        // is a no-op; either way we then truncate via create.
        let _ = std::fs::remove_file(&p);
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&p)?;
        let mut g = self.inner.lock().unwrap();
        g.file = Some(f);
        g.show_terminal = !quiet;
        Ok(())
    }

    /// Print a line with the configured prefix + optional timestamp.
    /// Mirrors `logger.Println(...)`.
    pub fn println(&self, msg: &str) {
        self.write_line(msg, true);
    }

    /// Print without a trailing newline behavior difference; same as println.
    pub fn printf(&self, msg: &str) {
        self.write_line(msg, true);
    }

    fn write_line(&self, msg: &str, _newline: bool) {
        let line = {
            let g = self.inner.lock().unwrap();
            let mut s = String::new();
            if g.show_time {
                s.push_str(&current_time_str());
                s.push(' ');
            }
            if !g.prefix.is_empty() {
                s.push_str(&g.prefix);
            }
            s.push_str(msg);
            s
        };
        // Acquire lock again to write (avoid holding across the format above).
        let mut g = self.inner.lock().unwrap();
        let line_bytes = line.as_bytes();
        if g.show_terminal {
            let _ = io::stdout().write_all(line_bytes);
            let _ = io::stdout().write_all(b"\n");
            let _ = io::stdout().flush();
        }
        if let Some(f) = g.file.as_mut() {
            let _ = f.write_all(line_bytes);
            let _ = f.write_all(b"\n");
            let _ = f.flush();
        }
    }
}

/// `HH:MM:SS` from the system clock, mirroring Go's `log.Ltime`.
fn current_time_str() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let local_offset = local_utc_offset_seconds();
    let t = secs.wrapping_add(local_offset as u64);
    let h = (t / 3600) % 24;
    let m = (t / 60) % 60;
    let s = t % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

/// Best-effort local offset. On a host without a tz, returns 0 (UTC).
fn local_utc_offset_seconds() -> i64 {
    // Use the difference between localtime and gmtime via libc when available.
    #[cfg(unix)]
    {
        use std::os::raw::*;
        extern "C" {
            fn time(t: *mut c_long) -> c_long;
            fn localtime_r(t: *const c_long, result: *mut Tm) -> *mut Tm;
        }
        #[repr(C)]
        struct Tm {
            tm_sec: c_int,
            tm_min: c_int,
            tm_hour: c_int,
            tm_mday: c_int,
            tm_mon: c_int,
            tm_year: c_int,
            tm_wday: c_int,
            tm_yday: c_int,
            tm_isdst: c_int,
            tm_gmtoff: c_long,
            tm_zone: *const c_char,
        }
        unsafe {
            let mut now: c_long = 0;
            time(&mut now);
            let mut lt = std::mem::zeroed::<Tm>();
            localtime_r(&now, &mut lt);
            lt.tm_gmtoff as i64
        }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logger_formats_prefix_and_time() {
        let l = Logger::new("syscall_", true);
        // Just ensure it doesn't panic; output goes to stdout.
        l.println("hello");
    }

    #[test]
    fn time_str_format() {
        let s = current_time_str();
        assert_eq!(s.len(), 8);
        assert_eq!(s.as_bytes()[2], b':');
        assert_eq!(s.as_bytes()[5], b':');
    }
}
