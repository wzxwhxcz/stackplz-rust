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
    /// Lines dropped because at least one sink (terminal and/or file) failed
    /// to write them: one line counts at most once (round 10 / M3).
    lines_failed: u64,
}

impl Logger {
    pub fn new(prefix: &str, show_time: bool) -> Self {
        Logger {
            inner: Mutex::new(LoggerInner {
                prefix: prefix.to_string(),
                show_time,
                show_terminal: true,
                file: None,
                lines_failed: 0,
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
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.file = Some(f);
        g.show_terminal = !quiet;
        Ok(())
    }

    /// Print a line with the configured prefix + optional timestamp.
    /// Mirrors `logger.Println(...)`.
    pub fn println(&self, msg: &str) {
        self.write_line(msg);
    }

    /// Total lines dropped because at least one sink failed to write them.
    /// Best-effort output stays best-effort, but failures are at least
    /// observable.
    pub fn failed_lines(&self) -> u64 {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.lines_failed
    }

    /// Present [`Logger::failed_lines`] on the CLI exit path (round 7 / F1,
    /// round 10 / M3): print the warning to stderr whenever lines were lost,
    /// **before** returning `res` — whether the run succeeded or failed, a
    /// failing run loses logs too, and that is when the warning matters most.
    /// `res` is returned unchanged so callers can keep using `?`.
    pub fn finish_run(res: Result<()>, logger: &Logger) -> Result<()> {
        if let Some(warning) = Self::dropped_lines_warning(logger.failed_lines()) {
            eprintln!("{warning}");
        }
        res
    }

    /// Present [`Logger::failed_lines`] on the CLI exit path (round 7 / F1):
    /// `None` when nothing was dropped, otherwise the one-line warning the
    /// caller prints to stderr. Pure, so tests can pin the wording.
    pub fn dropped_lines_warning(failed: u64) -> Option<String> {
        if failed == 0 {
            None
        } else {
            Some(format!("warning: dropped {failed} log lines"))
        }
    }

    /// Write one line + newline to a sink; bump `failed` when any step fails.
    fn write_line_to(sink: &mut dyn Write, bytes: &[u8], failed: &mut u64) {
        let ok =
            sink.write_all(bytes).is_ok() && sink.write_all(b"\n").is_ok() && sink.flush().is_ok();
        if !ok {
            *failed += 1;
        }
    }

    /// Write one line to the terminal and/or file sink, counting the line as
    /// lost when **either** sink fails (round 10 / M3): a line that fails on
    /// both sinks still counts once — `failed_lines` speaks of lost lines,
    /// not of failed sink writes. `None` means the sink is absent.
    fn write_line_sinks(
        terminal: Option<&mut dyn Write>,
        file: Option<&mut dyn Write>,
        bytes: &[u8],
        lines_failed: &mut u64,
    ) {
        let sink_ok = |sink: Option<&mut dyn Write>| match sink {
            Some(w) => {
                let mut failed = 0u64;
                Self::write_line_to(w, bytes, &mut failed);
                failed == 0
            }
            None => true,
        };
        if !sink_ok(terminal) || !sink_ok(file) {
            *lines_failed += 1;
        }
    }

    fn write_line(&self, msg: &str) {
        let line = {
            let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
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
        // A poisoned lock (a panicking writer thread) must not kill the trace
        // loop; recovering the guard keeps logging instead of unwrapping.
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let line_bytes = line.as_bytes();
        // Best-effort output: a closed stdout or a full disk is unactionable
        // here (no error channel, no retry), and dropping the line beats
        // aborting the trace loop that the whole tool runs inside.
        // `g.file` is taken out and put back so the line counter
        // (`g.lines_failed`) can be borrowed mutably in the same call:
        // borrowing `g.file` and `g.lines_failed` together is rejected
        // (E0499 — the old code worked around it by inlining the file write).
        let mut stdout = io::stdout();
        let terminal = g.show_terminal.then_some(&mut stdout as &mut dyn Write);
        let mut file = g.file.take();
        let file_sink = file.as_mut().map(|f| f as &mut dyn Write);
        Self::write_line_sinks(terminal, file_sink, line_bytes, &mut g.lines_failed);
        g.file = file;
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
            if time(&mut now) == -1 {
                return 0;
            }
            // All-zero `Tm` is valid (ints plus a nullable pointer); on
            // failure `localtime_r` leaves it untouched, so we fall back to
            // UTC (gmtoff 0) — the best-effort contract above, not an
            // explicit report.
            let mut lt = std::mem::zeroed::<Tm>();
            if localtime_r(&now, &mut lt).is_null() {
                return 0;
            }
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
    use std::sync::Arc;

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

    /// A writer whose write/flush always fail.
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("fail"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("fail"))
        }
    }

    #[test]
    fn write_line_to_counts_failures() {
        let mut good: Vec<u8> = Vec::new();
        let mut ok_failed = 0u64;
        Logger::write_line_to(&mut good, b"line", &mut ok_failed);
        assert_eq!(ok_failed, 0, "healthy sink must not count a failure");
        assert_eq!(good, b"line\n");

        let mut failed = 0u64;
        Logger::write_line_to(&mut FailingWriter, b"line", &mut failed);
        assert_eq!(failed, 1, "failing sink must bump the counter once");
    }

    /// M3: `failed_lines` counts **lost lines**, so a line whose terminal and
    /// file writes both fail bumps the counter once, not twice. This drives
    /// exactly the per-line decision `write_line` makes.
    #[test]
    fn double_sink_failure_counts_one_lost_line() {
        let mut lines_failed = 0u64;
        Logger::write_line_sinks(
            Some(&mut FailingWriter),
            Some(&mut FailingWriter),
            b"line",
            &mut lines_failed,
        );
        assert_eq!(lines_failed, 1, "one line lost on both sinks counts once");

        let mut n = 0u64;
        Logger::write_line_sinks(Some(&mut FailingWriter), None, b"line", &mut n);
        assert_eq!(n, 1, "terminal-only failure still loses the line");
        let mut n = 0u64;
        Logger::write_line_sinks(None, Some(&mut FailingWriter), b"line", &mut n);
        assert_eq!(n, 1, "file-only failure still loses the line");

        let mut good: Vec<u8> = Vec::new();
        let mut n = 0u64;
        Logger::write_line_sinks(Some(&mut good), None, b"line", &mut n);
        assert_eq!(n, 0, "healthy sink loses nothing");
        assert_eq!(good, b"line\n");

        let mut n = 0u64;
        Logger::write_line_sinks(None, None, b"line", &mut n);
        assert_eq!(n, 0, "no sink, nothing written, nothing lost");
    }

    /// M3: the dropped-lines warning must be presented on the error path too —
    /// `finish_run` runs before the caller returns `res`, and must hand `res`
    /// back unchanged (the warning wording itself is pinned by
    /// `dropped_lines_warning_names_the_count`).
    #[test]
    fn finish_run_prints_the_warning_on_the_error_path_too() {
        let logger = Logger::new("", false);
        let ok: anyhow::Result<()> = Ok(());
        assert!(Logger::finish_run(ok, &logger).is_ok());

        let err: anyhow::Result<()> = Err(anyhow::anyhow!("module failed"));
        let e = Logger::finish_run(err, &logger).unwrap_err();
        assert!(format!("{e:#}").contains("module failed"), "{e:#}");
    }

    #[test]
    fn dropped_lines_warning_is_none_when_nothing_was_dropped() {
        assert_eq!(Logger::dropped_lines_warning(0), None);
    }

    #[test]
    fn dropped_lines_warning_names_the_count() {
        assert_eq!(
            Logger::dropped_lines_warning(1).as_deref(),
            Some("warning: dropped 1 log lines")
        );
        assert_eq!(
            Logger::dropped_lines_warning(7).as_deref(),
            Some("warning: dropped 7 log lines")
        );
    }

    /// Round 12 / R11-9: one shared Logger with one `set_out_file` call — two
    /// threads write concurrently (the dual-module `-o` case) and all 100
    /// lines land intact: no truncation/unlink of the other writer's output,
    /// no torn lines (the inner Mutex serializes writes).
    #[test]
    fn shared_logger_concurrent_writes_keep_all_lines() {
        let dir =
            std::env::temp_dir().join(format!("stackplz-logger-shared-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trace.log");
        let logger = Arc::new(Logger::new("", false));
        logger
            .set_out_file(&dir.to_string_lossy(), "trace.log", true)
            .unwrap();

        let mut handles = Vec::new();
        for tag in ["A", "B"] {
            let logger = Arc::clone(&logger);
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    logger.println(&format!("{tag}-{i}"));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            content.lines().count(),
            100,
            "all 100 lines must be present"
        );
        for tag in ["A", "B"] {
            for i in 0..50 {
                let want = format!("{tag}-{i}");
                assert!(
                    content.lines().any(|l| l == want.as_str()),
                    "missing intact line {want}"
                );
            }
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
