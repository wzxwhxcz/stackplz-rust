//! Native unwinder FFI. Mirrors dev's `user/event/chelper.go` +
//! `user/event/load_so.c` + `user/event/load_so.h:13`.
//!
//! On the Go side, `init_stack_unwinder(dl_path)` (`load_so.c:15`) `dlopen`s
//! `<dl_path>/libstackplz.so` and resolves its exported `StackPlz` symbol;
//! `get_stack(map_buffer, opt, regs_buf, stack_buf)` (`load_so.h:13`) forwards
//! to it (`load_so.c:67`). We have no cgo wrapper, so we replicate the chain in
//! pure Rust via `libloading`: `dlopen` the library and call `StackPlz` directly
//! with the same four arguments. The bundled `.so` is the dev build of
//! <https://github.com/SeeFlowerX/unwinddaemon> (4-arg `StackPlz` +
//! `UnwindOption` block, see [`super::ievent::UnwindOption`]).
//!
//! The prebuilt `.so` files are bundled in `assets/preload_libs/` and extracted
//! next to the binary at runtime (see `cli::root::persistent_pre_run`).

use super::ievent::{UnwindBuf, UnwindOption};
use anyhow::{anyhow, Result};
use libloading::{Library, Symbol};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, OnceLock};

/// Signature of the unwinder library's exported `StackPlz` entry point
/// (unwinddaemon `lib.cpp:523`; dev's C wrapper declares the same shape as
/// `FPTR` in `load_so.c:8`):
/// ```c
/// const char* StackPlz(char* map_buffer, void* opt, void* regs_buf, void* stack_buf);
/// ```
/// `opt` points at an [`UnwindOption`], `regs_buf` at the 33 `u64` registers,
/// `stack_buf` at the dumped stack bytes. All four are `*const` here because the
/// library only reads them; pointer constness is not part of the C ABI, so the C
/// declaration above needs no change.
type StackPlzFn = unsafe extern "C" fn(
    map_buffer: *const c_char,
    opt: *const c_void,
    regs_buf: *const c_void,
    stack_buf: *const c_void,
) -> *const c_char;

/// Cached handle to the loaded unwinder library + resolved symbol, plus the
/// `lib_path` it was loaded from. Both are leaked into process-static storage so
/// the `'static` symbol borrow is sound.
struct Unwinder {
    stack_plz: Symbol<'static, StackPlzFn>,
}

// No `unsafe impl Send/Sync` is needed: libloading already implements both for
// `Symbol<'_, T>` when `T` is, and a plain `extern "C" fn` pointer is.
// Concurrent entry into the C function is serialized by `FFI_LOCK` below.

/// unwinddaemon keeps process-global unwind/symbol caches, so `StackPlz` must not
/// be entered concurrently; this lock is what makes that true.
static FFI_LOCK: Mutex<()> = Mutex::new(());

/// Cached unwinder + the `lib_path` it came from. Only a successful load is
/// cached: a failed `dlopen` (the `.so` may not be extracted yet) has to be
/// retryable, with its error surfaced to that caller.
static UNWINDER: OnceLock<(String, Unwinder)> = OnceLock::new();

/// Resolve `StackPlz`, `dlopen`ing `<lib_path>/libstackplz.so` on first use.
///
/// A differing `lib_path` on a later call is an error rather than a silent reuse
/// of the first handle: the two SDK flavours are different ABIs.
fn unwinder(lib_path: &str) -> Result<&'static Unwinder> {
    let stored = match UNWINDER.get() {
        Some(stored) => stored,
        None => {
            // Load before caching, so a failure leaves the cache empty.
            // shortcut: a racing first call can dlopen twice; the unused handle
            // stays leaked (by design). Upgrade if parse_stack becomes hot.
            let loaded = load_unwinder(lib_path)?;
            UNWINDER.get_or_init(|| (lib_path.to_string(), loaded))
        }
    };
    let (path, unw) = stored;
    if path != lib_path {
        return Err(anyhow!(
            "unwinder already loaded from {path}, refusing a different lib_path {lib_path}"
        ));
    }
    Ok(unw)
}

fn load_unwinder(lib_path: &str) -> Result<Unwinder> {
    let full = format!("{}/libstackplz.so", lib_path.trim_end_matches('/'));
    // SAFETY: dlopen of a path we control. The Library is intentionally leaked
    // (Box::leak) so its symbols remain valid for the process lifetime, giving
    // us a sound 'static borrow.
    let boxed_lib = unsafe {
        Box::new(Library::new(&full).map_err(|e| anyhow!("dlopen {} failed: {}", full, e))?)
    };
    let static_lib: &'static Library = Box::leak(boxed_lib);
    // `static_lib` is `&'static Library`, so `get` returns `Symbol<'static, _>`
    // directly — no separate borrow step needed.
    let stack_plz: Symbol<'static, StackPlzFn> = unsafe { static_lib.get(b"StackPlz\0") }
        .map_err(|e| anyhow!("dlsym StackPlz failed: {}", e))?;
    Ok(Unwinder { stack_plz })
}

/// Resolve a stack trace for the given unwind buffer.
///
/// Mirrors dev's `ParseStack(map_buffer, opt, ubuf)` (`user/event/chelper.go:55-77`):
/// - `lib_path`: directory containing the extracted `libstackplz.so` + deps
///   (Go's `LibPath`, set to `<exec_dir>/preload_libs` in `InitCLib`).
/// - `map_buffer`: full `/proc/<pid>/maps` text.
/// - `ubuf`: parsed unwind buffer (regs + stack dump).
///
/// Returns the human-readable stack trace (the `Stackinfo` field). Errors are
/// reported in-band as `<...>` strings, matching dev's degradation.
///
/// # C string ownership
/// `StackPlz` returns a `malloc`ed, NUL-terminated string that the caller owns
/// (`unwinddaemon/lib.cpp:513`; dev frees it with `C.free_stack_str`,
/// `chelper.go:74`). It is copied out and freed here, so it must only stay
/// valid for the duration of the call.
pub fn parse_stack(lib_path: &str, map_buffer: &str, ubuf: &UnwindBuf) -> String {
    // C reads `opt.stack_size` bytes from `stack_buf`, and `UnwindBuf`'s fields
    // are public, so a caller can hand us an inconsistent pair. Refuse it
    // instead of letting C read past the buffer.
    if ubuf.stack_size > ubuf.data.len() as u64 {
        return "<invalid unwind buffer: stack_size > data.len()>".into();
    }

    let unw = match unwinder(lib_path) {
        Ok(u) => u,
        Err(e) => return format!("<unwinder load failed: {}>", e),
    };

    let map_c = match CString::new(map_buffer) {
        Ok(s) => s,
        Err(_) => return "<invalid map_buffer>".into(),
    };

    // dev: `ContextEvent.GetOpt()` builds the option from the parsed UnwindBuf.
    // shortcut: show-pc output isn't ported (`--showpc` was dropped as a dead
    // flag), so ShowPC stays false; flip it via `unwind_option(true)` if the
    // backtrace renderer ever needs the original pc.
    let opt = ubuf.unwind_option(false);

    let opt_ptr: *const UnwindOption = std::ptr::from_ref(&opt);
    let regs_ptr: *const c_void = ubuf.regs.as_ptr().cast();
    let stack_ptr: *const c_void = if ubuf.data.is_empty() {
        std::ptr::null()
    } else {
        ubuf.data.as_ptr().cast()
    };

    // The C side keeps process-global caches; serialize entry (see `FFI_LOCK`).
    let _guard = FFI_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    // SAFETY: `map_c` is a live NUL-terminated buffer, `opt`/`regs`/`ubuf.data`
    // outlive the call and have the shapes unwinddaemon expects (an
    // `UnwindOption` at `opt`, 33 `u64` registers at `regs_buf`, `stack_size`
    // bytes at `stack_buf` — a null `stack_ptr` is only sent when it is 0, and
    // `stack_size > data.len()` was rejected above); the library only reads them.
    let raw = unsafe { (unw.stack_plz)(map_c.as_ptr(), opt_ptr.cast(), regs_ptr, stack_ptr) };
    if raw.is_null() {
        return "<StackPlz returned null>".into();
    }
    // SAFETY: `raw` is the non-null, NUL-terminated buffer the C side just
    // malloc'ed for this call (owned by us, freed below), so scanning up to its
    // terminator stays inside that allocation; the borrow ends before the free.
    let out = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    // shortcut: only Linux frees this (`libc` is a Linux-only dependency), so a
    // non-Linux build leaks one string per unwind; upgrade if it ever runs there.
    #[cfg(target_os = "linux")]
    // SAFETY: `raw` came from the C side's `malloc` and is no longer borrowed.
    unsafe {
        libc::free(raw as *mut c_void)
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_lib_returns_graceful_message() {
        // The library doesn't exist on the test host; parse_stack must not panic.
        let ubuf = UnwindBuf::default();
        let s = parse_stack("/nonexistent/path", "fake maps", &ubuf);
        assert!(s.contains("unwinder load failed") || s.starts_with('<'));
    }

    #[test]
    fn inconsistent_stack_buffer_is_rejected() {
        // `UnwindBuf`'s fields are public: `stack_size` may exceed `data.len()`,
        // which would make C read past the buffer. The guard must catch it.
        let ubuf = UnwindBuf {
            stack_size: 4096,
            data: Vec::new(),
            ..Default::default()
        };
        let s = parse_stack("/nonexistent/path", "fake maps", &ubuf);
        assert!(s.contains("invalid unwind buffer"), "got {s}");
    }
}
