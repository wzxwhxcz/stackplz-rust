//! Native unwinder FFI. Mirrors `user/event/chelper.go` + `user/event/load_so.c`.
//!
//! On the Go side, `ParseStack(map_buffer, ubuf)` calls the cgo function
//! `get_stack(dl_path, map_buffer, reg_mask, unwind_buf, stack_buf)` (declared in
//! `load_so.h`). That C function lazily `dlopen`s `libstackplz.so` (which links
//! against Android `libunwindstack.so`) and calls its exported `StackPlz`
//! symbol. We replicate the whole chain in pure Rust via `libloading`.
//!
//! The prebuilt `.so` files are bundled in `assets/preload_libs/` and extracted
//! next to the binary at runtime (see `cli::root::persistent_pre_run`).

use super::ievent::{LibArg, UnwindBuf};
use crate::ebpf::bpf_common::ARM64_REG_MASK;
use anyhow::{anyhow, Result};
use libloading::{Library, Symbol};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::OnceLock;

/// Signature of the C `get_stack` entry point (`load_so.h`):
/// ```c
/// const char* get_stack(char* dl_path, char* map_buffer,
///                       uint64_t reg_mask, void* unwind_buf, void* stack_buf);
/// ```
type GetStackFn = unsafe extern "C" fn(
    dl_path: *mut c_char,
    map_buffer: *mut c_char,
    reg_mask: u64,
    unwind_buf: *mut c_void,
    stack_buf: *mut c_void,
) -> *const c_char;

/// Cached handle to the loaded unwinder library + resolved symbol. Both are
/// leaked into process-static storage so the `'static` symbol borrow is sound.
struct Unwinder {
    get_stack: Symbol<'static, GetStackFn>,
}

unsafe impl Send for Unwinder {}
unsafe impl Sync for Unwinder {}

static UNWINDER: OnceLock<Result<Unwinder>> = OnceLock::new();

/// Lazily load `libstackplz.so` from `<exec_dir>/preload_libs` and resolve
/// `get_stack`. Errors are cached so we don't retry on every event.
fn unwinder(lib_path: &str) -> &'static Result<Unwinder> {
    UNWINDER.get_or_init(|| load_unwinder(lib_path))
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
    let get_stack: Symbol<'static, GetStackFn> =
        unsafe { static_lib.get(b"get_stack\0") }
            .map_err(|e| anyhow!("dlsym get_stack failed: {}", e))?;
    Ok(Unwinder { get_stack })
}

/// Resolve a stack trace for the given unwind buffer.
///
/// Mirrors Go's `ParseStack(map_buffer, ubuf)` (`chelper.go:11-20`):
/// - `lib_path`: directory containing the extracted `libstackplz.so` + deps
///   (Go's `LibPath`, set to `<exec_dir>/preload_libs` in `init()`).
/// - `map_buffer`: full `/proc/<pid>/maps` text.
/// - `ubuf`: parsed unwind buffer (regs + stack dump).
///
/// Returns the human-readable stack trace (the `Stackinfo` field).
pub fn parse_stack(lib_path: &str, map_buffer: &str, ubuf: &UnwindBuf) -> String {
    let unw = match unwinder(lib_path) {
        Ok(u) => u,
        Err(e) => return format!("<unwinder load failed: {}>", e),
    };

    let dl_path = match CString::new(lib_path) {
        Ok(s) => s,
        Err(_) => return "<invalid lib_path>".into(),
    };
    let map_c = match CString::new(map_buffer) {
        Ok(s) => s,
        Err(_) => return "<invalid map_buffer>".into(),
    };

    // Build the LibArg (abi + regs[33] + size + dyn_size) to pass as unwind_buf.
    let arg: LibArg = ubuf.lib_arg();

    unsafe {
        let stack_ptr = if ubuf.data.is_empty() {
            std::ptr::null_mut()
        } else {
            ubuf.data.as_ptr() as *mut c_void
        };
        let raw = (unw.get_stack)(
            dl_path.as_ptr() as *mut c_char,
            map_c.as_ptr() as *mut c_char,
            ARM64_REG_MASK,
            &arg as *const LibArg as *mut c_void,
            stack_ptr,
        );
        if raw.is_null() {
            return "<get_stack returned null>".into();
        }
        CStr::from_ptr(raw).to_string_lossy().into_owned()
    }
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
}
