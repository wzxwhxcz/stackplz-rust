//! Filesystem helpers. Mirrors `FindLib` (`helper.go:142-179`) and
//! `ReadMapsByPid` (`user/event/ievent.go:166-173`).

use anyhow::{anyhow, bail, Result};
use std::collections::HashSet;
use std::path::PathBuf;

/// Resolve a library to a single unambiguous full path.
///
/// Mirrors `util.FindLib(library, library_dirs)` (`helper.go:142-179`):
/// - If `library` starts with `/`, treat it as a full path and require it exist.
/// - Otherwise, join it with each entry of `library_dirs` (deduplicated),
///   `stat` each candidate, and require exactly one hit. Zero matches is an
///   error; two-or-more matches with the same name is an error.
pub fn find_lib(library: &str, library_dirs: &[String]) -> Result<String> {
    if library.starts_with('/') {
        let p = PathBuf::from(library);
        if !p.exists() {
            bail!("library not found: {}", library);
        }
        return Ok(library.to_string());
    }

    let mut hits: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for dir in library_dirs {
        if !seen.insert(dir.clone()) {
            continue;
        }
        let candidate = PathBuf::from(dir).join(library);
        if candidate.exists() {
            hits.push(candidate.to_string_lossy().into_owned());
        }
    }
    match hits.len() {
        0 => bail!("library not found: {}", library),
        1 => Ok(hits.remove(0)),
        n => bail!("find {} libs with the same name", n),
    }
}

/// Read `/proc/{pid}/maps` as a UTF-8 string. Mirrors `ReadMapsByPid`
/// (`ievent.go:166-173`). Returns the raw text; the native unwinder parses it.
pub fn read_maps_by_pid(pid: u32) -> Result<String> {
    let path = format!("/proc/{}/maps", pid);
    std::fs::read_to_string(&path).map_err(|e| anyhow!("read {} failed: {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_lib_absolute_path() {
        // Existing absolute file.
        let p = env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml";
        let r = find_lib(&p, &[]).unwrap();
        assert_eq!(r, p);
    }

    #[test]
    fn find_lib_missing_absolute() {
        assert!(find_lib("/no/such/lib.so", &[]).is_err());
    }

    #[test]
    fn find_lib_by_name_single_hit() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let r = find_lib("Cargo.toml", &[dir.to_string()]).unwrap();
        assert!(r.ends_with("Cargo.toml"));
    }

    #[test]
    fn find_lib_ambiguous_is_error() {
        // Build two temp dirs that both contain a file named the same, so the
        // ambiguity is deterministic regardless of the host layout (CI runners
        // don't have a `../stackplz` sibling).
        let tmp = std::env::temp_dir();
        let a = tmp.join("stackplz_find_lib_a");
        let b = tmp.join("stackplz_find_lib_b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("libsame.so"), b"").unwrap();
        std::fs::write(b.join("libsame.so"), b"").unwrap();
        let dirs = [a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned()];
        let r = find_lib("libsame.so", &dirs);
        assert!(r.is_err(), "expected ambiguity error, got {:?}", r);
        // cleanup so re-runs are clean
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn find_lib_dedup_dirs() {
        let dir = env!("CARGO_MANIFEST_DIR").to_string();
        // Same dir twice should still resolve to one hit.
        let r = find_lib("Cargo.toml", &[dir.clone(), dir]).unwrap();
        assert!(r.ends_with("Cargo.toml"));
    }
}
