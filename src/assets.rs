//! Embedded asset extraction. Mirrors the generated `stackplz/assets` package
//! (go-bindata output) used for `--prepare` / first-run lib extraction.
//!
//! The preload `.so` files are embedded at compile time via `include_bytes!`
//! and written to `<exec_dir>/preload_libs/` at runtime. This replaces
//! `assets.RestoreAssets(ExecPath, "preload_libs")`.

use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// One embedded preload library.
struct EmbeddedLib {
    name: &'static str,
    bytes: &'static [u8],
}

/// The full list of bundled preload libs. Mirrors the 9 files in
/// `assets/preload_libs/`.
const PRELOAD_LIBS: &[EmbeddedLib] = &[
    EmbeddedLib {
        name: "ld-android.so",
        bytes: include_bytes!("../assets/preload_libs/ld-android.so"),
    },
    EmbeddedLib {
        name: "libbase.so",
        bytes: include_bytes!("../assets/preload_libs/libbase.so"),
    },
    EmbeddedLib {
        name: "libc++.so",
        bytes: include_bytes!("../assets/preload_libs/libc++.so"),
    },
    EmbeddedLib {
        name: "libdl.so",
        bytes: include_bytes!("../assets/preload_libs/libdl.so"),
    },
    EmbeddedLib {
        name: "liblog.so",
        bytes: include_bytes!("../assets/preload_libs/liblog.so"),
    },
    EmbeddedLib {
        name: "liblzma.so",
        bytes: include_bytes!("../assets/preload_libs/liblzma.so"),
    },
    EmbeddedLib {
        name: "libm.so",
        bytes: include_bytes!("../assets/preload_libs/libm.so"),
    },
    EmbeddedLib {
        name: "libstackplz.so",
        bytes: include_bytes!("../assets/preload_libs/libstackplz.so"),
    },
    EmbeddedLib {
        name: "libunwindstack.so",
        bytes: include_bytes!("../assets/preload_libs/libunwindstack.so"),
    },
];

/// Extract all embedded preload libs to `<exec_dir>/preload_libs/`.
/// Mirrors `assets.RestoreAssets(ExecPath, "preload_libs")`.
pub fn restore_assets(exec_dir: &str, subdir: &str) -> Result<()> {
    let dir = PathBuf::from(exec_dir).join(subdir);
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("create {} failed: {}", dir.display(), e))?;
    for lib in PRELOAD_LIBS {
        let target = dir.join(lib.name);
        std::fs::write(&target, lib.bytes)
            .map_err(|e| anyhow!("write {} failed: {}", target.display(), e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_nine_libs_embedded() {
        assert_eq!(
            PRELOAD_LIBS.len(),
            9,
            "expected 9 preload libs to match the Go tree"
        );
        let names: Vec<&str> = PRELOAD_LIBS.iter().map(|l| l.name).collect();
        assert!(names.contains(&"libstackplz.so"));
        assert!(names.contains(&"libunwindstack.so"));
    }

    #[test]
    fn embedded_libs_are_elf() {
        for lib in PRELOAD_LIBS {
            // ELF magic.
            assert_eq!(&lib.bytes[..4], b"\x7fELF", "{} is not an ELF", lib.name);
        }
    }

    #[test]
    fn restore_assets_writes_files() {
        let tmp = std::env::temp_dir().join("stackplz_restore_test");
        let _ = std::fs::remove_dir_all(&tmp);
        restore_assets(tmp.to_str().unwrap(), "preload_libs").unwrap();
        let p = tmp.join("preload_libs/libstackplz.so");
        assert!(p.exists());
        assert_eq!(&std::fs::read(&p).unwrap()[..4], b"\x7fELF");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
