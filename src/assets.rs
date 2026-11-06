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
    // Android 10- (SDK <= 29) build of the same library. Upstream embeds it and
    // `RestoreAssets` renames it over `libstackplz.so` on old SDKs
    // (`user/config/config_global.go:76-96`). Missing here before round 3, so
    // `--sdk-int` had nothing to select (report W15).
    EmbeddedLib {
        name: "libstackplz10.so",
        bytes: include_bytes!("../assets/preload_libs/libstackplz10.so"),
    },
    EmbeddedLib {
        name: "libunwindstack.so",
        bytes: include_bytes!("../assets/preload_libs/libunwindstack.so"),
    },
];

/// Pick the `libstackplz.so` flavour for the target SDK.
///
/// Mirrors `GlobalConfig.RestoreAssets` (`user/config/config_global.go:76-96`):
/// SDK `<= 29` (Android 10 and older) uses `libstackplz10.so`, renamed over
/// `libstackplz.so` after extraction; `sdk_int == 0` defaults to 29.
pub fn preload_lib_for_sdk(sdk_int: u32) -> &'static str {
    if sdk_int == 0 || sdk_int <= 29 {
        "libstackplz10.so"
    } else {
        "libstackplz.so"
    }
}

/// `GetSdkInt()` (`cli/cmd/root.go:586-601`): read `ro.build.version.sdk`, and
/// fall back to 29 when `getprop` is unavailable or unparseable.
pub fn get_sdk_int() -> u32 {
    const DEFAULT_SDK_INT: u32 = 29;
    let output = std::process::Command::new("getprop")
        .arg("ro.build.version.sdk")
        .output();
    match output {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            let text = text.trim();
            if text.is_empty() {
                return DEFAULT_SDK_INT;
            }
            text.parse().unwrap_or(DEFAULT_SDK_INT)
        }
        Err(_) => DEFAULT_SDK_INT,
    }
}

/// Extract all embedded preload libs to `<exec_dir>/preload_libs/`.
/// Mirrors `assets.RestoreAssets(ExecPath, "preload_libs")`.
///
/// The SDK-specific `libstackplz10.so` is always written; [`restore_assets_for_sdk`]
/// additionally renames it over `libstackplz.so` on old SDKs, which is what
/// upstream does and which is why the file must not be written under its own
/// name only.
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

/// Extract the preload libs and select the SDK-appropriate `libstackplz.so`.
///
/// Mirrors `GlobalConfig.RestoreAssets` (`config_global.go:76-96`): on
/// `sdk_int <= 29` the Android-10 build replaces `libstackplz.so`. Returns the
/// library name that ended up as `libstackplz.so`.
pub fn restore_assets_for_sdk(exec_dir: &str, subdir: &str, sdk_int: u32) -> Result<&'static str> {
    restore_assets(exec_dir, subdir)?;
    let chosen = preload_lib_for_sdk(sdk_int);
    if chosen != "libstackplz.so" {
        let dir = PathBuf::from(exec_dir).join(subdir);
        std::fs::rename(dir.join(chosen), dir.join("libstackplz.so"))
            .map_err(|e| anyhow!("rename {} failed: {}", chosen, e))?;
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ten_libs_embedded() {
        assert_eq!(
            PRELOAD_LIBS.len(),
            10,
            "9 upstream libs + the Android 10 libstackplz10.so"
        );
        let names: Vec<&str> = PRELOAD_LIBS.iter().map(|l| l.name).collect();
        assert!(names.contains(&"libstackplz.so"));
        assert!(names.contains(&"libstackplz10.so"));
        assert!(names.contains(&"libunwindstack.so"));
    }

    /// Report W15: `--sdk-int` must actually select the Android 10 library.
    #[test]
    fn sdk_int_selects_the_android10_library() {
        assert_eq!(
            preload_lib_for_sdk(0),
            "libstackplz10.so",
            "0 defaults to 29"
        );
        assert_eq!(preload_lib_for_sdk(28), "libstackplz10.so");
        assert_eq!(preload_lib_for_sdk(29), "libstackplz10.so");
        assert_eq!(preload_lib_for_sdk(30), "libstackplz.so");
        assert_eq!(preload_lib_for_sdk(34), "libstackplz.so");
    }

    #[test]
    fn restore_for_old_sdk_renames_the_android10_build() {
        let tmp = std::env::temp_dir().join("stackplz_restore_sdk_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let chosen = restore_assets_for_sdk(tmp.to_str().unwrap(), "preload_libs", 28).unwrap();
        assert_eq!(chosen, "libstackplz10.so");
        let lib = tmp.join("preload_libs/libstackplz.so");
        assert!(lib.exists(), "libstackplz.so must exist after the rename");
        // The Android-10 build is the bigger of the two (2,001,016 vs 597,904).
        assert!(std::fs::metadata(&lib).unwrap().len() > 1_000_000);
        let _ = std::fs::remove_dir_all(&tmp);
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
