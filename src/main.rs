//! stackplz-rs entry point. Mirrors `main.go`.
//!
//! All work happens in [`stackplz::cli::start`]: it parses the single dev-style
//! command, performs the BPF kernel-config check (skippable with `--nocheck`,
//! dev `root.go:109-113`), runs the persistent pre-run and dispatches to the
//! selected module(s).
//!
//! The kernel check used to live here and run unconditionally, which made
//! `--nocheck` a dead flag (report W15).

use stackplz::cli;

fn main() {
    let code = cli::start();
    std::process::exit(code);
}
