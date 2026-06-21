#!/usr/bin/env bash
# Fetch the build-time dependencies for the dev-branch eBPF programs.
# Mirrors `build_env.sh` from the upstream Go project (dev branch).
#
# The dev eBPF tree (ebpf/) is self-contained: it vendors the libbpf helper
# headers (ebpf/bpf/*) and the CO-RE BTF definitions (ebpf/vmlinux_510.h), so
# the only external dependency is `libbpf/src/bpf_helpers.h`. CO-RE relocation
# at load time additionally needs a minimized BTF per target kernel, generated
# by `bpftool gen min_core_btf`.
#
# Run once on a Linux host (or in CI). Produces:
#   libbpf/                 libbpf source (for -I libbpf/src)
#   assets/bpftool          the bpftool binary
#   assets/*.btf            full BTF for two reference kernels
#   assets/*_min.btf        minimized BTF (one per .o per kernel)
set -euo pipefail

BPFTOOL_VERSION="v7.2.0-snapshot.0"
BPFTOOL_TARBALL="bpftool-${BPFTOOL_VERSION}-amd64.tar.gz"

mkdir -p assets
mkdir -p libbpf

clone() {
    local url="$1"; local dest="$2"
    if [ -d "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
        echo "skip (exists): $dest"
        return
    fi
    echo "cloning $url -> $dest"
    git clone --depth 1 "$url" "$dest"
}

# 1) libbpf source (headers consumed at -I libbpf/src).
clone https://github.com/libbpf/libbpf libbpf

# 2) bpftool binary (for `gen min_core_btf`).
if [ ! -x assets/bpftool ]; then
    (
        cd assets
        wget -O "$BPFTOOL_TARBALL" \
            "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/${BPFTOOL_TARBALL}"
        tar -zxvf "$BPFTOOL_TARBALL"
        rm -f "$BPFTOOL_TARBALL"
        chmod +x bpftool
    )
fi

# 3) Reference kernel BTFs (Android 12 / 5.10 + rock5b / 5.10).
fetch_btf() {
    local name="$1"
    local out="$2"
    if [ -f "$out" ]; then
        echo "skip (exists): $out"
        return
    fi
    local tarxz="${name}.tar.xz"
    wget -O "$tarxz" \
        "https://github.com/SeeFlowerX/BTFHubForAndroid/raw/master/${name}.tar.xz"
    tar -xvf "$tarxz" -C assets
    rm -f "$tarxz"
}
fetch_btf common-android12-5.10/a12-5.10-arm64 assets/a12-5.10-arm64.btf
fetch_btf rock5b/rock5b-5.10-f9d1b1529-arm64 assets/rock5b-5.10-f9d1b1529-arm64.btf

# 4) Generate minimized BTF per kernel, per eBPF object (after a successful
#    `cargo build` that produced ebpf/bpf/{stack,syscall}.o). Skipped if the
#    objects don't exist yet — build the crate first, then re-run.
if [ -f ebpf/bpf/stack.o ] && [ -f ebpf/bpf/syscall.o ]; then
    # bpftool resolves the .o paths relative to CWD; run from the repo root so
    # the assets/ BTF and ebpf/bpf/*.o paths both resolve.
    assets/bpftool gen min_core_btf \
        assets/rock5b-5.10-f9d1b1529-arm64.btf assets/rock5b-5.10-arm64_min.btf \
        ebpf/bpf/stack.o ebpf/bpf/syscall.o || true
    assets/bpftool gen min_core_btf \
        assets/a12-5.10-arm64.btf assets/a12-5.10-arm64_min.btf \
        ebpf/bpf/stack.o ebpf/bpf/syscall.o || true
else
    echo "note: ebpf/bpf/*.o not built yet; build the crate first, then re-run to gen min BTF."
fi

echo "done. libbpf + assets ready."
