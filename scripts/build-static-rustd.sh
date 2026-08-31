#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_spec=${RUSTD_STATIC_TARGET_SPEC:-$root/config/x86_64-static-linux.json}
target_dir=${RUSTD_STATIC_TARGET_DIR:-$root/build/static-rustd}
toolchain=${RUSTD_STATIC_TOOLCHAIN:-nightly-2026-07-20}
cargo_bin=${CARGO:-cargo}

fail() { printf 'RustD static build: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }

for command in "$cargo_bin" readelf file; do need "$command"; done
[[ -f $target_spec ]] || fail "target specification is missing: $target_spec"

mkdir -p "$target_dir"
export RUSTUP_TOOLCHAIN="$toolchain"
export RUSTC_WRAPPER=
export CARGO_TARGET_DIR="$target_dir"
if [[ -n ${RUSTFLAGS:-} ]]; then
    export RUSTFLAGS="$RUSTFLAGS -C target-feature=+crt-static"
else
    export RUSTFLAGS='-C target-feature=+crt-static'
fi

"$cargo_bin" build \
    --locked \
    --release \
    --all-features \
    --bin rustd \
    --manifest-path "$root/Cargo.toml" \
    --target "$target_spec" \
    -Z json-target-spec \
    -Z build-std=std,panic_abort \
    -Z build-std-features=compiler-builtins-mem

image="$target_dir/x86_64-static-linux/release/rustd"
[[ -s $image ]] || fail "static RustD image is missing or empty: $image"
readelf -hW "$image" | grep -Fq 'Type:                              DYN' \
    || fail "RustD image is not a position-independent ELF executable: $image"
if readelf -lW "$image" | grep -Fq ' INTERP '; then
    fail "RustD image has a dynamic loader and cannot be PID 1: $image"
fi

printf 'RustD static image: %s\n' "$image"
file "$image"
