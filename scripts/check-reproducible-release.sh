#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT/target/reproducibility}"
WORK="$(mktemp -d -t rustd-reproducible.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

for command in cargo git make gzip sha256sum stat sort find cmp readlink rustc cc gfortran python3; do
    command -v "$command" >/dev/null || {
        printf 'required command is missing: %s\n' "$command" >&2
        exit 2
    }
done

SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" show -s --format=%ct HEAD)}"
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
# Cargo builds several native executables from shared source files. Keep this
# release proof single-threaded by default so link scheduling cannot become an
# input to the artifact order; callers may override the job count explicitly
# when diagnosing a toolchain.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export LC_ALL=C
export TZ=UTC
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$ROOT=/usr/src/rustd"
export RUSTFLAGS

rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"

mapfile -t NATIVE_BUILD_EXECUTABLES < <(
    PYTHONPATH="$ROOT/scripts" python3 - <<'PY'
from executable_contract import NATIVE_BUILD_EXECUTABLES

for name in sorted(NATIVE_BUILD_EXECUTABLES):
    print(name)
PY
)
if [[ "${#NATIVE_BUILD_EXECUTABLES[@]}" -eq 0 ]]; then
    printf '%s\n' 'native RustD executable contract is empty' >&2
    exit 2
fi

build_once() {
    local label=$1
    local target_dir="$WORK/target-$label"
    local install_root="$WORK/root-$label"
    local artifact_manifest="$OUTPUT/artifacts-$label.sha256"
    local package_manifest="$OUTPUT/package-$label.manifest"
    local path_manifest="$WORK/paths-$label.txt"

    make -C "$ROOT" build TARGET_DIR="$target_dir"
    make -C "$ROOT" install TARGET_DIR="$target_dir" DESTDIR="$install_root"

    (
        cd "$target_dir/release"
        sha256sum "${NATIVE_BUILD_EXECUTABLES[@]}" | sort -k2
    ) >"$artifact_manifest"

    (
        cd "$install_root"
        find . \( -type f -o -type l \) -printf '%P\n' | sort
    ) >"$path_manifest"

    : >"$package_manifest"
    while IFS= read -r relative; do
        local file="$install_root/$relative"
        if [[ -L "$file" ]]; then
            printf 'link %s %s\n' "$(readlink "$file")" "$relative" >>"$package_manifest"
        else
            local mode
            local digest
            mode="$(stat -c '%a' "$file")"
            digest="$(sha256sum "$file" | awk '{print $1}')"
            printf '%s %s %s\n' "$mode" "$digest" "$relative" >>"$package_manifest"
        fi
    done <"$path_manifest"
}

build_once first
build_once second

cmp "$WORK/paths-first.txt" "$WORK/paths-second.txt"
cmp "$OUTPUT/artifacts-first.sha256" "$OUTPUT/artifacts-second.sha256"
cmp "$OUTPUT/package-first.manifest" "$OUTPUT/package-second.manifest"

{
    printf 'source_commit=%s\n' "$SOURCE_COMMIT"
    printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
    printf 'native_build_executables=%s\n' "${#NATIVE_BUILD_EXECUTABLES[@]}"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'cc=%s\n' "$(cc --version | head -n1)"
    printf 'gfortran=%s\n' "$(gfortran --version | head -n1)"
} >"$OUTPUT/build-environment.txt"

printf 'reproducible release artifacts and install manifest verified for %s\n' "$SOURCE_COMMIT"
