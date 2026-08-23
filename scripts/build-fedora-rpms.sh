#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build an exact RustD + RustD-Resolved Fedora RPM set from clean source trees.
set -Eeuo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESOLVED_ROOT="${RUSTD_RESOLVED_SOURCE_ROOT:-${SOURCE_ROOT}/../rustd-resolved}"
OUTPUT="${RUSTD_FEDORA_RPM_OUTPUT:-${SOURCE_ROOT}/target/fedora-rpms}"
TOPDIR="${RUSTD_FEDORA_RPM_TOPDIR:-${SOURCE_ROOT}/target/fedora-rpmbuild}"

fail() { printf 'Fedora RPM build: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"; }

for command in git cargo tar gzip sha256sum rpmbuild rpm python3; do need "$command"; done
[[ -d "$RESOLVED_ROOT/.git" ]] || fail "rustd-resolved checkout not found: $RESOLVED_ROOT"

rustd_sha="$(git -C "$SOURCE_ROOT" rev-parse HEAD)"
resolved_sha="$(git -C "$RESOLVED_ROOT" rev-parse HEAD)"
pinned_resolved="$(tr -d '[:space:]' < "$SOURCE_ROOT/scripts/rustd-resolved-revision.txt")"
[[ "$resolved_sha" == "$pinned_resolved" ]] \
    || fail "resolver checkout $resolved_sha does not match RustD pin $pinned_resolved"
[[ -z "$(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=normal)" ]] \
    || fail "RustD checkout must be clean"
[[ -z "$(git -C "$RESOLVED_ROOT" status --porcelain --untracked-files=normal)" ]] \
    || fail "rustd-resolved checkout must be clean"

rustd_version="$(python3 - "$SOURCE_ROOT/Cargo.toml" <<'PY'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text()
m=re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
assert m
print(m.group(1))
PY
)"
resolved_version="$(python3 - "$RESOLVED_ROOT/Cargo.toml" <<'PY'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text()
m=re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
assert m
print(m.group(1))
PY
)"

rm -rf "$TOPDIR" "$OUTPUT"
mkdir -p "$TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$OUTPUT"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT HUP INT TERM

make_source() {
    local repo=$1 sha=$2 name=$3 version=$4 dest=$5
    local tree="$work/$name-$version"
    local epoch
    epoch="$(git -C "$repo" show -s --format=%ct "$sha")"
    mkdir -p "$tree"
    git -C "$repo" archive "$sha" | tar -xf - -C "$tree"
    (
        cd "$tree"
        # Vendor registry dependencies into a dedicated directory. Existing
        # project-owned vendor trees remain part of the source archive and
        # Cargo's generated source replacement config points only at vendor-rpm
        # for registry crates.
        cargo vendor --locked vendor-rpm > /tmp/rustd-cargo-vendor-config.$$
        mkdir -p .cargo
        cp /tmp/rustd-cargo-vendor-config.$$ .cargo/config.toml
        rm -f /tmp/rustd-cargo-vendor-config.$$
    )
    tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
        -C "$work" -cf - "$name-$version" | gzip -n -9 > "$dest"
}

rustd_tar="$TOPDIR/SOURCES/rustd-$rustd_version.tar.gz"
resolved_tar="$TOPDIR/SOURCES/rustd-resolved-$resolved_version.tar.gz"
make_source "$SOURCE_ROOT" "$rustd_sha" rustd "$rustd_version" "$rustd_tar"
make_source "$RESOLVED_ROOT" "$resolved_sha" rustd-resolved "$resolved_version" "$resolved_tar"

cp "$SOURCE_ROOT/dist/fedora/rustd.spec" "$TOPDIR/SPECS/"
cp "$SOURCE_ROOT/dist/fedora/rustd-fedora-compat.spec" "$TOPDIR/SPECS/"
cp "$SOURCE_ROOT/dist/fedora/rustd-compat-libs.spec" "$TOPDIR/SPECS/"
cp "$SOURCE_ROOT/dist/fedora/rustd-selinux.spec" "$TOPDIR/SPECS/"
cp "$RESOLVED_ROOT/dist/fedora/rustd-resolved.spec" "$TOPDIR/SPECS/"

systemd_evr="$(rpm -q --qf '%{EVR}' systemd 2>/dev/null || true)"
systemd_libs_evr="$(rpm -q --qf '%{EVR}' systemd-libs 2>/dev/null || true)"
systemd_udev_evr="$(rpm -q --qf '%{EVR}' systemd-udev 2>/dev/null || true)"
[[ -n "$systemd_evr" && -n "$systemd_libs_evr" && -n "$systemd_udev_evr" ]] \
    || fail "systemd, systemd-libs, and systemd-udev must be installed while building replacement RPM metadata"
[[ "$systemd_evr" == "$systemd_libs_evr" && "$systemd_evr" == "$systemd_udev_evr" ]] \
    || fail "Fedora systemd capability EVRs differ: manager=$systemd_evr libs=$systemd_libs_evr udev=$systemd_udev_evr"

rpmbuild_common=(--define "_topdir $TOPDIR")
rpmbuild -ba "${rpmbuild_common[@]}" "$TOPDIR/SPECS/rustd.spec"
rpmbuild -ba "${rpmbuild_common[@]}" "$TOPDIR/SPECS/rustd-selinux.spec"
rpmbuild -ba "${rpmbuild_common[@]}" \
    --define "systemd_compat_evr $systemd_evr" \
    "$TOPDIR/SPECS/rustd-fedora-compat.spec"
rpmbuild -ba "${rpmbuild_common[@]}" \
    --define "systemd_compat_evr $systemd_evr" \
    "$TOPDIR/SPECS/rustd-compat-libs.spec"
rpmbuild -ba "${rpmbuild_common[@]}" \
    --define "systemd_compat_evr $systemd_evr" \
    "$TOPDIR/SPECS/rustd-resolved.spec"

find "$TOPDIR/RPMS" -type f -name '*.rpm' -exec cp -a {} "$OUTPUT/" \;
find "$TOPDIR/SRPMS" -type f -name '*.src.rpm' -exec cp -a {} "$OUTPUT/" \;

compat_rpm=$(find "$OUTPUT" -maxdepth 1 -type f \
    -name 'rustd-fedora-compat-*.rpm' ! -name '*.src.rpm' | head -1)
[[ -n $compat_rpm ]]
compat_provides=$(rpm -qp --provides "$compat_rpm")
for capability in \
    "systemd = $systemd_evr" \
    "systemd-udev = $systemd_evr" \
    "systemd-pam = $systemd_evr" \
    "systemd-units = $systemd_evr" \
    "systemd-sysusers = $systemd_evr" \
    "systemd-standalone-sysusers = $systemd_evr" \
    "systemd-tmpfiles = $systemd_evr" \
    "systemd-standalone-tmpfiles = $systemd_evr" \
    'systemd-sysv = 206'; do
    grep -Fxq "$capability" <<<"$compat_provides"
done
grep -Eq "^systemd\([^)]*\) = ${systemd_evr//./\\.}$" <<<"$compat_provides"
grep -Eq "^systemd-udev\([^)]*\) = ${systemd_evr//./\\.}$" <<<"$compat_provides"
grep -Eq "^systemd-pam\([^)]*\) = ${systemd_evr//./\\.}$" <<<"$compat_provides"
grep -Eq "^udev\([^)]*\) = ${systemd_evr//./\\.}$" <<<"$compat_provides"
grep -Fxq "udev = $systemd_evr" <<<"$compat_provides"

resolved_rpm=$(find "$OUTPUT" -maxdepth 1 -type f \
    -name 'rustd-resolved-*.rpm' ! -name '*-nss-*' ! -name '*-debug*' \
    ! -name '*.src.rpm' | head -1)
[[ -n $resolved_rpm ]]
resolved_provides=$(rpm -qp --provides "$resolved_rpm")
grep -Fxq "systemd-resolved = $systemd_evr" <<<"$resolved_provides"
grep -Eq "^systemd-resolved\([^)]*\) = ${systemd_evr//./\\.}$" \
    <<<"$resolved_provides"

manifest="$OUTPUT/manifest.txt"
{
    printf 'schema=rustd-fedora-rpm-set-v1\n'
    printf 'rustd_sha=%s\n' "$rustd_sha"
    printf 'resolved_sha=%s\n' "$resolved_sha"
    printf 'rustd_version=%s\n' "$rustd_version"
    printf 'resolved_version=%s\n' "$resolved_version"
    printf 'systemd_reference_evr=%s\n' "$systemd_evr"
    printf 'systemd_libraries_reference_evr=%s\n' "$systemd_libs_evr"
    printf 'systemd_udev_reference_evr=%s\n' "$systemd_udev_evr"
    printf 'source.rustd.sha256=%s\n' "$(sha256sum "$rustd_tar" | awk '{print $1}')"
    printf 'source.resolved.sha256=%s\n' "$(sha256sum "$resolved_tar" | awk '{print $1}')"
    while IFS= read -r rpm_path; do
        printf 'rpm.%s.sha256=%s\n' "$(basename "$rpm_path")" "$(sha256sum "$rpm_path" | awk '{print $1}')"
    done < <(find "$OUTPUT" -maxdepth 1 -type f -name '*.rpm' | sort)
} > "$manifest"

printf 'Fedora RPM set built for RustD %s + RustD-Resolved %s\n' "$rustd_sha" "$resolved_sha"
printf 'Output: %s\n' "$OUTPUT"
