#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Install the native RustD executable surface."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

from executable_contract import NATIVE_BUILD_ALIASES, NATIVE_EXECUTABLES, NATIVE_LIBEXEC


def destination(root: Path, absolute: Path) -> Path:
    return root / absolute.relative_to("/")


def install_executable(source: Path, target: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"missing built executable: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(0o755)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-directory", type=Path, required=True)
    parser.add_argument("--destdir", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, default=Path("/usr"))
    parser.add_argument(
        "--native-libexec-directory", type=Path, default=Path("/usr/lib/rustd")
    )
    args = parser.parse_args()

    if not args.destdir.is_absolute() or args.destdir == Path("/"):
        print("DESTDIR must be an absolute, non-root staging directory", file=sys.stderr)
        return 64
    for path in (args.prefix, args.native_libexec_directory):
        if not path.is_absolute():
            print(f"installation path must be absolute: {path}", file=sys.stderr)
            return 64

    native_bin_directory = args.prefix / "bin"
    try:
        for native in sorted(NATIVE_EXECUTABLES):
            build_name = NATIVE_BUILD_ALIASES.get(native, native)
            source = args.build_directory / build_name
            install_root = (
                args.native_libexec_directory
                if native in NATIVE_LIBEXEC
                else native_bin_directory
            )
            install_executable(source, destination(args.destdir, install_root / native))
    except OSError as error:
        print(f"executable installation failed: {error}", file=sys.stderr)
        return 1

    print(f"installed {len(NATIVE_EXECUTABLES)} native RustD executables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
