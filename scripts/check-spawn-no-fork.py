#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail when production spawn sources call fork()."""

from __future__ import annotations

import pathlib
import re
import sys


def code_without_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    pattern = re.compile(r"(?<![A-Za-z0-9_])fork\s*\(")
    sources = {
        "ffi/spawn.c": (root / "ffi/spawn.c").read_text(encoding="utf-8"),
        "ffi/spawn_helper.c": (root / "ffi/spawn_helper.c").read_text(encoding="utf-8"),
    }
    for path, text in sources.items():
        if pattern.search(code_without_comments(text)):
            print(f"{path} contains a fork() call", file=sys.stderr)
            return 1

    match = re.search(
        r"(?ms)^pid_t\s+rustd_spawn\([^)]*\)\s*\{.*?^\}",
        sources["ffi/spawn.c"],
    )
    if match is None:
        print("rustd_spawn definition missing", file=sys.stderr)
        return 1
    body = match.group(0)
    if pattern.search(code_without_comments(body)):
        print("production rustd_spawn must not call fork", file=sys.stderr)
        return 1
    if "spawn_helper_image" not in body:
        print("rustd_spawn must launch through spawn_helper_image", file=sys.stderr)
        return 1
    if "posix_spawn" not in code_without_comments(sources["ffi/spawn.c"]):
        print("ffi/spawn.c must use posix_spawn", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
