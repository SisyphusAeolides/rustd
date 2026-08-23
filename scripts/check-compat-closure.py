#!/usr/bin/env python3
"""Verify rustd-compat behaviorally covers every symbol required by a host audit."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SYMBOL = re.compile(r"^(sd_|udev_)")
FUNCTION = re.compile(
    r"(?m)^[\w\s*]+\b((?:sd_|udev_)[A-Za-z0-9_]+)\s*\([^;]*?\)\s*\{"
)
UNSUPPORTED_MARKERS = ("ENOSYS", "rustd_bus_enosys")
COMPAT_SOURCES = (
    Path("libs/compat/systemd.c"),
    Path("libs/compat/journal_send_impl.c"),
    Path("libs/compat/sd_bus_impl.c"),
    Path("libs/compat/sd_json_varlink_impl.c"),
    Path("libs/compat/sd_varlink_idl_impl.c"),
    Path("libs/compat/udev.c"),
)
DATA_SYMBOLS = {"sd_bus_object_vtable_format"}


def dynamic_symbols(path: Path, *, undefined: bool) -> set[str]:
    result = subprocess.run(
        ["readelf", "--dyn-syms", "--wide", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 8 or ("UND" in fields) != undefined:
            continue
        candidate = fields[-2] if fields[-1].startswith("(") else fields[-1]
        if SYMBOL.match(candidate):
            symbols.add(candidate.replace("@@", "@", 1))
    return symbols


def function_body(source: str, start: int) -> str:
    depth = 1
    cursor = start
    while cursor < len(source) and depth:
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
        cursor += 1
    return source[start:cursor]


def unsupported_symbols(root: Path) -> set[str]:
    unsupported: set[str] = set()
    for relative in COMPAT_SOURCES:
        source = (root / relative).read_text(encoding="utf-8")
        for match in FUNCTION.finditer(source):
            name = match.group(1)
            body = function_body(source, match.end())
            if any(marker in body for marker in UNSUPPORTED_MARKERS):
                unsupported.add(name)
    return unsupported


def unversioned(symbol: str) -> str:
    return symbol.split("@", 1)[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--libsystemd", required=True, type=Path)
    parser.add_argument("--libudev", required=True, type=Path)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="source tree used to reject behaviorally unsupported exports",
    )
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    consumers = {
        Path(item["path"])
        for package in report.get("packages", [])
        for item in package.get("elf_consumers", [])
    }
    required: set[str] = set()
    for consumer in sorted(consumers):
        required.update(dynamic_symbols(consumer, undefined=True))

    provided = dynamic_symbols(args.libsystemd, undefined=False)
    provided.update(dynamic_symbols(args.libudev, undefined=False))
    provided_bases = {unversioned(symbol) for symbol in provided}
    missing = sorted(
        symbol
        for symbol in required
        if symbol not in provided
        and not ("@" not in symbol and unversioned(symbol) in provided_bases)
    )

    unsupported_exports = unsupported_symbols(args.repository_root)
    unsupported = sorted(
        symbol for symbol in required if unversioned(symbol) in unsupported_exports
    )

    print(
        f"compat closure: {len(consumers)} consumers, "
        f"{len(required)} required versioned symbols, {len(missing)} missing, "
        f"{len(unsupported)} unsupported"
    )
    for symbol in missing:
        print(f"MISSING {symbol}")
    for symbol in unsupported:
        print(f"UNSUPPORTED {symbol}")

    return 1 if missing or unsupported else 0


if __name__ == "__main__":
    sys.exit(main())
