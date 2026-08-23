#!/usr/bin/env python3
"""Inventory every installed non-systemd ELF that imports libsystemd/libudev ABI."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path


ABI_SYMBOL = re.compile(r"^(?:sd_|udev_)")


def command(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def rpm_owner(path: Path) -> str | None:
    result = subprocess.run(
        ["rpm", "-qf", "--qf", "%{NAME}", str(path)],
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def undefined_abi_many(paths: list[Path]) -> dict[Path, list[str]]:
    result = subprocess.run(
        ["readelf", "--dynamic", "--dyn-syms", "--wide", *(str(path) for path in paths)],
        capture_output=True,
        text=True,
    )
    found: dict[Path, set[str]] = defaultdict(set)
    needed: dict[Path, set[str]] = defaultdict(set)
    current: Path | None = None
    for line in result.stdout.splitlines():
        if line.startswith("File: "):
            current = Path(line.removeprefix("File: "))
            continue
        if current is None:
            continue
        if "(NEEDED)" in line and "Shared library: [" in line:
            needed[current].add(line.split("Shared library: [", 1)[1].split("]", 1)[0])
            continue
        fields = line.split()
        if len(fields) < 8 or "UND" not in fields:
            continue
        symbol = fields[-2] if fields[-1].startswith("(") else fields[-1]
        symbol = symbol.replace("@@", "@", 1)
        if ABI_SYMBOL.match(symbol):
            found[current].add(symbol)
    filtered: dict[Path, list[str]] = {}
    for path, symbols in found.items():
        libraries = needed[path]
        selected = {
            symbol
            for symbol in symbols
            if (symbol.startswith("sd_") and "libsystemd.so.0" in libraries)
            or (symbol.startswith("udev_") and "libudev.so.1" in libraries)
        }
        if selected:
            filtered[path] = sorted(selected)
    return filtered


def elf_files(roots: list[Path]):
    for root in roots:
        for directory, _, names in os.walk(root):
            for name in names:
                path = Path(directory, name)
                try:
                    mode = path.stat().st_mode
                    # ABI consumers are executables or dynamically loadable
                    # objects. Avoid invoking readelf on data, debug payloads,
                    # firmware, archives, and the rest of a full /usr tree.
                    if not (mode & 0o111) and ".so" not in name:
                        continue
                    with path.open("rb") as stream:
                        if stream.read(4) == b"\x7fELF":
                            yield path
                except (OSError, PermissionError):
                    continue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--root", action="append", type=Path, default=[])
    args = parser.parse_args()
    roots = args.root or [Path("/usr")]

    packages: dict[str, list[dict[str, object]]] = defaultdict(list)
    required: set[str] = set()
    candidates = list(elf_files(roots))
    for offset in range(0, len(candidates), 256):
        for path, symbols in undefined_abi_many(candidates[offset : offset + 256]).items():
            owner = rpm_owner(path)
            if owner is None or owner == "systemd" or owner.startswith("systemd-"):
                continue
            packages[owner].append({"path": str(path), "symbols": symbols})
            required.update(symbols)

    report = {
        "schema": "rustd-installed-elf-abi-audit-v1",
        "systemd_evr": command("rpm", "-q", "--qf", "%{EVR}", "systemd"),
        "systemd_libraries_evr": command(
            "rpm", "-q", "--qf", "%{EVR}", "systemd-libs"
        ),
        "consumer_count": sum(len(items) for items in packages.values()),
        "required_symbol_count": len(required),
        "required_symbols": sorted(required),
        "packages": [
            {"name": name, "elf_consumers": sorted(items, key=lambda item: item["path"])}
            for name, items in sorted(packages.items())
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"installed ELF ABI audit: {report['consumer_count']} consumers, "
        f"{report['required_symbol_count']} versioned symbols, {len(packages)} packages"
    )
    print(f"report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
