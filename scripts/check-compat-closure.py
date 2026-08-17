#!/usr/bin/env python3
"""Verify rustd-compat exports every versioned symbol required by a host audit."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SYMBOL = re.compile(r"^(sd_|udev_)")


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--libsystemd", required=True, type=Path)
    parser.add_argument("--libudev", required=True, type=Path)
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
    missing = sorted(required - provided)

    print(
        f"compat closure: {len(consumers)} consumers, "
        f"{len(required)} required versioned symbols, {len(missing)} missing"
    )
    for symbol in missing:
        print(f"MISSING {symbol}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
