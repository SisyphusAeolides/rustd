#!/usr/bin/env python3
"""Fail unless RustD has complete measured ABI closure and no systemd dependency."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

SYSTEMD_INCLUDE = re.compile(r"#\s*include\s*[<\"]systemd/")
SYSTEMD_NEEDED = re.compile(r"\bNEEDED\b.*\blibsystemd\.so")
EXPECTED_REQUIRED = 338


def fail(message: str) -> None:
    raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness", type=Path, default=Path("target/compat-readiness.json"))
    parser.add_argument("--libsystemd", type=Path, default=Path("build/libs/libsystemd.so.0"))
    parser.add_argument("--libudev", type=Path, default=Path("build/libs/libudev.so.1"))
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    readiness_path = args.readiness if args.readiness.is_absolute() else root / args.readiness
    report = json.loads(readiness_path.read_text(encoding="utf-8"))

    required = int(report.get("required", -1))
    supported = int(report.get("supported", -1))
    unsupported = int(report.get("unsupported", -1))
    missing = int(report.get("missing_source_definition", -1))
    if required != EXPECTED_REQUIRED:
        fail(f"measured ABI inventory changed: expected {EXPECTED_REQUIRED}, got {required}")
    if supported != EXPECTED_REQUIRED or unsupported != 0 or missing != 0 or not report.get("complete"):
        fail(
            f"ABI closure incomplete: {supported}/{required} supported, "
            f"{unsupported} unsupported, {missing} missing"
        )

    source_roots = [root / "libs", root / "include", root / "ffi", root / "src"]
    offenders: list[str] = []
    for source_root in source_roots:
        if not source_root.exists():
            continue
        for path in source_root.rglob("*"):
            if not path.is_file() or path.suffix not in {".c", ".h", ".rs", ".cc", ".cpp", ".hpp"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if SYSTEMD_INCLUDE.search(text):
                offenders.append(str(path.relative_to(root)))
    if offenders:
        fail("systemd development headers remain: " + ", ".join(sorted(offenders)))

    for raw in (args.libsystemd, args.libudev):
        library = raw if raw.is_absolute() else root / raw
        result = subprocess.run(
            ["readelf", "-d", str(library)],
            check=True,
            capture_output=True,
            text=True,
        )
        if SYSTEMD_NEEDED.search(result.stdout):
            fail(f"{library}: runtime dependency on libsystemd remains")

    stub = root / "libs/compat/sd_bus_stubs.c"
    if stub.exists():
        text = stub.read_text(encoding="utf-8")
        if "rustd_bus_enosys" in text or "ENOSYS" in text:
            fail("sd-bus fail-closed stubs remain in the release tree")

    print(
        f"release closure: {supported}/{required} ABI symbols supported, "
        "0 unsupported, 0 missing, no systemd headers/runtime linkage"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"release closure: {error}", file=sys.stderr)
        raise SystemExit(1) from error
