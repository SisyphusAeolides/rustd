#!/usr/bin/env python3
"""Report source-level readiness of the RustD libsystemd/libudev compatibility ABI."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys


def load_closure_module(root: Path):
    path = root / "scripts" / "check-compat-closure.py"
    spec = importlib.util.spec_from_file_location("rustd_compat_closure", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--needed",
        type=Path,
        default=Path("libs/compat/needed_syms.txt"),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("target/compat-readiness.json"),
    )
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    closure = load_closure_module(root)
    needed_path = args.needed if args.needed.is_absolute() else root / args.needed
    required = {
        line.strip()
        for line in needed_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    source_functions: set[str] = set()
    for relative in (
        Path("libs/compat/systemd.c"),
        Path("libs/compat/sd_bus_stubs.c"),
        Path("libs/compat/udev.c"),
    ):
        source = (root / relative).read_text(encoding="utf-8")
        source_functions.update(match.group(1) for match in closure.FUNCTION.finditer(source))

    source_exports = source_functions | set(closure.DATA_SYMBOLS)
    missing = sorted(required - source_exports)
    unsupported_exports = closure.unsupported_symbols(root)
    unsupported = sorted(required & unsupported_exports)
    supported = sorted(required - set(missing) - set(unsupported))

    report = {
        "required": len(required),
        "supported": len(supported),
        "unsupported": len(unsupported),
        "missing_source_definition": len(missing),
        "supported_symbols": supported,
        "unsupported_symbols": unsupported,
        "missing_symbols": missing,
        "complete": not missing and not unsupported,
    }
    report_path = args.report if args.report.is_absolute() else root / args.report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        "compat source readiness: "
        f"{len(supported)}/{len(required)} behaviorally supported, "
        f"{len(unsupported)} unsupported, {len(missing)} missing"
    )
    for symbol in unsupported:
        print(f"UNSUPPORTED {symbol}")
    for symbol in missing:
        print(f"MISSING {symbol}")
    print(f"report: {report_path}")

    if args.require_complete and not report["complete"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
