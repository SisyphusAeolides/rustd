#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Validate Cargo build targets against installed executable surfaces."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from executable_contract import (
    COMPATIBILITY_BUILD_ALIASES,
    COMPATIBILITY_BUILD_EXECUTABLES,
    COMPATIBILITY_TO_NATIVE,
    EXPECTED_BUILD_EXECUTABLE_COUNT,
    NATIVE_BUILD_ALIASES,
    NATIVE_BUILD_EXECUTABLES,
)


def load_targets(metadata_path: Path) -> dict[str, Path]:
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    repository_manifest = (Path(__file__).resolve().parent.parent / "Cargo.toml").resolve()
    packages = [
        package
        for package in data["packages"]
        if Path(package["manifest_path"]).resolve() == repository_manifest
    ]
    if len(packages) != 1:
        raise ValueError(
            f"expected exactly one repository package, found {len(packages)}"
        )

    targets: dict[str, Path] = {}
    for target in packages[0]["targets"]:
        if "bin" not in target["kind"]:
            continue
        name = target["name"]
        if name in targets:
            raise ValueError(f"duplicate executable target {name}")
        targets[name] = Path(target["src_path"]).resolve()
    return targets


def validate(targets: dict[str, Path]) -> None:
    expected = NATIVE_BUILD_EXECUTABLES | COMPATIBILITY_BUILD_EXECUTABLES
    actual = frozenset(targets)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"executable build inventory mismatch; missing={missing}, extra={extra}")
    if len(targets) != EXPECTED_BUILD_EXECUTABLE_COUNT:
        raise ValueError(
            f"expected {EXPECTED_BUILD_EXECUTABLE_COUNT} build executables, found {len(targets)}"
        )

    for compatibility, native in sorted(COMPATIBILITY_TO_NATIVE.items()):
        # systemctl intentionally has a dedicated compatibility wrapper so it
        # can preserve upstream-visible behavior such as set-property drop-in
        # filenames while rustctl retains native RustD naming.
        if compatibility == "systemctl":
            continue
        compatibility_build = COMPATIBILITY_BUILD_ALIASES.get(
            compatibility, compatibility
        )
        native_build = NATIVE_BUILD_ALIASES.get(native, native)
        if targets[compatibility_build] != targets[native_build]:
            raise ValueError(
                f"{compatibility} and {native} do not use the same source: "
                f"{targets[compatibility_build]} != {targets[native_build]}"
            )

    for installed, build in sorted(NATIVE_BUILD_ALIASES.items()):
        if build not in targets:
            raise ValueError(f"native install alias {installed} references missing build target {build}")
    for installed, build in sorted(COMPATIBILITY_BUILD_ALIASES.items()):
        if build not in targets:
            raise ValueError(
                f"compatibility install alias {installed} references missing build target {build}"
            )

    missing_sources = sorted(
        str(path) for path in set(targets.values()) if not path.is_file()
    )
    if missing_sources:
        raise ValueError(f"missing executable sources: {missing_sources}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    args = parser.parse_args()
    try:
        targets = load_targets(args.metadata)
        validate(targets)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"executable inventory validation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"executable build inventory: {len(NATIVE_BUILD_EXECUTABLES)} native + "
        f"{len(COMPATIBILITY_BUILD_EXECUTABLES)} compatibility targets passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
