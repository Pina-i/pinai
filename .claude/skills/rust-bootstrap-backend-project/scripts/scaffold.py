#!/usr/bin/env python3
"""Scaffold a layered Rust backend service from the skill's template.

Usage:
  scaffold.py <target-dir> --name <service> [--member]

  <target-dir>  where the service is created; must not exist or be empty
  --name        kebab-case service name: crate prefix and binary name (e.g. chat-server)
  --member      the service joins an existing Cargo workspace: skip the workspace
                Cargo.toml, Makefile and .gitignore, and print what to merge instead
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / "assets" / "template"
PLACEHOLDER = "__SERVICE__"
WORKSPACE_ONLY = {"Cargo.toml", "Makefile", ".gitignore"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Scaffold a layered Rust backend service.")
    parser.add_argument("target")
    parser.add_argument("--name", required=True)
    parser.add_argument("--member", action="store_true")
    args = parser.parse_args()

    if not re.fullmatch(r"[a-z][a-z0-9]*(-[a-z0-9]+)*", args.name):
        print(f"error: --name must be kebab-case, got {args.name!r}", file=sys.stderr)
        return 2

    target = Path(args.target).resolve()
    if target.exists() and any(target.iterdir()):
        print(f"error: {target} exists and is not empty", file=sys.stderr)
        return 2

    for source in sorted(TEMPLATE.rglob("*")):
        relative = source.relative_to(TEMPLATE)
        if args.member and len(relative.parts) == 1 and relative.name in WORKSPACE_ONLY:
            continue
        destination = target / relative
        if source.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        text = source.read_text(encoding="utf-8")
        destination.write_text(text.replace(PLACEHOLDER, args.name), encoding="utf-8")
        shutil.copymode(source, destination)

    print(f"Created {args.name} in {target}")
    if args.member:
        workspace = (TEMPLATE / "Cargo.toml").read_text(encoding="utf-8")
        dependencies = workspace.split("[workspace.dependencies]", 1)[1].strip()
        print("\nMerge into the root workspace Cargo.toml:")
        print(f'  members: add "{target.name}/crates/*" (a path relative to the root)')
        print("  [workspace.dependencies]: add whichever of these are missing, keeping")
        print("  the root's existing versions and merging features:\n")
        print("\n".join(f"    {line}" for line in dependencies.splitlines()))
        print("\nMerge the check / test-integration targets of the template Makefile")
        print("into the root Makefile, and point compose.test.yml's port at a free one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
