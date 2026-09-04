#!/usr/bin/env python3
"""Deterministic check (and outward export) for the facade and orchestration
IDL contract artifacts.

Authority direction (issue #3 D2, extended by issue #19): the facade IDL and
the orchestration formal API contract artifact are owned authoritatively by
THIS repository under the sealed XML spec. Downstream consumers (notably
xx-builders-net) generate from here; nothing is ever copied INTO this
repository from a downstream checkout. There is therefore no `--generate
--source <checkout>` mode: a reverse generator would make the downstream
working copy canonical and let an unreviewed external mutation silently
become the contract.

- Default `check` mode is offline and CI-safe: every bay:generated-projection
  declared in spec/b2b-federation-spec-v1.xml must have a matching
  bay:artifact with role="contract" whose sha256 equals the file bytes, so a
  hand edit to either the projection or its declaration fails this gate
  instead of drifting silently.
- `--export --dest DIR` copies the authoritative projection bytes OUTWARD
  from this repository into DIR (a downstream working copy) and verifies the
  copy is byte-identical. It is a convenience for downstream consumers and is
  never required to validate this repository.
"""

import hashlib
import os
import shutil
import sys
import xml.etree.ElementTree as ET

PROJECTIONS = [
    "api/proto/builders/v1/federation.proto",
    "api/proto/builders/v1/common.proto",
    "api/proto/builders/v1/orchestration.proto",
    "api/proto/builders/v1/attachment.proto",
]
NS = {"bay": "urn:baylife:system-specification:4.0"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def load_declarations(root_dir):
    tree = ET.parse(os.path.join(root_dir, "spec", "b2b-federation-spec-v1.xml"))
    root = tree.getroot()
    projections = [
        p.attrib["path"]
        for p in root.findall(".//bay:generated-projection", NS)
        if p.attrib.get("path")
    ]
    artifacts = {}
    for art in root.findall(".//bay:artifact", NS):
        artifacts[art.attrib.get("path")] = (
            art.attrib.get("id"),
            art.attrib.get("role"),
            art.attrib.get("sha256"),
        )
    return projections, artifacts


def check(root_dir):
    projections, artifacts = load_declarations(root_dir)
    failures = []
    for path in PROJECTIONS:
        if path not in projections:
            failures.append(f"projection missing from bay:delivery: {path}")
            continue
        entry = artifacts.get(path)
        if entry is None:
            failures.append(f"projection has no bay:artifact declaration: {path}")
            continue
        art_id, role, declared = entry
        if role != "contract":
            failures.append(f"artifact {art_id} role is {role!r}, want 'contract'")
            continue
        full = os.path.join(root_dir, path)
        if not os.path.exists(full):
            failures.append(f"projection file absent: {path}")
            continue
        actual = sha256_file(full)
        if actual != declared:
            failures.append(
                f"projection drift for {path}: file sha256 {actual} != "
                f"artifact {art_id} declares {declared}"
            )
            continue
        print(f"  --> PINNED: {path} ({actual[:12]}...) matches {art_id}")
    if failures:
        for f in failures:
            print(f"[FAIL] {f}", file=sys.stderr)
        return 1
    print(f"  --> PASS: {len(PROJECTIONS)} facade IDL projections pinned to contract artifacts")
    return 0


def export(root_dir, dest):
    for path in PROJECTIONS:
        src = os.path.join(root_dir, path)
        if not os.path.exists(src):
            print(f"[FAIL] authoritative projection absent: {path}", file=sys.stderr)
            return 1
        dst = os.path.join(dest, path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        if sha256_file(src) != sha256_file(dst):
            print(f"[FAIL] export mismatch for {path}", file=sys.stderr)
            return 1
        print(f"  --> EXPORTED: {path} ({sha256_file(src)[:12]}...) to {dest}")
    return check(root_dir)


def main(argv):
    if "--generate" in argv or "--source" in argv:
        print(
            "[REFUSED] this repository owns the facade IDL authoritatively "
            "(issue #3 D2): there is no reverse generator copying projections "
            "in from a downstream checkout. Use --export --dest DIR to copy "
            "authoritative bytes outward, or run the offline check with no flags.",
            file=sys.stderr,
        )
        return 2
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if "--export" in argv:
        try:
            dest = argv[argv.index("--dest") + 1]
        except (ValueError, IndexError):
            print("usage: check-projections.py [--export --dest <dir>]", file=sys.stderr)
            return 2
        print("Exporting authoritative facade IDL projections outward...")
        return export(root_dir, dest)
    print("Checking facade IDL projection pins...")
    return check(root_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
