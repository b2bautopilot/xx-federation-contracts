#!/usr/bin/env python3
"""Deterministic check (and pinned regeneration) for the facade IDL projections.

The gateway-facing control facade IDL lives here as an XML-declared projection
(bay:generated-projection in spec/b2b-federation-spec-v1.xml, decision D2 on
issue #3). Each projection path must have a matching bay:artifact with
role="contract" whose sha256 equals the file bytes, so a hand edit to either
the projection or its declaration fails this gate instead of drifting silently.

Regeneration is a byte copy from the canonical control source, never a
hand-maintained second authority:

    python3 scripts/check-projections.py --generate --source <xx-builders-net checkout>

--generate copies api/proto/builders/v1/{federation,common}.proto from SOURCE
(which must be at the pinned commit SOURCE_COMMIT below; verified offline with
`git -C SOURCE rev-parse HEAD`) and then runs the check. Advancing the pin is
an explicit spec change (new digests + revision), never a silent edit.

Check mode (default) is offline and CI-safe: it only reads this repository.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

SOURCE_COMMIT = "c1ad78a4eb8a3ae0e0d1652609fbbe51fc4a5ad9"  # xx-builders-net origin/dev
PROJECTIONS = [
    "api/proto/builders/v1/federation.proto",
    "api/proto/builders/v1/common.proto",
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


def generate(root_dir, source):
    head = subprocess.run(
        ["git", "-C", source, "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    if head.returncode != 0:
        print(f"[FAIL] not a git checkout: {source}", file=sys.stderr)
        return 1
    if head.stdout.strip() != SOURCE_COMMIT:
        print(
            f"[FAIL] source checkout is at {head.stdout.strip()}, want pinned "
            f"{SOURCE_COMMIT}; advancing the pin is an explicit spec change",
            file=sys.stderr,
        )
        return 1
    for path in PROJECTIONS:
        src = os.path.join(source, path)
        dst = os.path.join(root_dir, path)
        if not os.path.exists(src):
            print(f"[FAIL] canonical source missing: {src}", file=sys.stderr)
            return 1
        shutil.copyfile(src, dst)
        print(f"  --> COPIED: {path} from {SOURCE_COMMIT[:12]}")
    return check(root_dir)


def main(argv):
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if "--generate" in argv:
        try:
            source = argv[argv.index("--source") + 1]
        except (ValueError, IndexError):
            print("usage: check-projections.py [--generate --source <checkout>]", file=sys.stderr)
            return 2
        print("Regenerating facade IDL projections from pinned canonical source...")
        return generate(root_dir, source)
    print("Checking facade IDL projection pins...")
    return check(root_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
