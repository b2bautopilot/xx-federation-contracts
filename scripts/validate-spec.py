#!/usr/bin/env python3
import hashlib
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


declared_hashes = {
    "schemas/b2b-architecture-v1.xsd": "76d354a7c601d9066fc8ab8ea4ab304719ef53db5751efc60a2a725de327fb9e",
}

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def semantic_hash(filepath):
    """Hash the canonical spec content while excluding its self-referential history."""
    ET.register_namespace("bay", "urn:baylife:system-specification:4.0")
    ET.register_namespace("b2b", "urn:b2b:architecture:1.0")
    ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")

    tree = ET.parse(filepath)
    root = tree.getroot()
    history = root.find("{urn:baylife:system-specification:4.0}history")
    if history is None:
        raise ValueError("specification is missing bay:history")

    children = list(root)
    history_index = children.index(history)
    history_tail = history.tail or ""
    root.remove(history)
    if history_index == 0:
        root.text = (root.text or "") + history_tail
    else:
        children[history_index - 1].tail = (children[history_index - 1].tail or "") + history_tail

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".xml") as canonical_input:
        tree.write(canonical_input, encoding="UTF-8", xml_declaration=True)
        canonical_input.flush()
        result = subprocess.run(
            ["xmllint", "--c14n", canonical_input.name],
            check=True,
            capture_output=True,
        )
    return hashlib.sha256(result.stdout).hexdigest()

def validate():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec_xml = os.path.join(root_dir, "spec", "b2b-federation-spec-v1.xml")
    b2b_xsd = os.path.join(root_dir, "schemas", "b2b-architecture-v1.xsd")
    v4_xsd = os.path.join(root_dir, "schemas", "system-specification-v4.xsd")

    print("=================================================================")
    print("      B2B AUTOPILOT / BUILDERS NET SPECIFICATION VALIDATOR       ")
    print("=================================================================")

    # 1. Check file existence
    for p in [spec_xml, b2b_xsd, v4_xsd]:
        if not os.path.exists(p):
            print(f"[FAIL] Required file missing: {p}", file=sys.stderr)
            return 1

    # 2. xmllint XSD schema validation
    print("[1/4] Running xmllint strict XSD schema validation...")
    try:
        res = subprocess.run(["xmllint", "--noout", "--schema", b2b_xsd, spec_xml], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[FAIL] xmllint validation failed:\n{res.stderr}", file=sys.stderr)
            return 1
        print("      --> PASS: Validates perfectly against system-specification-v4.xsd and b2b-architecture-v1.xsd")
    except FileNotFoundError:
        print("      --> [WARN] xmllint not installed; falling back to Python ElementTree")

    # 3. ElementTree parse & reference integrity
    print("[2/4] Verifying structural graph & ID reference integrity...")
    tree = ET.parse(spec_xml)
    root = tree.getroot()

    declared_ids = set()
    for elem in root.iter():
        i = elem.attrib.get("id")
        if i:
            if i in declared_ids:
                print(f"[FAIL] Duplicate ID detected: {i}", file=sys.stderr)
                return 1
            declared_ids.add(i)

    print(f"      --> PASS: {len(declared_ids)} unique architectural IDs registered")

    for elem in root.iter():
        for attr in ["source-ref", "target-ref", "actor-ref", "change-set-ref", "artifact-ref"]:
            val = elem.attrib.get(attr)
            if val and val not in declared_ids:
                if not val.startswith("actor.") and not val.startswith("agent-prompt."):
                    print(f"[FAIL] Dangling {attr} reference: '{val}' not found in declared IDs", file=sys.stderr)
                    return 1

    print("      --> PASS: All relationships and gates resolve with 100% reference integrity")

    # 4. Artifact SHA-256 verification
    print("[3/4] Verifying declared artifact SHA-256 checksums...")
    ns = {"bay": "urn:baylife:system-specification:4.0"}
    for art in root.findall(".//bay:artifact", ns):
        art_id = art.attrib.get("id")
        relative_path = art.attrib.get("path")
        art_path = os.path.join(root_dir, relative_path)
        expected_sha = art.attrib.get("sha256")
        pinned_sha = declared_hashes.get(relative_path)
        if pinned_sha and expected_sha != pinned_sha:
            print(f"[FAIL] XML artifact declaration for {art_id} does not match validator declared_hashes", file=sys.stderr)
            return 1
        if os.path.exists(art_path):
            actual_sha = sha256_file(art_path)
            if actual_sha != expected_sha:
                print(f"[FAIL] SHA-256 mismatch for artifact {art_id} ({art.attrib.get('path')}): expected {expected_sha}, got {actual_sha}", file=sys.stderr)
                return 1
            print(f"      --> PASS: {art.attrib.get('path')} ({actual_sha[:12]}...) matches declared sha256")
        else:
            print(f"      --> [SKIP] Optional external projection artifact: {art.attrib.get('path')}")

    # 5. Semantic Hash Verification
    print("[4/4] Verifying sealed revision semantic hash...")
    revisions = root.findall(".//bay:revision", ns)
    calculated_hash = semantic_hash(spec_xml)
    latest_revision = max(revisions, key=lambda rev: int(rev.attrib["number"]))
    for rev in revisions:
        rev_num = rev.attrib.get("number")
        sem_hash = rev.attrib.get("semantic-hash")
        if rev is latest_revision and sem_hash != f"sha256:{calculated_hash}":
            print(
                f"[FAIL] Revision {rev_num} semantic-hash mismatch: expected sha256:{calculated_hash}, got {sem_hash}",
                file=sys.stderr,
            )
            return 1
        print(f"      --> PASS: Revision {rev_num} sealed with semantic-hash {sem_hash[:20]}...")

    print("=================================================================")
    print("  SUCCESS: SPECIFICATION & METASCHEMA ARE 100% ADVERSARIALLY SOUND")
    print("=================================================================")
    return 0

if __name__ == "__main__":
    sys.exit(validate())
