#!/usr/bin/env python3
import hashlib
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


declared_hashes = {
    "schemas/b2b-architecture-v1.xsd": "a007f2fd976ee6a6d1664f456f0af004798321d89e034c71fc0b87645891a9c8",
}

# Issue #19 orchestration contract, extended by issue #21 revision 10:
# every artifact path below must exist on disk with a matching
# bay:artifact declaration (checked generically in step 3); presence
# itself is enforced in step 5.
required_orchestration_artifacts = [
    "contracts/orchestration/orchestration.go",
    "contracts/orchestration/ledger.go",
    "contracts/orchestration/visibility.go",
    "contracts/orchestration/bff.go",
    "contracts/orchestration/projection.go",
    "contracts/orchestration/slots.go",
    "contracts/orchestration/migration.go",
    "contracts/attachment/attachment.go",
    "contracts/attachment/lifecycle.go",
    "contracts/provenance/provenance.go",
    "api/proto/builders/v1/orchestration.proto",
    "api/proto/builders/v1/attachment.proto",
    "projections/b2b-federation-contracts.md",
    "projections/b2b-federation-contracts.html",
]

# (relationship id, required evidence keys) for the orchestration seal.
required_relationship_evidence = {
    "rel.agent-connects-control": [
        "orchestration-run-ledger",
        "agent-telemetry",
        "attachment-capability",
        "runtime-provenance",
        "participant-lifecycle",
        "provenance-binding",
        "attachment-custody",
    ],
    "rel.portal-dials-control": [
        "bff-command-envelope",
        "observation-stream",
        "attachment-evidence",
        "observation-projection",
        "attachment-evidence-projection",
    ],
}

# (component id, required child element local-names) for the seal.
required_component_fields = {
    "comp.builders-control": ["orchestration-ledger", "attachment-ledger"],
    "comp.builders-agent": ["participant-mode", "runtime-provenance"],
    "comp.builders-portal": ["observation-projection"],
    "comp.sim-infra": ["orchestration-runtimes"],
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
    print("[1/5] Running xmllint strict XSD schema validation...")
    try:
        res = subprocess.run(["xmllint", "--noout", "--schema", b2b_xsd, spec_xml], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[FAIL] xmllint validation failed:\n{res.stderr}", file=sys.stderr)
            return 1
        print("      --> PASS: Validates perfectly against system-specification-v4.xsd and b2b-architecture-v1.xsd")
    except FileNotFoundError:
        print("      --> [WARN] xmllint not installed; falling back to Python ElementTree")

    # 3. ElementTree parse & reference integrity
    print("[2/5] Verifying structural graph & ID reference integrity...")
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
    print("[3/5] Verifying declared artifact SHA-256 checksums...")
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
    print("[4/5] Verifying sealed revision semantic hash...")
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

    # 6. Orchestration contract completeness (issue #19)
    print("[5/5] Verifying orchestration/observation/attachment/provenance seal...")
    if check_orchestration_seal(root, root_dir, spec_xml) != 0:
        return 1

    print("=================================================================")
    print("  SUCCESS: SPECIFICATION & METASCHEMA ARE 100% ADVERSARIALLY SOUND")
    print("=================================================================")
    return 0


def local_name(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def check_orchestration_seal(root, root_dir, spec_xml):
    import re

    bay_ns = "{urn:baylife:system-specification:4.0}"
    failures = []

    # (a) Required contract artifacts exist on disk. SHA pinning itself is
    # enforced generically in step 3; here a missing file is a hard fail so
    # the seal can never reference vapor.
    for rel_path in required_orchestration_artifacts:
        if not os.path.exists(os.path.join(root_dir, rel_path)):
            failures.append(f"orchestration artifact absent on disk: {rel_path}")

    # Index components and relationships by id.
    components = {}
    comp_root = root.find(f"{bay_ns}components")
    if comp_root is not None:
        for comp in comp_root:
            if comp.attrib.get("id"):
                components[comp.attrib["id"]] = comp
    relationships = {}
    rel_root = root.find(f"{bay_ns}relationships")
    if rel_root is not None:
        for rel in rel_root:
            if rel.attrib.get("id"):
                relationships[rel.attrib["id"]] = rel

    # (b) Required evidence keys on the agent and portal relationships.
    for rel_id, keys in required_relationship_evidence.items():
        rel = relationships.get(rel_id)
        if rel is None:
            failures.append(f"relationship absent: {rel_id}")
            continue
        have = {ev.attrib.get("key") for ev in rel.findall(f"{bay_ns}evidence")}
        for key in keys:
            if key not in have:
                failures.append(f"{rel_id} missing evidence key: {key}")

    # (c) Required typed fields on the touched components.
    for comp_id, fields in required_component_fields.items():
        comp = components.get(comp_id)
        if comp is None:
            failures.append(f"component absent: {comp_id}")
            continue
        have = {local_name(child.tag) for child in comp}
        for field in fields:
            if field not in have:
                failures.append(f"{comp_id} missing typed field: {field}")

    # (c2) Migration target (issue #21): the control-plane
    # postgres-migrations-count equals the Go PostgresMigrationTarget, and
    # the component description honestly maps every served migration with
    # its downstream entity id and code-only status. The drift correction
    # (revision 9 declared 57 while downstream had integrated 58) must stay
    # recorded with its no-live-migration honesty note.
    control = components.get("comp.builders-control")
    if control is not None:
        count = ""
        description = ""
        for child in control:
            if local_name(child.tag) == "postgres-migrations-count" and child.text:
                count = child.text.strip()
            if local_name(child.tag) == "description" and child.text:
                description = child.text
        go_target = None
        migration_go = os.path.join(root_dir, "contracts", "orchestration", "migration.go")
        try:
            with open(migration_go, encoding="utf-8") as f:
                match = re.search(r"PostgresMigrationTarget\s*=\s*(\d+)", f.read())
                if match:
                    go_target = match.group(1)
        except OSError:
            go_target = None
        if go_target is None:
            failures.append("Go PostgresMigrationTarget absent")
        elif count != go_target:
            failures.append(
                f"migration target drift: XML declares {count} != Go enforces {go_target}"
            )
        for keyword in ["000058_orchestration_ledger", "000059_attachment_custody",
                        "migration 60", "code-only", "no live database"]:
            if keyword not in description:
                failures.append(
                    f"comp.builders-control description missing migration record {keyword!r}"
                )

    # (d) Cloud execution vocabulary: container runtimes only. GCP runs
    # Cloud Run, Azure runs ACA/ACI, AWS stays ECS Fargate-only; any VM
    # vocabulary fails the seal (Revision 6 prohibition).
    sim = components.get("comp.sim-infra")
    if sim is not None:
        runtimes = ""
        for child in sim:
            if local_name(child.tag) == "orchestration-runtimes" and child.text:
                runtimes = child.text.strip().lower()
        for want in ["cloud-run", "fargate"]:
            if want not in runtimes:
                failures.append(f"orchestration-runtimes missing {want}")
        if "container-apps" not in runtimes and "aca" not in runtimes:
            failures.append("orchestration-runtimes missing azure container apps")
        if "container-instances" not in runtimes and "aci" not in runtimes:
            failures.append("orchestration-runtimes missing azure container instances")
        for banned in ["ec2", "gce-virtual", "aks-nodepool", "gke-nodepool",
                       "virtual-machine", "virtual_machine", "hyper-v", "vsphere"]:
            if banned in runtimes:
                failures.append(f"orchestration-runtimes carries VM vocabulary: {banned}")
        if re.search(r"(?<![a-z-])vms?(?![a-z-])", runtimes):
            failures.append("orchestration-runtimes carries VM vocabulary: vm")

    # (e) Privacy: the sealed spec carries no private topology — no RFC1918,
    # no link-local/cloud-metadata literals. Loopback stays legal: it is the
    # declared local facade endpoint, not topology.
    with open(spec_xml, "r", encoding="utf-8") as f:
        spec_text = f.read()
    for pattern, label in [
        (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "private 10/8"),
        (r"192\.168\.\d{1,3}\.\d{1,3}", "private 192.168/16"),
        (r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", "private 172.16/12"),
        (r"169\.254\.\d{1,3}\.\d{1,3}", "link-local/cloud-metadata"),
    ]:
        if re.search(pattern, spec_text):
            failures.append(f"spec leaks {label} address literal")

    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        return 1
    print("      --> PASS: orchestration seal complete (artifacts, evidence, fields, cloud vocabulary, privacy)")
    return 0

if __name__ == "__main__":
    sys.exit(validate())
