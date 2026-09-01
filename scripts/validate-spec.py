#!/usr/bin/env python3
import os, sys, xml.etree.ElementTree as ET

def validate_spec():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec_path = os.path.join(root_dir, "spec", "b2b-federation-spec-v1.xml")

    if not os.path.exists(spec_path):
        print(f"Error: Spec file not found at {spec_path}", file=sys.stderr)
        return 1

    print(f"--> Validating {spec_path}...")
    try:
        tree = ET.parse(spec_path)
        root = tree.getroot()
        print("    [PASS] XML syntax and structure well-formed")
    except Exception as e:
        print(f"    [FAIL] XML syntax error: {e}", file=sys.stderr)
        return 1

    # Check component and relationship IDs
    component_ids = set()
    for elem in root.iter():
        cid = elem.attrib.get("id")
        if cid:
            if cid in component_ids:
                print(f"    [FAIL] Duplicate element ID found: {cid}", file=sys.stderr)
                return 1
            component_ids.add(cid)

    print(f"    [PASS] Verified {len(component_ids)} unique architectural element IDs")

    # Check reference integrity
    for elem in root.iter():
        ref = elem.attrib.get("ref")
        if ref and ref not in component_ids:
            if not ref.startswith("actor.") and not ref.startswith("agent-prompt."):
                print(f"    [FAIL] Broken reference integrity: '{ref}' not found in component IDs", file=sys.stderr)
                return 1

    print("    [PASS] Reference integrity verified")
    print("ALL SPEC VALIDATION CHECKS PASSED (100% GREEN)")
    return 0

if __name__ == "__main__":
    sys.exit(validate_spec())
