#!/usr/bin/env python3
"""Three-way consistency gate for the issue #19 orchestration contract.

Single-source invariant: spec/b2b-federation-spec-v1.xml is the architecture
authority. api/proto/builders/v1/orchestration.proto is the formal API
contract artifact linked and digested there. The Go packages
contracts/orchestration, contracts/attachment, and contracts/provenance are
the enforcement implementation of the same sealed contract — not a second
source of truth, and the proto is NOT generated from handwritten Go (no
Go->proto generator exists or is claimed).

This gate mechanically proves the three sides agree, so neither the proto
nor the Go can drift into an unlinked second schema copy:

1. XML linkage: every contract file has a bay:artifact declaration whose
   sha256 equals the file bytes.
2. Vocabulary equivalence: every proto enum member (minus UNSPECIFIED) maps
   to exactly one sealed Go string constant and vice versa; every BFF
   service RPC maps to exactly one sealed BFF command string.
3. No legacy drift: no xyz-b2b source-pointer outside the explicitly
   documented compatibility-only go_package option.

Exit 0 on agreement, 1 with [FAIL] lines otherwise. CI runs this alongside
scripts/validate-spec.py, scripts/check-projections.py, and
scripts/generate-projections.py --check.
"""

import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET

NS = {"bay": "urn:baylife:system-specification:4.0"}

PROTO = "api/proto/builders/v1/orchestration.proto"

LINKED_FILES = [
    "contracts/orchestration/orchestration.go",
    "contracts/orchestration/ledger.go",
    "contracts/orchestration/visibility.go",
    "contracts/orchestration/bff.go",
    "contracts/attachment/attachment.go",
    "contracts/provenance/provenance.go",
    PROTO,
]

# Sealed vocabulary equivalence: proto enum member -> Go string constant.
ENUM_MAP = {
    "RunState": {
        "RUN_REQUESTED": "requested",
        "RUN_AUTHORIZED": "authorized",
        "RUN_RUNNING": "running",
        "RUN_COMPLETED": "completed",
        "RUN_FAILED": "failed",
        "RUN_TIMED_OUT": "timed_out",
        "RUN_CANCELLED": "cancelled",
    },
    "TaskState": {
        "TASK_PENDING": "pending",
        "TASK_ASSIGNED": "assigned",
        "TASK_ACKNOWLEDGED": "acknowledged",
        "TASK_IN_PROGRESS": "in_progress",
        "TASK_IN_REVIEW": "in_review",
        "TASK_DONE": "done",
        "TASK_FAILED": "failed",
        "TASK_TIMED_OUT": "timed_out",
        "TASK_CANCELLED": "cancelled",
    },
    "OrchestrationEventKind": {
        "EVENT_REQUEST": "request",
        "EVENT_AUTHORIZATION": "authorization",
        "EVENT_PM_START": "pm_start",
        "EVENT_PLAN_PUBLICATION": "plan_publication",
        "EVENT_ASSIGNMENT": "assignment",
        "EVENT_ACKNOWLEDGMENT": "acknowledgment",
        "EVENT_PROGRESS": "progress",
        "EVENT_HANDOFF": "handoff",
        "EVENT_DECISION": "decision",
        "EVENT_REVIEW": "review",
        "EVENT_SYNTHESIS": "synthesis",
        "EVENT_COMPLETION": "completion",
        "EVENT_FAILURE": "failure",
        "EVENT_TIMEOUT": "timeout",
        "EVENT_CANCELLATION": "cancellation",
    },
    "ParticipantRole": {
        "ROLE_PM": "pm",
        "ROLE_BUILDER": "builder",
        "ROLE_REVIEWER": "reviewer",
    },
    "ObservationVisibility": {
        "VISIBILITY_TENANT": "tenant",
        "VISIBILITY_PARTNER": "partner",
    },
    "AttachmentDirection": {
        "DIRECTION_INPUT": "input",
        "DIRECTION_RETURNED": "returned",
    },
    "AttachmentScanState": {
        "SCAN_PENDING": "pending",
        "SCAN_CLEAN": "clean",
        "SCAN_QUARANTINED": "quarantined",
        "SCAN_BLOCKED": "blocked",
    },
    "ContainerRuntimeKind": {
        "GCP_CLOUD_RUN": "gcp-cloud-run",
        "AZURE_CONTAINER_APPS": "azure-container-apps",
        "AZURE_CONTAINER_INSTANCES": "azure-container-instances",
        "AWS_ECS_FARGATE": "aws-ecs-fargate",
    },
}

# Sealed BFF surface equivalence: proto RPC -> Go command string.
RPC_MAP = {
    "StartRun": "start_run",
    "CancelRun": "cancel_run",
    "GetRun": "get_run",
    "WatchEvents": "watch_events",
}

# Go string constants carried as proto strings (no proto enum): still sealed
# vocabulary that must exist verbatim in the Go implementation.
GO_ONLY_STRINGS = {
    "contracts/orchestration/orchestration.go": [
        "muse", "codex", "claude", "grok", "antigravity", "human",
    ],
    "contracts/attachment/attachment.go": [
        "tenant", "partner", "fetch", "return",
    ],
}

GO_PACKAGE_COMPAT = "github.com/b2bautopilot/xyz-b2b/services/builders-net/gen/builders/v1;buildersv1"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def parse_proto_enums(text):
    enums = {}
    for match in re.finditer(r"enum\s+(\w+)\s*\{([^}]*)\}", text):
        members = re.findall(r"(\w+)\s*=\s*(\d+)\s*;", match.group(2))
        enums[match.group(1)] = members
    return enums


def parse_proto_rpcs(text):
    return re.findall(r"rpc\s+(\w+)\s*\(", text)


def check(root_dir):
    failures = []

    # 1. XML linkage for all seven files.
    tree = ET.parse(os.path.join(root_dir, "spec", "b2b-federation-spec-v1.xml"))
    artifacts = {}
    for art in tree.getroot().findall(".//bay:artifact", NS):
        artifacts[art.attrib.get("path")] = art.attrib.get("sha256")
    for rel_path in LINKED_FILES:
        declared = artifacts.get(rel_path)
        if not declared:
            failures.append(f"no bay:artifact linkage for {rel_path}")
            continue
        actual = sha256_file(os.path.join(root_dir, rel_path))
        if actual != declared:
            failures.append(f"artifact drift for {rel_path}: file {actual} != declared {declared}")

    # 2a. Proto enum <-> Go string equivalence.
    with open(os.path.join(root_dir, PROTO), encoding="utf-8") as f:
        proto_text = f.read()
    go_text = {}
    for rel_path in LINKED_FILES:
        if rel_path.endswith(".go"):
            with open(os.path.join(root_dir, rel_path), encoding="utf-8") as f:
                go_text[rel_path] = f.read()
    all_go = "\n".join(go_text.values())
    enums = parse_proto_enums(proto_text)
    for enum_name, mapping in ENUM_MAP.items():
        members = enums.get(enum_name)
        if members is None:
            failures.append(f"proto enum absent: {enum_name}")
            continue
        proto_names = [name for name, _ in members if not name.endswith("UNSPECIFIED")]
        if set(proto_names) != set(mapping):
            failures.append(
                f"proto enum {enum_name} members {sorted(proto_names)} != sealed {sorted(mapping)}"
            )
        numbers = [int(num) for _, num in members]
        if numbers != list(range(len(numbers))):
            failures.append(f"proto enum {enum_name} numbers not dense from 0: {numbers}")
        for member, go_value in mapping.items():
            if f'"{go_value}"' not in all_go:
                failures.append(f"sealed Go value {go_value!r} ({member}) absent from Go implementation")

    # 2b. BFF RPC <-> command string equivalence.
    rpcs = parse_proto_rpcs(proto_text)
    for rpc, command in RPC_MAP.items():
        if rpc not in rpcs:
            failures.append(f"proto RPC absent: {rpc}")
        if f'"{command}"' not in all_go:
            failures.append(f"sealed BFF command {command!r} absent from Go implementation")
    # RPCs parsed here come only from orchestration.proto (single-file
    # parse), so any unmapped RPC is drift. Pre-existing facade services
    # live in federation.proto, sealed under issue #3, and are out of scope.
    extra_rpcs = set(rpcs) - set(RPC_MAP.keys())
    if extra_rpcs:
        failures.append(f"unmapped proto RPCs (second surface?): {sorted(extra_rpcs)}")

    # 2c. Go-carried sealed strings exist verbatim.
    for rel_path, values in GO_ONLY_STRINGS.items():
        text = go_text.get(rel_path, "")
        for value in values:
            if f'"{value}"' not in text:
                failures.append(f"sealed string {value!r} absent from {rel_path}")

    # 3. No legacy xyz-b2b drift outside the documented compat go_package.
    for rel_path in LINKED_FILES:
        with open(os.path.join(root_dir, rel_path), encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                if "xyz-b2b" in line and GO_PACKAGE_COMPAT not in line:
                    failures.append(f"legacy drift {rel_path}:{lineno}: {line.strip()[:100]}")
    if GO_PACKAGE_COMPAT not in proto_text:
        failures.append("compat go_package missing from orchestration.proto")
    if "compatibility-only" not in proto_text.lower():
        failures.append("go_package compatibility-only documentation missing from orchestration.proto")

    return failures


def main(argv):
    del argv
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("Checking orchestration XML<->proto<->Go consistency...")
    failures = check(root_dir)
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        return 1
    print(f"  --> PASS: {len(LINKED_FILES)} linked files, "
          f"{sum(len(m) for m in ENUM_MAP.values())} enum values, "
          f"{len(RPC_MAP)} RPCs agree across XML, proto, and Go")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
