#!/usr/bin/env python3
"""Three-way consistency gate for the orchestration contract (issues
#19 and #21).

Single-source invariant: spec/b2b-federation-spec-v1.xml is the architecture
authority. api/proto/builders/v1/orchestration.proto (OrchestrationService:
commands, queries, observation projection, participant binding) and
api/proto/builders/v1/attachment.proto (AttachmentService: custody and
scoped capabilities) are the formal API contract artifacts linked and
digested there. The Go packages contracts/orchestration,
contracts/attachment, and contracts/provenance are the enforcement
implementation of the same sealed contract — not a second source of truth,
and neither proto is generated from handwritten Go (no Go->proto generator
exists or is claimed).

This gate mechanically proves the sides agree, so no proto and no Go file
can drift into an unlinked second schema copy:

1. XML linkage: every contract file has a bay:artifact declaration whose
   sha256 equals the file bytes.
2. Vocabulary equivalence: every proto enum member (minus UNSPECIFIED)
   maps to exactly one sealed Go string constant and vice versa; every
   service RPC maps to exactly one sealed operation string.
3. Additive compatibility: every revision-9 message field keeps its sealed
   field number (new fields only append); the revision-10 additions are
   present where declared.
4. Migration agreement: the XML postgres-migrations-count equals the Go
   PostgresMigrationTarget constant.
5. No legacy drift: no xyz-b2b source-pointer outside the explicitly
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
B2B = "urn:b2b:architecture:1.0"

PROTOS = [
    "api/proto/builders/v1/orchestration.proto",
    "api/proto/builders/v1/attachment.proto",
]

LINKED_FILES = [
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
] + PROTOS

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
    "ParticipantStatus": {
        "PARTICIPANT_INVITED": "invited",
        "PARTICIPANT_ACTIVE": "active",
        "PARTICIPANT_SUSPENDED": "suspended",
        "PARTICIPANT_DEPARTED": "departed",
        "PARTICIPANT_REMOVED": "removed",
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
    "AttachmentAudience": {
        "ATTACHMENT_AUDIENCE_TENANT": "tenant",
        "ATTACHMENT_AUDIENCE_PARTNER": "partner",
    },
    "CapabilityAction": {
        "CAPABILITY_ACTION_PUT": "put",
        "CAPABILITY_ACTION_FETCH": "fetch",
        "CAPABILITY_ACTION_DOWNLOAD": "download",
    },
    "AttachmentLifecycle": {
        "LIFECYCLE_OFFERED": "offered",
        "LIFECYCLE_AUTHORIZED": "authorized",
        "LIFECYCLE_FETCHED": "fetched",
        "LIFECYCLE_VERIFIED": "verified",
        "LIFECYCLE_PRODUCED": "produced",
        "LIFECYCLE_RETURNED": "returned",
        "LIFECYCLE_EXPIRED": "expired",
        "LIFECYCLE_REJECTED": "rejected",
    },
    "AttachmentDownloadReason": {
        "DOWNLOAD_AVAILABLE": "available",
        "DOWNLOAD_SCAN_PENDING": "scan_pending",
        "DOWNLOAD_NOT_CLEAN": "not_clean",
        "DOWNLOAD_EXPIRED": "expired",
        "DOWNLOAD_NOT_VERIFIED": "not_verified",
        "DOWNLOAD_NOT_VISIBLE": "not_visible",
    },
    "AttachmentRejectVerdict": {
        "REJECT_QUARANTINE": "quarantine",
        "REJECT_BLOCK": "block",
    },
    "PutCompletionStatus": {
        "PUT_STORED": "stored",
        "PUT_REPLAYED": "replayed",
    },
    "ContainerRuntimeKind": {
        "GCP_CLOUD_RUN": "gcp-cloud-run",
        "AZURE_CONTAINER_APPS": "azure-container-apps",
        "AZURE_CONTAINER_INSTANCES": "azure-container-instances",
        "AWS_ECS_FARGATE": "aws-ecs-fargate",
    },
}

# Sealed service surface equivalence: proto RPC -> Go operation string.
# Browser BFF commands (bff.go) and authenticated control operations
# (slots.go) plus custody operations (attachment/lifecycle.go) share one
# map because the pin is mechanical: every served RPC has exactly one
# sealed Go operation name.
RPC_MAP = {
    "StartRun": "start_run",
    "CancelRun": "cancel_run",
    "GetRun": "get_run",
    "WatchEvents": "watch_events",
    "RegisterProvenance": "register_provenance",
    "BindParticipant": "bind_participant",
    "UpdateParticipantStatus": "update_participant_status",
    "GetProvenance": "get_provenance",
    "MintCapability": "mint_capability",
    "PutAttachment": "put_attachment",
    "FetchAttachment": "fetch_attachment",
    "GetAttachmentRef": "get_attachment_ref",
    "RejectAttachment": "reject_attachment",
    "SweepAttachments": "sweep_attachments",
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

# Revision-9 message field pins: sealed field numbers that must never be
# renumbered or repurposed. Revision-10 fields only append. Format:
# message name -> {field name: number}.
PINNED_FIELDS = {
    "OrchestrationRun": {
        "schema_version": 1, "run_id": 2, "room_id": 3, "command_id": 4,
        "source_org_id": 5, "target_org_id": 6, "tenant_id": 7, "state": 8,
        "revision": 9, "audit_head_hash": 10, "created_at_ms": 11,
        "updated_at_ms": 12,
    },
    "AgentParticipant": {
        "participant_id": 1, "role": 2, "agent_kind": 3, "session_id": 4,
        "workload_id": 5, "container_id": 6, "assigned_task_id": 7,
        "runtime_provenance_id": 8,
    },
    "OrchestrationTask": {
        "task_id": 1, "depends_on": 2, "assignee_id": 3, "state": 4,
        "public_summary": 5, "result_ref": 6, "attachment_ids": 7,
    },
    "OrchestrationEvent": {
        "schema_version": 1, "event_id": 2, "seq": 3, "run_id": 4,
        "task_id": 5, "actor_id": 6, "tenant_id": 7, "kind": 8,
        "causation_id": 9, "correlation_id": 10, "visibility": 11,
        "summary": 12, "attachments": 13, "timestamp_ms": 14,
        "audit_hash": 15,
    },
    "PartnerEvent": {
        "schema_version": 1, "event_id": 2, "seq": 3, "run_id": 4,
        "kind": 5, "actor_role": 6, "summary": 7, "attachments": 8,
        "timestamp_ms": 9, "audit_hash": 10,
    },
    "RuntimeProvenance": {
        "schema_version": 1, "provenance_id": 2, "oci_index_digest": 3,
        "oci_platform_digests": 4, "agentkit_commit": 5,
        "agentkit_version": 6, "cli_name": 7, "cli_version": 8,
        "model_id": 9, "provider_id": 10, "network_policy_hash": 11,
        "spec_revision": 12, "spec_hash": 13, "runtime_kind": 14,
        "cloud": 15, "non_root": 16, "no_new_privileges": 17,
        "image_verified": 18,
    },
    "BffCommandEnvelope": {
        "schema_version": 1, "command_id": 2, "idempotency_key": 3,
        "command": 4, "run_id": 5, "tenant_id": 6, "actor_id": 7,
        "payload": 8, "requested_at_ms": 9,
    },
    "BffCommandReceipt": {
        "schema_version": 1, "command_id": 2, "run_id": 3, "accepted": 4,
        "degraded": 5, "incomplete": 6, "status": 7, "next_after_seq": 8,
        "audit_key_id": 9, "signature": 10,
    },
    "WatchEventsRequest": {
        "run_id": 1, "tenant_id": 2, "after_seq": 3, "limit": 4,
    },
    "WatchEventsResponse": {
        "events": 1, "next_after_seq": 2, "degraded": 3, "incomplete": 4,
    },
}

# Revision-10 additions that must be present: (kind, name) with kind in
# message/enum/service. The seal declares them; absence is drift.
REQUIRED_ADDITIONS = [
    ("message", "ProposedParticipantSlot"),
    ("message", "StartRunRequest"),
    ("message", "GetRunRequest"),
    ("message", "ObservationCounts"),
    ("message", "GetRunResponse"),
    ("message", "PartnerRunProjection"),
    ("message", "RegisterProvenanceRequest"),
    ("message", "RegisterProvenanceResponse"),
    ("message", "BindParticipantRequest"),
    ("message", "BindParticipantResponse"),
    ("message", "UpdateParticipantStatusRequest"),
    ("message", "UpdateParticipantStatusResponse"),
    ("message", "GetProvenanceRequest"),
    ("message", "GetProvenanceResponse"),
    ("message", "AttachmentEvidence"),
    ("message", "MintCapabilityRequest"),
    ("message", "MintCapabilityResponse"),
    ("message", "PutAttachmentChunk"),
    ("message", "PutAttachmentResponse"),
    ("message", "FetchAttachmentRequest"),
    ("message", "FetchAttachmentChunk"),
    ("message", "GetAttachmentRefRequest"),
    ("message", "GetAttachmentRefResponse"),
    ("message", "RejectAttachmentRequest"),
    ("message", "RejectAttachmentResponse"),
    ("message", "SweepAttachmentsRequest"),
    ("message", "SweepAttachmentsResponse"),
    ("enum", "ParticipantStatus"),
    ("enum", "AttachmentAudience"),
    ("enum", "CapabilityAction"),
    ("enum", "AttachmentLifecycle"),
    ("enum", "AttachmentDownloadReason"),
    ("enum", "AttachmentRejectVerdict"),
    ("enum", "PutCompletionStatus"),
    ("service", "AttachmentService"),
]

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


def parse_proto_messages(text):
    """message name -> {field name: number}."""
    messages = {}
    for match in re.finditer(r"message\s+(\w+)\s*\{([^}]*)\}", text):
        fields = re.findall(
            r"^\s*(?:repeated\s+)?[\w.]+(?:<[^>]+>)?\s+(\w+)\s*=\s*(\d+)\s*;",
            match.group(2),
            re.MULTILINE,
        )
        messages[match.group(1)] = {name: int(num) for name, num in fields}
    return messages


def parse_proto_rpcs(text):
    return re.findall(r"rpc\s+(\w+)\s*\(", text)


def parse_proto_services(text):
    return re.findall(r"service\s+(\w+)\s*\{", text)


def check(root_dir):
    failures = []

    # 1. XML linkage for all files.
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

    # Load both IDL files.
    proto_texts = {}
    for rel_path in PROTOS:
        with open(os.path.join(root_dir, rel_path), encoding="utf-8") as f:
            proto_texts[rel_path] = f.read()
    go_text = {}
    for rel_path in LINKED_FILES:
        if rel_path.endswith(".go"):
            with open(os.path.join(root_dir, rel_path), encoding="utf-8") as f:
                go_text[rel_path] = f.read()
    all_go = "\n".join(go_text.values())

    # Merged enum/message/rpc/service indexes across both IDL files.
    enums = {}
    for rel_path, text in proto_texts.items():
        for name, members in parse_proto_enums(text).items():
            if name in enums:
                failures.append(f"proto enum {name} defined twice ({rel_path})")
            enums[name] = members
    messages = {}
    for rel_path, text in proto_texts.items():
        for name, fields in parse_proto_messages(text).items():
            if name in messages:
                failures.append(f"proto message {name} defined twice ({rel_path})")
            messages[name] = (rel_path, fields)
    rpcs = []
    for rel_path, text in proto_texts.items():
        rpcs.extend(parse_proto_rpcs(text))
    services = []
    for rel_path, text in proto_texts.items():
        services.extend(parse_proto_services(text))

    # 2a. Proto enum <-> Go string equivalence.
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

    # 2b. RPC <-> operation string equivalence.
    for rpc, command in RPC_MAP.items():
        if rpc not in rpcs:
            failures.append(f"proto RPC absent: {rpc}")
        if f'"{command}"' not in all_go:
            failures.append(f"sealed operation {command!r} absent from Go implementation")
    extra_rpcs = set(rpcs) - set(RPC_MAP.keys())
    if extra_rpcs:
        failures.append(f"unmapped proto RPCs (second surface?): {sorted(extra_rpcs)}")

    # 2c. Go-carried sealed strings exist verbatim.
    for rel_path, values in GO_ONLY_STRINGS.items():
        text = go_text.get(rel_path, "")
        for value in values:
            if f'"{value}"' not in text:
                failures.append(f"sealed string {value!r} absent from {rel_path}")

    # 3. Additive compatibility: revision-9 field numbers pinned.
    for msg_name, pinned in PINNED_FIELDS.items():
        entry = messages.get(msg_name)
        if entry is None:
            failures.append(f"proto message absent: {msg_name}")
            continue
        _, fields = entry
        for field, number in pinned.items():
            if fields.get(field) != number:
                failures.append(
                    f"field renumber/moved: {msg_name}.{field} want ={number}, "
                    f"have ={fields.get(field)}"
                )

    # 3b. Revision-10 additions present where declared.
    for kind, name in REQUIRED_ADDITIONS:
        if kind == "message" and name not in messages:
            failures.append(f"revision-10 message absent: {name}")
        elif kind == "enum" and name not in enums:
            failures.append(f"revision-10 enum absent: {name}")
        elif kind == "service" and name not in services:
            failures.append(f"revision-10 service absent: {name}")

    # 3c. AttachmentRef lives authoritatively in attachment.proto only
    # (moved out of orchestration.proto in revision 10 with zero served
    # wire change): a second definition is a forked source of truth.
    attach_text = proto_texts[PROTOS[1]]
    orch_text = proto_texts[PROTOS[0]]
    if "message AttachmentRef" not in attach_text:
        failures.append("AttachmentRef absent from attachment.proto")
    if "message AttachmentRef" in orch_text:
        failures.append("AttachmentRef still defined in orchestration.proto (second source)")

    # 4. Migration-target agreement: XML authority equals Go enforcement.
    xml_count = None
    for elem in tree.getroot().iter():
        if elem.tag.endswith("}postgres-migrations-count") and elem.text:
            xml_count = elem.text.strip()
    go_target = None
    migration_go = os.path.join(root_dir, "contracts", "orchestration", "migration.go")
    with open(migration_go, encoding="utf-8") as f:
        match = re.search(r"PostgresMigrationTarget\s*=\s*(\d+)", f.read())
        if match:
            go_target = match.group(1)
    if xml_count is None:
        failures.append("XML postgres-migrations-count absent")
    elif go_target is None:
        failures.append("Go PostgresMigrationTarget absent")
    elif xml_count != go_target:
        failures.append(
            f"migration target drift: XML declares {xml_count} != Go enforces {go_target}"
        )

    # 5. No legacy xyz-b2b drift outside the documented compat go_package.
    for rel_path in LINKED_FILES:
        with open(os.path.join(root_dir, rel_path), encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                if "xyz-b2b" in line and GO_PACKAGE_COMPAT not in line:
                    failures.append(f"legacy drift {rel_path}:{lineno}: {line.strip()[:100]}")
    for rel_path, text in proto_texts.items():
        if GO_PACKAGE_COMPAT not in text:
            failures.append(f"compat go_package missing from {rel_path}")
        if "compatibility-only" not in text.lower():
            failures.append(f"go_package compatibility-only documentation missing from {rel_path}")

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
          f"{len(RPC_MAP)} RPCs agree across XML, protos, and Go "
          f"(+{sum(len(v) for v in PINNED_FIELDS.values())} pinned fields, migration target pinned)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
