#!/usr/bin/env python3
"""Deterministic Markdown/HTML projections of the authoritative spec.

Renders spec/b2b-federation-spec-v1.xml into human-readable catalogs under
projections/: component/relationship/artifact/revision tables. Output is
byte-deterministic (document order, fixed template, no timestamps): run with
no flags to regenerate, or with --check to fail on any byte difference
(clean-diff gate used by tools/projcheck and CI).

Self-reference rule: rows whose artifact role is "projection" render their
sha256 cell as "derived" instead of the declared value. The projections
embed the artifact table, so embedding their own sealed sha would make the
seal uncomputable; their bytes are pinned instead by the bay:artifact sha
(checked in scripts/validate-spec.py) plus this script's --check gate.

For the same reason the sealed-revision list renders numbers and summaries
only, never semantic-hash values: the semantic hash covers the artifact
section (including these projections' shas), so embedding it here would make
the seal uncomputable. Hashes live authoritatively in the XML.
"""

import os
import sys
import tempfile
import xml.etree.ElementTree as ET

BAY = "urn:baylife:system-specification:4.0"
NS = {"bay": BAY}

MARKDOWN_PATH = "projections/b2b-federation-contracts.md"
HTML_PATH = "projections/b2b-federation-contracts.html"


def local(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def text_of(elem):
    parts = []
    for node in elem.iter():
        if node.tag == f"{{{BAY}}}description" and node.text:
            parts.append(node.text.strip())
    return " ".join(parts)


def describe_component(comp):
    kind = local(comp.tag)
    desc = ""
    for child in comp:
        if local(child.tag) == "description" and child.text:
            desc = child.text.strip()
            break
    fields = []
    for child in comp:
        name = local(child.tag)
        if name in ("description",):
            continue
        fields.append(f"{name}={child.text.strip() if child.text else ''}")
    return kind, desc, fields


def build_model(root_dir):
    tree = ET.parse(os.path.join(root_dir, "spec", "b2b-federation-spec-v1.xml"))
    root = tree.getroot()
    meta = root.find("bay:metadata", NS)
    version = meta.attrib.get("version", "") if meta is not None else ""
    status = meta.attrib.get("status", "") if meta is not None else ""
    components = []
    comp_root = root.find("bay:components", NS)
    for comp in comp_root if comp_root is not None else []:
        kind, desc, fields = describe_component(comp)
        components.append({
            "id": comp.attrib.get("id", ""),
            "kind": kind,
            "name": comp.attrib.get("name", ""),
            "status": comp.attrib.get("status", ""),
            "revision": comp.attrib.get("revision", ""),
            "source": comp.attrib.get("source-pointer", ""),
            "description": desc,
            "fields": fields,
        })
    relationships = []
    rel_root = root.find("bay:relationships", NS)
    for rel in rel_root if rel_root is not None else []:
        evidence = []
        for ev in rel.findall("bay:evidence", NS):
            evidence.append((ev.attrib.get("key", ""), ev.attrib.get("artifact-ref", "")))
        desc = ""
        for child in rel:
            if local(child.tag) == "description" and child.text:
                desc = child.text.strip()
                break
        relationships.append({
            "id": rel.attrib.get("id", ""),
            "kind": local(rel.tag),
            "source": rel.attrib.get("source-ref", ""),
            "target": rel.attrib.get("target-ref", ""),
            "status": rel.attrib.get("status", ""),
            "revision": rel.attrib.get("revision", ""),
            "description": desc,
            "evidence": evidence,
        })
    artifacts = []
    for art in root.findall(".//bay:artifact", NS):
        artifacts.append({
            "id": art.attrib.get("id", ""),
            "path": art.attrib.get("path", ""),
            "role": art.attrib.get("role", ""),
            "sha256": art.attrib.get("sha256", ""),
        })
    revisions = []
    for rev in root.findall(".//bay:revision", NS):
        summary = ""
        for child in rev:
            if local(child.tag) == "summary" and child.text:
                summary = child.text.strip()
                break
        revisions.append({
            "number": rev.attrib.get("number", ""),
            "hash": rev.attrib.get("semantic-hash", ""),
            "summary": summary,
        })
    revisions.sort(key=lambda r: int(r["number"]))
    return version, status, components, relationships, artifacts, revisions


def render_markdown(version, status, components, relationships, artifacts, revisions):
    out = []
    out.append("# B2B Federation Contracts — Authoritative Catalog")
    out.append("")
    out.append(f"Spec version {version} ({status}). Generated deterministically from")
    out.append("spec/b2b-federation-spec-v1.xml — do not edit by hand.")
    out.append("")
    out.append("## Components")
    out.append("")
    out.append("| id | kind | name | status | rev |")
    out.append("| --- | --- | --- | --- | --- |")
    for c in components:
        out.append(f"| {c['id']} | {c['kind']} | {c['name']} | {c['status']} | {c['revision']} |")
    out.append("")
    for c in components:
        out.append(f"### {c['id']}")
        out.append("")
        out.append(c["description"])
        out.append("")
        if c["fields"]:
            out.append("Fields: " + ", ".join(f"`{f}`" for f in c["fields"]))
            out.append("")
        out.append(f"Source: `{c['source']}`")
        out.append("")
    out.append("## Relationships")
    out.append("")
    out.append("| id | kind | source | target | status | rev |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for r in relationships:
        out.append(f"| {r['id']} | {r['kind']} | {r['source']} | {r['target']} | {r['status']} | {r['revision']} |")
    out.append("")
    for r in relationships:
        out.append(f"### {r['id']}")
        out.append("")
        out.append(r["description"])
        out.append("")
        for key, ref in r["evidence"]:
            out.append(f"- evidence `{key}` -> `{ref}`")
        out.append("")
    out.append("## Artifacts")
    out.append("")
    out.append("| id | path | role | sha256 |")
    out.append("| --- | --- | --- | --- |")
    for a in artifacts:
        sha = "derived" if a["role"] == "projection" else a["sha256"]
        out.append(f"| {a['id']} | {a['path']} | {a['role']} | {sha} |")
    out.append("")
    out.append("## Sealed revisions")
    out.append("")
    for r in revisions:
        out.append(f"- revision {r['number']}: {r['summary']}")
    out.append("")
    return "\n".join(out)


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def render_html(version, status, components, relationships, artifacts, revisions):
    out = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en">')
    out.append("<head><meta charset=\"utf-8\">")
    out.append(f"<title>B2B Federation Contracts — spec {esc(version)}</title></head>")
    out.append("<body>")
    out.append("<h1>B2B Federation Contracts — Authoritative Catalog</h1>")
    out.append(f"<p>Spec version {esc(version)} ({esc(status)}). Generated deterministically")
    out.append("from spec/b2b-federation-spec-v1.xml.</p>")
    out.append("<h2>Components</h2>")
    out.append("<table><tr><th>id</th><th>kind</th><th>name</th><th>status</th><th>rev</th></tr>")
    for c in components:
        out.append(f"<tr><td>{esc(c['id'])}</td><td>{esc(c['kind'])}</td>"
                   f"<td>{esc(c['name'])}</td><td>{esc(c['status'])}</td>"
                   f"<td>{esc(c['revision'])}</td></tr>")
    out.append("</table>")
    out.append("<h2>Relationships</h2>")
    out.append("<table><tr><th>id</th><th>source</th><th>target</th><th>status</th><th>rev</th></tr>")
    for r in relationships:
        out.append(f"<tr><td>{esc(r['id'])}</td><td>{esc(r['source'])}</td>"
                   f"<td>{esc(r['target'])}</td><td>{esc(r['status'])}</td>"
                   f"<td>{esc(r['revision'])}</td></tr>")
    out.append("</table>")
    out.append("<h2>Artifacts</h2>")
    out.append("<table><tr><th>id</th><th>path</th><th>role</th><th>sha256</th></tr>")
    for a in artifacts:
        sha = "derived" if a["role"] == "projection" else a["sha256"]
        out.append(f"<tr><td>{esc(a['id'])}</td><td>{esc(a['path'])}</td>"
                   f"<td>{esc(a['role'])}</td><td>{esc(sha)}</td></tr>")
    out.append("</table>")
    out.append("<h2>Sealed revisions</h2>")
    out.append("<ul>")
    for r in revisions:
        out.append(f"<li>revision {esc(r['number'])}: {esc(r['summary'])}</li>")
    out.append("</ul>")
    out.append("</body>")
    out.append("</html>")
    out.append("")
    return "\n".join(out)


def generate(root_dir):
    model = build_model(root_dir)
    return {
        MARKDOWN_PATH: render_markdown(*model),
        HTML_PATH: render_html(*model),
    }


def main(argv):
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outputs = generate(root_dir)
    if "--check" in argv:
        failures = []
        for path, want in outputs.items():
            full = os.path.join(root_dir, path)
            if not os.path.exists(full):
                failures.append(f"projection absent: {path}")
                continue
            with open(full, "r", encoding="utf-8") as f:
                if f.read() != want:
                    failures.append(f"projection drift for {path}: regenerate with scripts/generate-projections.py")
        if failures:
            for f in failures:
                print(f"[FAIL] {f}", file=sys.stderr)
            return 1
        print(f"  --> PASS: {len(outputs)} spec projections clean (markdown + html)")
        return 0
    for path, content in outputs.items():
        full = os.path.join(root_dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  --> WROTE: {path} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
