# Spec-Driven Development (SDD) Guide for `xx-federation-contracts`

`xx-federation-contracts` is the **Level 0 Root Specification Authority** for the entire `b2bautopilot` sovereign federation fleet.

---

## 1. Single Source of Truth

The single authoritative specification for the B2B federation platform is:
```text
spec/b2b-federation-spec-v1.xml
```
Governed by:
- `schemas/system-specification-v4.xsd` (Baylife meta-schema)
- `schemas/b2b-architecture-v1.xsd` (B2B federation domain profile)

---

## 2. The Spec-Driven Workflow (Rule for Developers & AI Agents)

Whenever a contract, RPC, data structure, or architectural boundary changes:

1. **Update the Spec First**:
   - Edit `spec/b2b-federation-spec-v1.xml` to declare the new component, relationship, field, or invariant.
   - Run `python3 scripts/validate-spec.py` to ensure schema validity and reference integrity.
2. **Project the Contracts**:
   - Update the Protocol Buffers in `api/proto/builders/v1/`.
   - Update Go struct implementations in `contracts/`, `identity/`, `keymaterial/`, etc.
3. **Commit & Seal**:
   - Record the change summary and seal the revision in `spec/b2b-federation-spec-v1.xml`.
   - Run `go test -v -race ./...`.
4. **Propagate Downstream**:
   - Downstream repositories (`xx-builders-net`, `xx-federation-gateway`, `xx-builders-portal`, etc.) update their dependencies to consume the new contracts.

---

## 3. Strict Invariants
- **No Free-Text Component References**: All component relationships must point to registered IDs in `spec/b2b-federation-spec-v1.xml`.
- **Zero Business Logic in Relays**: Relays only splice ciphertext; business payloads live strictly in `order_to_cash.v1` and contract packs.
- **Fail-Closed CI**: Any PR that introduces broken references or syntax errors in the XML spec will fail the GitHub Actions `validate-spec` job.
