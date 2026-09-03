# `xx-federation-contracts` — Agent & Developer Onboarding Guide

Welcome to **`xx-federation-contracts`** (`github.com/b2bautopilot/xx-federation-contracts`), the sovereign federation contracts, schemas, and cryptographic identity foundation for **B2B Autopilot / Builders Net**.

This document is the authoritative onboarding guide for both human engineers and AI coding agents working in this repository. Read this file completely before authoring or modifying code.

---

## 1. Repository Purpose & System Context

In the B2B Autopilot architecture, independent enterprises operate sovereign control planes and private meshes with no inbound public access. Enterprises federate through outbound-only gateways meeting at a payload-blind multi-cloud relay fabric.

`xx-federation-contracts` represents **Target Repository #6** under **ADR 0009 / ADR 0010** (Decoupling Monorepo `xyz-b2b` into 9 sovereign repositories).

### What this repository IS:
- The single source of truth for inter-enterprise API contracts, wire protocols, and contract packs (`order_to_cash.v1`).
- The canonical provider of SPIFFE/mTLS component identities and cryptographic verification primitives.
- The provider of Ed25519 signing material abstractions (audit signing, SSH CA, fabric membership, service access).
- The definition of universal application error codes and build provenance release manifests.

### What this repository IS NOT:
- It does **NOT** own Postgres databases or stateful storage (Postgres is strictly owned by `xx-builders-net`).
- It does **NOT** manage container sandboxes, execution lifecycles, or LLM agents (owned by `xx-builders-agent`).
- It does **NOT** run network servers, libp2p nodes, or WireGuard daemons (owned by `xx-federation-gateway`, `xx-federation-relay`, and `xx-mesh-net`).

---

## 2. Non-Negotiable Architectural Invariants

Every change in this repository must preserve the following core invariants:

### Invariant 1: Zero Business Logic in Transport
- Inter-enterprise exchange schemas and payloads must separate transport framing from business domain operations.
- Relays (`xx-federation-relay`) must remain completely payload-blind, handling only ciphertext splicing and gossip presence.
- Gateways (`xx-federation-gateway`) must enforce contract preflights using the schema validators defined here without baking in bespoke workflow logic.

### Invariant 2: Ed25519 Cryptographic Manifests & Signatures
- All manifests, governance approvals, and capability tokens are signed with Ed25519 keys.
- Digest calculations must operate on canonicalized, byte-identical serializations.
- Manifest verification is fail-closed: invalid signatures, unknown key IDs, or mismatched digests must be rejected immediately.

### Invariant 3: SPIFFE Identity & Trust Domain Enforcement
- Internal component identities strictly follow the `builders-net` trust domain:
  - Workloads: `spiffe://builders-net/workload/...`
  - Gateways: `spiffe://builders-net/federation-gateway/tenant/<tenant>/gateway/<gateway>`
  - Agents: `x-builders-agent://tenant/<tenant>/project/<project>/node/<node>`
- Mutual TLS must verify client certificates against the authorized CA bundle.
- External federation certificate planes (`gatewaycert`) use their own declared SPIFFE namespaces and plane CAs, recorded in `spec/b2b-federation-spec-v1.xml` (`artifact.contracts.gatewaycert-planes`); they never reuse the internal `builders-net` trust domain:
  - Relay-client leaves (ClientAuth): `spiffe://relay.b2bautopilot.com/.../role/relay-client`
  - Gateway transport-server leaves (ServerAuth, DNS-SAN-bound): `spiffe://gateway-transport.b2bautopilot.com/.../role/transport-server`
  - Gateway business-facade leaves (ClientAuth): `spiffe://gateway.b2bautopilot.com/.../role/business-facade`
  - Relay-cell backplane / cell-server leaves (ClientAuth / ServerAuth, DNS-SAN-bound): `spiffe://relay-cell.b2bautopilot.com/.../role/backplane`, `/role/backplane-server`, `/role/server`

### Invariant 4: Fail-Closed Security & Sanitized Errors
- Error messages must never leak internal network topology, private IPs (e.g. `10.x.x.x`, `192.168.x.x`), unredacted SPIFFE internals, or private keys.
- Unknown fields in capability tokens or manifest structures must not cause security bypasses.

### Invariant 5: Clean, Self-Contained Go Module
- `go.mod` must remain completely self-contained with **zero local `replace` directives**.
- Dependencies must be strictly scoped to standard libraries and essential vetted packages (`google.golang.org/grpc`, `golang.org/x/crypto`, `github.com/google/uuid`).

### Invariant 6: Pure Container Topology & Strict VM Prohibition
- All enterprise simulation services across AWS, Azure, and GCP must execute strictly on serverless container runtimes:
  - **AWS**: AWS ECS Fargate (`control`, `gateway`, `builder1`, `builder2`, and `dev-awsrelay-service`). Zero EC2 virtual machines or EBS volumes.
  - **Azure**: Azure Container Apps (ACA) & Azure Container Instances (ACI) (`control`, `gateway`, `builder1`, `builder2`, and `dev-azurerelay-aci`). Zero persistent compute VMs.
  - **GCP**: Google Cloud Run (v2) serverless services (`control`, `gateway`, `builder1`, `builder2`). Zero host compute VMs (only single `dev-gcprelay` VM exception permitted for direct raw TCP port 4101 ingress).
- Any infrastructure change proposing compute VMs for gateway, control plane, or builder daemons is an adversarial regression violating sealed **Revision 6** (`spec/b2b-federation-spec-v1.xml`).

---

## 3. Directory & Package Layout

```
xx-federation-contracts/
├── api/proto/builders/v1/          # Facade IDL projections (federation.proto, common.proto)
├── apperrors/                      # Shared error taxonomy & codes
│   └── errors.go
├── contracts/                      # Inter-enterprise contract definitions
│   ├── cmd/manifestsign/           # CLI tool for manifest authority signing
│   │   └── main.go
│   ├── contractapproval/           # Multi-tenant contract approval & signing records
│   │   ├── approval.go
│   │   └── approval_test.go
│   ├── contractmanifest/           # Ed25519 signed manifest format & verifier
│   │   ├── manifest.go
│   │   ├── manifest_race_test.go
│   │   └── manifest_test.go
│   ├── contractpacks/              # Concrete business interaction packs
│   │   └── ordertocash/            # Order-to-Cash v1 state machine & schemas
│   │       ├── pack.go
│   │       └── pack_test.go
│   ├── exchange/                   # Gateway exchange protocol v1
│   │   ├── discovery.go
│   │   ├── exchange.go
│   │   └── *_test.go
│   ├── facade/                     # Facade vocabulary: exchange states, failure classes, binding matchers
│   ├── federationstate/            # Federation state vocabularies & usability predicates
│   ├── orgregistry/                # Rendezvous ids, presence-ref, intake policy & decisions
│   ├── relaywire/                  # Payload-blind relay rendezvous control frames
│   ├── transport/                  # Gateway-to-gateway transport & AES-GCM relay sealing
│   └── servicecatalog/             # Partner-visible service registry schemas
│       ├── servicecatalog.go
│       └── servicecatalog_test.go
├── gatewaycert/ (+testonly/)       # Certificate planes, SPIFFE builders, provider contract
├── gatewaypool/                    # Gateway pool coordinator lease vocabulary
├── gatewayregistration/            # relay-mesh-registration.v0 envelopes, JCS canonicalisation
├── identity/                       # SPIFFE identity, mTLS credentials, CA & CSR
│   ├── certcheck.go
│   ├── certissue.go
│   ├── csrverify.go
│   ├── identity.go
│   ├── provider.go
│   ├── tls.go
│   └── *_test.go
├── keymaterial/                    # Ed25519 signing key providers (Audit, SSH, Fabric)
│   ├── keymaterial.go
│   └── *_test.go
├── release/                        # Release manifest, provenance, acceptance records
│   ├── acceptance.go
│   ├── production_evidence.go
│   ├── release.go
│   └── *_test.go
├── scripts/                        # validate-spec.py, check-projections.py
├── testdata/parity/                # Golden compatibility vectors + paritygen replays
├── go.mod
├── go.sum
├── README.md
├── AGENTS.md
└── SPEC-DRIVEN-DEVELOPMENT.md
```

---

## 4. Subsystem Deep Dives

### `contracts/contractmanifest`
- Defines `Manifest` and `SignedDocument`.
- Canonicalizes manifest payloads using deterministic JSON encoding before signing.
- Computes SHA-256 manifest hash `ManifestHashSHA256`.
- `Verify(SignedDocument, PublicKey)` provides thread-safe, race-tested signature verification.

### `contracts/contractpacks/ordertocash`
- Implements the 7 core interactions of `order_to_cash.v1`:
  1. `request_for_quote`: Initial buyer inquiry with line items and delivery terms.
  2. `submit_quote`: Seller quote response with price schedules and validity periods.
  3. `submit_purchase_order`: Buyer purchase order referencing quote hash.
  4. `confirm_order`: Seller order confirmation.
  5. `update_shipment_status`: Carrier/seller tracking updates.
  6. `issue_invoice`: Structured payment request with tax details.
  7. `update_payment_status`: Remittance confirmation and settlement status.
- Strict payload validation enforces schema adherence, preventing payload tampering or malformed transactions.

### `identity`
- Extracts typed identities (`RuntimeIdentity`, `AgentIdentity`, `GatewayIdentity`) directly from `credentials.AuthInfo` in gRPC context.
- Configures mTLS via `ServerTransportCredentials` and `ClientTransportCredentials` with embedded SAN verification and CRL checking.

### `keymaterial`
- Separates cryptographic keys by security domain:
  - `DevLocalAuditSigningKey()`: Deterministic audit log signer for local development.
  - `DevLocalMembershipSigningKey()`: libp2p network admission capability signer.
  - `DevLocalServiceAccessSigningKey()`: Sovereign microservice exposure (`fed-svc`) capability signer.
  - `ProviderConfig`: Production loader integrating with KMS and Vault mounted secrets.

---

## 5. Development & Testing Workflow

### Running Tests
Always verify your changes before submitting:

```bash
# Verify build
go build ./...

# Run all unit and race detector tests
go test -count=1 -race ./...
```

### Adding New Schemas or Contract Packs
When introducing a new contract pack or expanding an existing contract:
1. **Consult `SPEC-DRIVEN-DEVELOPMENT.md`** for schema evolution and backward compatibility rules.
2. Ensure all fields are additive and optional if modifying existing structs.
3. Write comprehensive unit tests including negative validation cases and serialization round-trips.
4. Verify that no private data or local absolute paths are leaked into error messages.
