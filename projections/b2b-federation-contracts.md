# B2B Federation Contracts — Authoritative Catalog

Spec version 1.7.0 (accepted). Generated deterministically from
spec/b2b-federation-spec-v1.xml — do not edit by hand.

## Components

| id | kind | name | status | rev |
| --- | --- | --- | --- | --- |
| comp.order-to-cash-v1 | business-service-contract | Order-to-Cash v1 Contract Pack | accepted | 2 |
| comp.x-mesh | userspace-wireguard-mesh | x-mesh WireGuard Substrate | accepted | 3 |
| comp.federation-relay | payload-blind-relay | Payload-Blind Relay Cells | accepted | 2 |
| comp.federation-gateway | enterprise-airlock-gateway | Enterprise Gateway Airlock | accepted | 2 |
| comp.builders-control | sovereign-control-plane | Sovereign Control Plane | accepted | 3 |
| comp.builders-agent | sandboxed-agent-runtime | Workstation Agent Runtime | accepted | 3 |
| comp.builders-portal | admin-portal | Builders Admin Portal | accepted | 4 |
| comp.builders-hub | operator-cockpit | Builders Hub Operator Cockpit | accepted | 2 |
| comp.sim-infra | simulation-infrastructure | Simulation Infrastructure | accepted | 5 |

### comp.order-to-cash-v1

7-stage cryptographic business transaction pack (RFQ -> Quote -> PO -> Confirm -> Ship -> Invoice -> Payment).

Fields: `protocol-pack=builders.federation.order_to_cash.v1`, `signature-algorithm=Ed25519`, `lifecycle-stages=rfq,quote,purchase_order,order_confirmation,shipment_notice,invoice,payment_settlement`

Source: `github.com/b2bautopilot/xx-federation-contracts`

### comp.x-mesh

Standalone WireGuard mesh daemon supporting kernel WireGuard on Linux, WireGuardNT on Windows, and wireguard-go on macOS/iOS with UDS control socket.

Fields: `userspace-engine=wireguard-go`, `socket-path=/run/x-mesh/sock`, `gossip-ttl-seconds=30`, `supported-engines=kernel_wireguard,wireguard_nt,wireguard_go`, `gossip-port=8442`, `fabric-port=4001`

Source: `github.com/b2bautopilot/xx-mesh-net`

### comp.federation-relay

GCP, AWS, and Azure standing relay cells with 12h/64GiB circuit budgets.

Fields: `circuit-protocol=libp2p/circuit-relay-v2`, `max-connection-duration-hours=12`, `max-connection-bandwidth-gib=64`, `payload-blind=true`

Source: `github.com/b2bautopilot/xx-federation-relay`

### comp.federation-gateway

Outbound-only gateway edge with zero open inbound public listeners and SPIFFE cert pinning.

Fields: `inbound-public-listeners=false`, `spiffe-trust-domain=builders-net`, `outbound-only=true`

Source: `github.com/b2bautopilot/xx-federation-gateway`

### comp.builders-control

Sole owner of Postgres storage with 57 migrations and fail-closed schema checks. Authoritative orchestration/attachment ledger and server projection for truthful multi-agent runs (issue #19).

Fields: `grpc-endpoint=127.0.0.1:9090`, `http-endpoint=127.0.0.1:8080`, `postgres-migrations-count=57`, `advisory-lock-hex=0x6232626d69677261`, `orchestration-ledger=run/task/event ledger with ordered observation stream, server-assigned sequence and visibility, and audit hash chain (contracts/orchestration)`, `attachment-ledger=content-addressed attachment objects with scoped fetch/return capabilities; events carry refs only, never bytes (contracts/attachment)`

Source: `github.com/b2bautopilot/xx-builders-net`

### comp.builders-agent

Containerized agent supervisor serving 16 coordination_* MCP tools on rootless podman overlay. Agent Kit container participant mode (one identity/session/container per PM, builder, and reviewer slot) with immutable runtime provenance verified before use (issue #19).

Fields: `mcp-socket-port=9210`, `supported-sandboxes=podman,apple_container,wsl2_containerd,gvisor`, `graph-driver-required=overlay`, `metadata-endpoints-denied=true`, `participant-mode=agentkit-container-participant`, `runtime-provenance=immutable OCI, Agent Kit, CLI, model, provider, network-policy and spec evidence verified against pins (contracts/provenance)`

Source: `github.com/b2bautopilot/xx-builders-agent`

### comp.builders-portal

Next.js 16 pure gRPC admin portal with zero direct SQL and strict BFF Command Architecture. Typed observation projection and BFF command evidence only; no direct ledger access (issue #19).

Fields: `framework=Next.js 16 / React 19`, `direct-sql-permitted=false`, `grpc-client-mode=pure-grpc-9090`, `command-architecture=bff-command-envelope.v1`, `observation-projection=partner-safe allowlisted event projection with cursor-resumed watch and explicit degraded/incomplete status (contracts/orchestration)`

Source: `github.com/b2bautopilot/xx-builders-portal`

### comp.builders-hub

Flutter multi-platform non-authoritative operator cockpit.

Fields: `framework=Flutter 3.41.4`, `authoritative=false`

Source: `github.com/b2bautopilot/xx-builders-hub`

### comp.sim-infra

OpenTofu GCP/AWS/Azure 100% container-native serverless infrastructure (Cloud Run, ECS Fargate, Azure Container Apps, Cloud SQL/RDS/Flexible Server) with zero compute VMs and dev/prod tiering. Orchestration participants run one identity/session/container each on GCP Cloud Run services/jobs and Azure Container Apps/Container Instances services/jobs; AWS stays ECS Fargate-only (issue #19).

Fields: `orchestrator=OpenTofu`, `supported-clouds=gcp,aws,azure`, `contract-spec=CONTRACT.md`, `pure-container-topology=true`, `vm-prohibition=true`, `builder-container-count-per-org=2`, `orchestration-runtimes=gcp-cloud-run,azure-container-apps,azure-container-instances,aws-ecs-fargate`

Source: `github.com/b2bautopilot/xx-sim-infra`

## Relationships

| id | kind | source | target | status | rev |
| --- | --- | --- | --- | --- | --- |
| rel.gateway-dials-relay | federation-transport-link | comp.federation-gateway | comp.federation-relay | accepted | 3 |
| rel.gateway-connects-control | control-facade-link | comp.federation-gateway | comp.builders-control | accepted | 2 |
| rel.agent-connects-control | agent-bidi-stream | comp.builders-agent | comp.builders-control | accepted | 2 |
| rel.portal-dials-control | client-rpc-link | comp.builders-portal | comp.builders-control | accepted | 2 |
| rel.hub-dials-control | client-rpc-link | comp.builders-hub | comp.builders-control | accepted | 1 |

### rel.gateway-dials-relay

Airlock gateways dial outbound to standing relay cells over circuit-relay-v2; the rendezvous control frame, the transport identity it carries, the relay-client certificate plane and the blind rendezvous key are the contracts both ends implement. The fabric keeps N-1 availability (loss of any one provider cell leaves an otherwise authorized exchange unblocked while two healthy cells stay reachable), dials ordered relay candidates under pre-existing bounded failover, and admits only proven end-to-end circuit evidence as circuit-relay-v2 success.

- evidence `n-minus-one-availability` -> `artifact.contracts.relayavailability`
- evidence `ordered-candidate-failover` -> `artifact.contracts.relayavailability`
- evidence `relay-readiness-levels` -> `artifact.contracts.relayavailability`
- evidence `circuit-evidence-rule` -> `artifact.contracts.relayavailability`
- evidence `downstream-consumers` -> `artifact.contracts.relayavailability`
- evidence `relaywire-control-frame` -> `artifact.contracts.relaywire`
- evidence `transport-identity` -> `artifact.contracts.transport`
- evidence `relay-client-certificate-plane` -> `artifact.contracts.gatewaycert-planes`
- evidence `blind-rendezvous-key` -> `artifact.contracts.orgregistry-rendezvous`

### rel.gateway-connects-control

Gateways call the local control plane via the narrow FederationService facade only; the facade IDL, its state and failure vocabularies, the receiver intake policy, the registration envelope schema, the certificate provider contract and the pool lease vocabulary are the contracts both sides implement.

- evidence `federation-service-idl` -> `artifact.contracts.federation-facade.proto`
- evidence `common-idl` -> `artifact.contracts.common.proto`
- evidence `facade-vocabulary` -> `artifact.contracts.facade`
- evidence `federation-state-vocabulary` -> `artifact.contracts.federationstate`
- evidence `receiver-intake-policy` -> `artifact.contracts.orgregistry-intake`
- evidence `gateway-registration-envelopes` -> `artifact.contracts.gatewayregistration`
- evidence `gateway-certificate-provider` -> `artifact.contracts.gatewaycert-provider`
- evidence `gateway-pool-lease` -> `artifact.contracts.gatewaypool`

### rel.agent-connects-control

Workstation agents connect to control plane over ConnectAgent / ConnectRuntime. The control owns the run/task/event/attachment ledger and ordered observation stream; agents join as authenticated Agent Kit container participants with immutable runtime provenance; attachment fetch and return happen by scoped capability carrying refs only, never bytes. Relays stay payload-blind: no orchestration semantics are added to relay cells.

- evidence `orchestration-run-ledger` -> `artifact.contracts.orchestration-ledger`
- evidence `agent-telemetry` -> `artifact.contracts.orchestration`
- evidence `attachment-capability` -> `artifact.contracts.attachment`
- evidence `runtime-provenance` -> `artifact.contracts.provenance`

### rel.portal-dials-control

Next.js Portal calls builders-control on gRPC :9090 with zero direct SQL. The portal sends BFF command/query envelopes and reads the typed observation projection with cursor-resumed watch; browser actor identity comes from the authenticated control context, never request fields, and every reply carries a signed audit receipt or an explicit degraded/incomplete status.

- evidence `bff-command-envelope` -> `artifact.contracts.orchestration-bff`
- evidence `observation-stream` -> `artifact.contracts.orchestration-visibility`
- evidence `attachment-evidence` -> `artifact.contracts.attachment`
- evidence `orchestration-idl` -> `artifact.contracts.orchestration-proto`

### rel.hub-dials-control

Flutter Hub reconciles snapshots against builders-control.


## Artifacts

| id | path | role | sha256 |
| --- | --- | --- | --- |
| artifact.contracts.order-to-cash.proto | api/proto/builders/v1/order_to_cash.proto | contract | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| artifact.contracts.federation-facade.proto | api/proto/builders/v1/federation.proto | contract | 65e9cc8acc4173821860c49a135e6a0dc09d86ffb7b060df3a56166e8b274d85 |
| artifact.contracts.common.proto | api/proto/builders/v1/common.proto | contract | 357ef6c3834a20742bc79187791145adefd58c3ae81da73377042965492224d3 |
| artifact.contracts.transport | contracts/transport/transport.go | contract | 83704dc589c960bf45305d0415fb4cfdc016c6d2eda1cb2aff8e03e8de2718b0 |
| artifact.contracts.transport-exchange | contracts/transport/exchange.go | contract | e9bff699d234167d5d67784f59c77c086ed9cd23cb63ed80da14baca5bc01daf |
| artifact.contracts.relaywire | contracts/relaywire/relaywire.go | contract | 64079bdc9b776448b02c0db23724976dede05edf8c075298a8c7e9c6ce2b3e25 |
| artifact.contracts.federationstate | contracts/federationstate/state.go | contract | 7e4d07b54ddd5022e84e160f031992b3559c32b4c369d950dcec8b3a9873fe85 |
| artifact.contracts.orgregistry-rendezvous | contracts/orgregistry/rendezvous.go | contract | 359646bfd51e81db3104a8025e2994cbd6624ab43aedc212c64bf32c4a7f2fc7 |
| artifact.contracts.orgregistry-intake | contracts/orgregistry/intake.go | contract | f6750659825aacd537afc3727a68179b177278e8a45f1b739471270974f9a2f0 |
| artifact.contracts.facade | contracts/facade/vocabulary.go | contract | d17406ece311b6ffa5265540ec73e2af1a4dc71d973cc965b09425c696a3852a |
| artifact.contracts.gatewayregistration | gatewayregistration/schema.go | contract | da27a4c4403030ff1c8db00610a706074337d3d1dbdf056cdc4a1f9a495fdaea |
| artifact.contracts.gatewaycert-planes | gatewaycert/plane.go | contract | f81b5edf5b87e2a787eac6eef7b1d22b7901fb3222b7903fdac05d4d9f516d38 |
| artifact.contracts.gatewaycert-provider | gatewaycert/provider.go | contract | b0f62df9af41596ffef1b248e92c06f40b183538a939e2d43a9003e425cf9cd3 |
| artifact.contracts.gatewaypool | gatewaypool/gatewaypool.go | contract | fdd68bb440d70652bb04cb36bd71cac38b1f653ff44927b53c92151239403e5e |
| artifact.contracts.relayavailability | contracts/relayavailability/availability.go | contract | f7868c1d3db0093fd7dc1760715480041418ba24a2085f5fdb2fe9175f7c1a1a |
| artifact.contracts.orchestration | contracts/orchestration/orchestration.go | contract | f0cbfaff3e8df120115be1882bf01a85ce2990759fa6fc533d70f7a545aacfd5 |
| artifact.contracts.orchestration-ledger | contracts/orchestration/ledger.go | contract | a522070637198794f55ee4c24cd62fa2153d96bc3278974c7f9c4033d9b6fa2b |
| artifact.contracts.orchestration-visibility | contracts/orchestration/visibility.go | contract | 731ef09858306f11f50a87e36de368476abeb365d53ccd6e6229136c72f23699 |
| artifact.contracts.orchestration-bff | contracts/orchestration/bff.go | contract | f89a468ee2d1ee53994d3c051598afcb67043339450ef89bb715924328c0f549 |
| artifact.contracts.attachment | contracts/attachment/attachment.go | contract | 18311d6530e4fced7157ddb1d7c65424ab9662919d22257bf5cf7ceb3ba115fa |
| artifact.contracts.provenance | contracts/provenance/provenance.go | contract | c110915ee41b472faa8c6ffea094b80606544e0025b8513f9adef575b4c717a0 |
| artifact.contracts.orchestration-proto | api/proto/builders/v1/orchestration.proto | contract | f61306a7052bc32eabb74fe1b5f6ba5c9814077a2ddc6582f0c04e9fcc01f82f |
| artifact.projection.spec-markdown | projections/b2b-federation-contracts.md | projection | derived |
| artifact.projection.spec-html | projections/b2b-federation-contracts.html | projection | derived |
| artifact.schema.system-specification | schemas/system-specification-v4.xsd | schema | efb60a221e950a9eb74f705961047055c2cfa40cc269ec6aac8d9131fd45b197 |
| artifact.schema.b2b-architecture | schemas/b2b-architecture-v1.xsd | schema | a007f2fd976ee6a6d1664f456f0af004798321d89e034c71fc0b87645891a9c8 |

## Sealed revisions

- revision 1: Sealed baseline architecture across all 9 sovereign repositories.
- revision 2: Sealed revision 2: sovereign repository source-pointers for all 9 components and agent runtime alignment (sandbox set and typed metadata-endpoint deny). The semantic-hash is the SHA-256 of the xmllint --c14n canonical form of this document with the bay:history element removed (its tail whitespace retained), so the hash covers every sealed section without self-reference.
- revision 3: Sealed revision 3: multi-platform WireGuard engine support and explicit x-mesh gossip and fabric port declarations, resolving Issue #11.
- revision 4: Sealed revision 4: multi-cloud environment tiering and isolation policy with dev/prod prefixing and project-level cloud boundary separation across GCP, AWS, and Azure.
- revision 5: Sealed revision 5: 100% container-native architecture transition across GCP Cloud Run, AWS ECS Fargate, and Azure Container Apps.
- revision 6: Sealed revision 6: pure container topology invariant (100% ECS Fargate, Cloud Run, Azure Container Apps) and hard VM prohibition across AWS, GCP, and Azure.
- revision 7: Sealed revision 7: contract artifacts and relationship evidence for the gateway-facing wire and facade types (issue #3 item 3); metadata 1.5.0. Semantic-hash computed as for revision 2 (SHA-256 of the xmllint --c14n canonical form with bay:history removed).
- revision 8: Sealed revision 8: N-1 relay-cell availability and machine-verifiable readiness contract with ordered candidate failover and circuit-only success evidence (issue #15); metadata 1.6.0. Semantic-hash computed as for revision 2 (SHA-256 of the xmllint --c14n canonical form with bay:history removed).
- revision 9: Sealed revision 9: truthful multi-agent orchestration, observation, attachment, and provenance contracts with the OrchestrationService formal API contract artifact (issue #19); metadata 1.7.0. Semantic-hash computed as for revision 2 (SHA-256 of the xmllint --c14n canonical form with bay:history removed).
