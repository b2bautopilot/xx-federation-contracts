# Inter-Enterprise Contracts & Action Catalogs

The inter-enterprise API surface: **action catalogs** — versioned, signed, policy-scoped contract packs that define the allowed actions enterprises expose to each other.

- **`contractpacks/ordertocash`** (`order_to_cash.v1`): Request for quote, quote submission, purchase order, order confirmation, shipment tracking, invoicing, and payment settlement.
- **`contractmanifest`**: Canonical Ed25519-signed manifest format, digest calculations, and keyring verification.
- **`contractapproval`**: Multi-tenant governance approval and signing records.
- **`exchange`**: Inter-enterprise gateway exchange protocol (`builders.federation.gateway_exchange.v1`).
- **`transport`**: Gateway-to-gateway transport identity, policy, negotiation and AES-GCM relay payload sealing.
- **`relaywire`**: Payload-blind relay rendezvous control frames (length-prefixed JSON).
- **`federationstate`**: Federation state vocabularies and usability predicates shared by control and gateway.
- **`orgregistry`**: Deterministic receiver rendezvous ids, blind presence-ref derivation and receiver intake decisions.
- **`facade`**: Facade vocabulary — outbound exchange states, failure classes, binding matchers, dev gateway headers.
- **`servicecatalog`**: Partner-visible service registry schemas and metadata.
- **`cmd/manifestsign`**: Authority CLI tool for minting and signing canonical manifest keyrings.
