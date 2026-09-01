# Inter-Enterprise Contracts & Action Catalogs

The inter-enterprise API surface: **action catalogs** — versioned, signed, policy-scoped contract packs that define the allowed actions enterprises expose to each other.

- **`contractpacks/ordertocash`** (`order_to_cash.v1`): Request for quote, quote submission, purchase order, order confirmation, shipment tracking, invoicing, and payment settlement.
- **`contractmanifest`**: Canonical Ed25519-signed manifest format, digest calculations, and keyring verification.
- **`contractapproval`**: Multi-tenant governance approval and signing records.
- **`exchange`**: Inter-enterprise gateway exchange protocol (`builders.federation.gateway_exchange.v1`).
- **`servicecatalog`**: Partner-visible service registry schemas and metadata.
- **`cmd/manifestsign`**: Authority CLI tool for minting and signing canonical manifest keyrings.
