# x-federation-contracts

**End-state repo (ADR 0010, established 2026-06-10). Code currently lives in
`x-builders-net/internal/federation/contractpacks` and migrates here as the
catalog grows.**

The inter-enterprise API surface: **action catalogs** — versioned, signed,
policy-scoped contract packs that define the allowed actions enterprises expose
to each other.

- `order_to_cash.v1` — request_for_quote → submit_quote → submit_purchase_order
  → confirm_order → update_shipment_status → issue_invoice →
  update_payment_status (7 interactions, payload schemas + result contracts).
- `communications.v1` — transaction-bound federated rooms + messages (the
  conversation lane).

This repo exists so partners can consume the contracts without running our
stack, and so catalogs version independently of the platform.
