module github.com/b2bautopilot/xyz-b2b/packages/federation-contracts

go 1.26.2

replace github.com/b2bautopilot/xyz-b2b/services/builders-net => ../../services/builders-net

replace github.com/b2bautopilot/xyz-b2b/services/mesh-net => ../../services/mesh-net

replace github.com/b2bautopilot/xyz-b2b/services/builders-agent => ../../services/builders-agent

replace github.com/b2bautopilot/xyz-b2b/services/federation-gateway => ../../services/federation-gateway

replace github.com/b2bautopilot/xyz-b2b/services/federation-relay => ../../services/federation-relay

replace github.com/b2bautopilot/xyz-b2b/packages/component-identity => ../../packages/component-identity

replace github.com/b2bautopilot/xyz-b2b/packages/key-material => ../../packages/key-material

replace github.com/b2bautopilot/xyz-b2b/packages/release-manifest => ../../packages/release-manifest

replace github.com/b2bautopilot/xyz-b2b/packages/app-errors => ../../packages/app-errors

require (
	github.com/b2bautopilot/xyz-b2b/packages/app-errors v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.6.0
)
