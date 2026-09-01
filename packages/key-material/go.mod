module github.com/b2bautopilot/xyz-b2b/packages/key-material

go 1.26.2

require golang.org/x/crypto v0.54.0

require golang.org/x/sys v0.47.0 // indirect

replace github.com/b2bautopilot/xyz-b2b/services/builders-net => ../../services/builders-net

replace github.com/b2bautopilot/xyz-b2b/services/mesh-net => ../../services/mesh-net

replace github.com/b2bautopilot/xyz-b2b/services/builders-agent => ../../services/builders-agent

replace github.com/b2bautopilot/xyz-b2b/services/federation-gateway => ../../services/federation-gateway

replace github.com/b2bautopilot/xyz-b2b/services/federation-relay => ../../services/federation-relay

replace github.com/b2bautopilot/xyz-b2b/packages/component-identity => ../../packages/component-identity

replace github.com/b2bautopilot/xyz-b2b/packages/release-manifest => ../../packages/release-manifest

replace github.com/b2bautopilot/xyz-b2b/packages/app-errors => ../../packages/app-errors

replace github.com/b2bautopilot/xyz-b2b/packages/federation-contracts => ../../packages/federation-contracts
