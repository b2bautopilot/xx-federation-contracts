module github.com/b2bautopilot/xyz-b2b/packages/component-identity

go 1.26.2

replace github.com/b2bautopilot/xyz-b2b/services/builders-net => ../../services/builders-net

replace github.com/b2bautopilot/xyz-b2b/services/mesh-net => ../../services/mesh-net

replace github.com/b2bautopilot/xyz-b2b/services/builders-agent => ../../services/builders-agent

replace github.com/b2bautopilot/xyz-b2b/services/federation-gateway => ../../services/federation-gateway

replace github.com/b2bautopilot/xyz-b2b/services/federation-relay => ../../services/federation-relay

replace github.com/b2bautopilot/xyz-b2b/packages/key-material => ../../packages/key-material

replace github.com/b2bautopilot/xyz-b2b/packages/release-manifest => ../../packages/release-manifest

replace github.com/b2bautopilot/xyz-b2b/packages/app-errors => ../../packages/app-errors

replace github.com/b2bautopilot/xyz-b2b/packages/federation-contracts => ../../packages/federation-contracts

require (
	github.com/b2bautopilot/xyz-b2b/packages/app-errors v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.82.0
)

require (
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260630182238-925bb5da69e7 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
