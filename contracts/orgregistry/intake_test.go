package orgregistry

import (
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/gatewayregistration"
)

// TestDecideIntake_DecisionTable covers the receiver-owned intake precedence for
// inbound domain-reached requests, mirroring the pre-move source bodies.
func TestDecideIntake_DecisionTable(t *testing.T) {
	acme := "org-acme"
	cases := []struct {
		name    string
		policy  ReceiverIntakePolicy
		request IntakeRequest
		want    IntakePosture
	}{
		{
			"no verified identity drops",
			ReceiverIntakePolicy{DefaultPosture: IntakeAllowServiceRequest},
			IntakeRequest{VerifiedSenderOrgID: "", PayloadAssertedSenderOrgID: "", SenderStatus: gatewayregistration.OrgStatusActive},
			IntakeDrop,
		},
		{
			"asserted != verified drops (spoof cross-check)",
			ReceiverIntakePolicy{DefaultPosture: IntakeAllowServiceRequest},
			IntakeRequest{VerifiedSenderOrgID: acme, PayloadAssertedSenderOrgID: "other", SenderStatus: gatewayregistration.OrgStatusActive},
			IntakeDrop,
		},
		{
			"suspended sender denied",
			ReceiverIntakePolicy{DefaultPosture: IntakeAllowServiceRequest},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusSuspended},
			IntakeDeny,
		},
		{
			"blocked sender denied",
			ReceiverIntakePolicy{DefaultPosture: IntakeAllowServiceRequest, BlockedSenderOrgIDs: []string{acme}},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			IntakeDeny,
		},
		{
			"approved sender uses approved posture",
			ReceiverIntakePolicy{DefaultPosture: IntakeChallenge, ApprovedSenderPosture: IntakeAllowInvocation, ApprovedSenderOrgIDs: []string{acme}},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			IntakeAllowInvocation,
		},
		{
			"approved sender with empty approved posture defaults to allow_service_request",
			ReceiverIntakePolicy{DefaultPosture: IntakeChallenge, ApprovedSenderOrgIDs: []string{acme}},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			IntakeAllowServiceRequest,
		},
		{
			"unlisted sender uses default posture",
			ReceiverIntakePolicy{DefaultPosture: IntakeDrop},
			IntakeRequest{VerifiedSenderOrgID: "org-other", SenderStatus: gatewayregistration.OrgStatusActive},
			IntakeDrop,
		},
		{
			"unset default posture fails closed to challenge",
			ReceiverIntakePolicy{},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			IntakeChallenge,
		},
	}
	for _, c := range cases {
		got := DecideIntake(c.policy, c.request)
		if got.Posture != c.want {
			t.Errorf("%s: DecideIntake posture = %q, want %q", c.name, got.Posture, c.want)
		}
	}
}

// TestDecideDataChannel_DecisionTable covers the optional S4 bulk data-channel gate
// (default deny).
func TestDecideDataChannel_DecisionTable(t *testing.T) {
	acme := "org-acme"
	servicePolicy := ReceiverIntakePolicy{
		DefaultPosture:     IntakeAllowServiceRequest,
		DataChannelPosture: DataChannelAllow,
	}
	cases := []struct {
		name    string
		policy  ReceiverIntakePolicy
		request IntakeRequest
		want    bool
	}{
		{
			"receiver not opted in denies by default",
			ReceiverIntakePolicy{DefaultPosture: IntakeAllowServiceRequest, DataChannelPosture: DataChannelDeny},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			false,
		},
		{
			"catalog-only intake never yields a channel",
			ReceiverIntakePolicy{DefaultPosture: IntakeAllowLimitedCatalog, DataChannelPosture: DataChannelAllow},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			false,
		},
		{
			"service-level admitted sender granted channel when opted in",
			servicePolicy,
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			true,
		},
		{
			"non-production eligible status denies channel",
			servicePolicy,
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusSuspended},
			false,
		},
		{
			"dropped sender denies channel",
			ReceiverIntakePolicy{DefaultPosture: IntakeDrop, DataChannelPosture: DataChannelAllow},
			IntakeRequest{VerifiedSenderOrgID: acme, SenderStatus: gatewayregistration.OrgStatusActive},
			false,
		},
	}
	for _, c := range cases {
		got := DecideDataChannel(c.policy, c.request)
		if got.Granted != c.want {
			t.Errorf("%s: DecideDataChannel granted = %v, want %v (reason %q)", c.name, got.Granted, c.want, got.Reason)
		}
	}
}

// TestIntakePostureValidation_FailClosed ensures an unknown configured posture is
// rejected at policy-validate time.
func TestIntakePostureValidation_FailClosed(t *testing.T) {
	bad := ReceiverIntakePolicy{DefaultPosture: IntakePosture("bogus")}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected Validate to fail closed on unknown default posture")
	}
	badData := ReceiverIntakePolicy{DefaultPosture: IntakeAllowServiceRequest, DataChannelPosture: DataChannelPosture("maybe")}
	if err := badData.Validate(); err == nil {
		t.Fatal("expected Validate to fail closed on unknown data-channel posture")
	}
	good := servicePolicyType()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

func servicePolicyType() ReceiverIntakePolicy {
	return ReceiverIntakePolicy{DefaultPosture: IntakeAllowServiceRequest, DataChannelPosture: DataChannelAllow}
}
