package gatewayregistration

import "testing"

func TestIsKnownOrgStatus(t *testing.T) {
	known := []OrgStatus{
		OrgStatusActive, OrgStatusVerifiedBusiness, OrgStatusDomainVerified,
		OrgStatusDraft, OrgStatusDomainPending, OrgStatusKYGPending,
		OrgStatusDomainReverificationRequired, OrgStatusReviewHold,
		OrgStatusSuspendedPendingAppeal, OrgStatusSuspended, OrgStatusRevoked,
		OrgStatusDeleted, OrgStatusPermanentlyBarred, OrgStatusUnknownOrg,
	}
	for _, s := range known {
		if !IsKnownOrgStatus(s) {
			t.Errorf("IsKnownOrgStatus(%q) = false, want true", s)
		}
	}
	for _, s := range []OrgStatus{"", "garbage", "Active", "ACTIVE", "domain"} {
		if IsKnownOrgStatus(s) {
			t.Errorf("IsKnownOrgStatus(%q) = true, want false", s)
		}
	}
}
