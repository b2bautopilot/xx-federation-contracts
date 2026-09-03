package gatewaycert

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProductionIssuancePreflightInput is the fail-closed gate that must pass
// before a caller enables production gateway certificate issuance.
type ProductionIssuancePreflightInput struct {
	Config    GatewayCertificateProviderConfig
	Provider  GatewayCertificateProvider
	Request   GatewayCertificatePlaneDescriptorRequest
	Now       time.Time
	MinActive time.Duration
}

func PreflightProductionIssuanceProvider(ctx context.Context, input ProductionIssuancePreflightInput) (TrustRootDescriptor, error) {
	cfg := input.Config
	if !cfg.Production {
		return TrustRootDescriptor{}, errors.New("production issuance preflight requires provider config production=true")
	}
	if !cfg.Kind.Valid() || cfg.Kind.NonProduction() {
		return TrustRootDescriptor{}, fmt.Errorf("production issuance preflight rejects provider kind %q", cfg.Kind)
	}
	if cfg.Kind != GatewayCertificateProviderKindExternalCA {
		return TrustRootDescriptor{}, fmt.Errorf("production issuance preflight has no go-live contract for provider kind %q", cfg.Kind)
	}
	if strings.TrimSpace(cfg.FabricID) == "" {
		return TrustRootDescriptor{}, errors.New("production issuance preflight requires provider fabric id")
	}
	if strings.TrimSpace(input.Request.FabricID) != "" && strings.TrimSpace(input.Request.FabricID) != strings.TrimSpace(cfg.FabricID) {
		return TrustRootDescriptor{}, fmt.Errorf("production issuance preflight fabric mismatch: provider=%q request=%q", cfg.FabricID, input.Request.FabricID)
	}
	if strings.TrimSpace(cfg.CACertFile) == "" || strings.TrimSpace(cfg.CAKeyFile) == "" {
		return TrustRootDescriptor{}, errors.New("production issuance preflight requires external_ca certificate and key files")
	}
	if input.Provider == nil {
		return TrustRootDescriptor{}, errors.New("production issuance preflight requires a gateway certificate provider")
	}
	productionProvider, ok := input.Provider.(GatewayCertificateProductionProvider)
	if !ok || !productionProvider.ProductionGatewayCertificateProvider() {
		return TrustRootDescriptor{}, errors.New("production issuance preflight requires a production-capable gateway certificate provider")
	}
	describer, ok := input.Provider.(GatewayCertificatePlaneDescriptorProvider)
	if !ok {
		return TrustRootDescriptor{}, errors.New("production issuance preflight requires a plane descriptor provider")
	}
	desc, err := describer.DescribeGatewayCertificatePlane(ctx, GatewayCertificatePlaneDescriptorRequest{
		Plane:     input.Request.Plane,
		FabricID:  strings.TrimSpace(input.Request.FabricID),
		OrgID:     strings.TrimSpace(input.Request.OrgID),
		GatewayID: strings.TrimSpace(input.Request.GatewayID),
	})
	if err != nil {
		return TrustRootDescriptor{}, err
	}
	desc = normalizeTrustRootDescriptor(desc)
	if err := validateTrustRootDescriptor(desc); err != nil {
		return TrustRootDescriptor{}, err
	}
	if desc.Plane != input.Request.Plane {
		return TrustRootDescriptor{}, fmt.Errorf("%w: descriptor plane %q does not match requested plane %q", ErrPlaneIdentityMismatch, desc.Plane, input.Request.Plane)
	}
	namespace, err := canonicalSPIFFENamespaceForPlane(input.Request.Plane)
	if err != nil {
		return TrustRootDescriptor{}, err
	}
	if desc.SPIFFENamespace != namespace {
		return TrustRootDescriptor{}, fmt.Errorf("%w: descriptor namespace %q is not canonical for plane %q", ErrPlaneIdentityMismatch, desc.SPIFFENamespace, input.Request.Plane)
	}
	if !desc.Production {
		return TrustRootDescriptor{}, fmt.Errorf("production issuance preflight rejects non-production descriptor %q", desc.ID)
	}
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !desc.ActivationNotBefore.IsZero() && now.Before(desc.ActivationNotBefore) {
		return TrustRootDescriptor{}, fmt.Errorf("production issuance preflight descriptor %q is not active yet", desc.ID)
	}
	if !desc.ActivationNotAfter.IsZero() && !now.Before(desc.ActivationNotAfter) {
		return TrustRootDescriptor{}, fmt.Errorf("production issuance preflight descriptor %q is expired", desc.ID)
	}
	if input.MinActive > 0 && !desc.ActivationNotAfter.IsZero() && now.Add(input.MinActive).After(desc.ActivationNotAfter) {
		return TrustRootDescriptor{}, fmt.Errorf("production issuance preflight descriptor %q expires before required active window %s", desc.ID, input.MinActive)
	}
	return desc, nil
}
