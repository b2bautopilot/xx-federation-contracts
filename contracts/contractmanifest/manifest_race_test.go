package contractmanifest

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/exchange"
)

// TestMemoryCacheResolveManifestConcurrentNoRace exercises the data race in
// (*MemoryCache).ResolveManifest. ResolveManifest re-verifies the cached manifest
// on every call, and Verify -> normalizeManifest mutates manifest.Contracts[i]
// in place and sort.SliceStable's the slice. Because the cached manifest's
// Contracts slice header still points to the backing array stored in the cache
// map, concurrent ResolveManifest calls write to and sort the SAME shared array.
//
// The manifest below carries two contracts in an order the sort reorders, so the
// per-element normalize writes AND the sort swap both touch a multi-element
// backing array. Run under `go test -race`: this fails (data race) before the
// fix that makes normalizeManifest operate on a fresh Contracts copy.
func TestMemoryCacheResolveManifestConcurrentNoRace(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}

	manifest := validManifest()
	// Second contract whose sort key orders BEFORE the first, so
	// normalizeManifest's sort.SliceStable swaps the two elements.
	manifest.Contracts = append(manifest.Contracts, Contract{
		ContractID:                 "aaa.catalog_view.request.v1",
		ContractVersion:            "1.0.0",
		Action:                     exchange.ActionGetServiceCatalogView,
		PayloadSchemaRef:           "schemas/catalog_view.v1.json",
		PayloadSchemaHashSHA256:    payloadSchemaHash(),
		MaxPayloadBytes:            4096,
		RequiresIdempotency:        false,
		ReplayWindowSeconds:        86400,
		AllowedPartnerLinkIDs:      []string{"plnk-a-b"},
		AllowedGatewayMethodScopes: []string{"federation.get_service_catalog_view"},
		EgressPolicyRef:            "egress.catalog_view",
		AuditClass:                 "catalog",
		RetentionClass:             "catalog",
	})

	signed, err := Sign(manifest, privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}

	cache := NewMemoryCache(Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
	if err := cache.PutVerified(context.Background(), signed); err != nil {
		t.Fatalf("PutVerified error = %v", err)
	}

	ref := exchange.ContractRef{
		ContractID:              testContractID,
		ContractVersion:         testContractVer,
		ManifestHashSHA256:      signed.ManifestHashSHA256,
		PayloadSchemaHashSHA256: payloadSchemaHash(),
	}

	const goroutines = 16
	const iterations = 64

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				if _, err := cache.ResolveManifest(context.Background(), ref); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("ResolveManifest under concurrency error = %v", err)
	}
}
