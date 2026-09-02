package membershipcap

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sort"
)

// ErrRosterAssembly is returned for an assembly-level input error (bad IssuedAtMS/TTLMS).
var ErrRosterAssembly = errors.New("fabric peer roster assembly invalid")

// RosterAssembly is the input to AssembleFabricPeerRoster: the VERIFIED registrations selected
// for a fabric plus the explicit de-peers for this epoch. Claims is []VerifiedMeshRegistration,
// so the PoP-check precondition is enforced by the TYPE SYSTEM (a claim reaches the assembler
// only via MeshRegistrationClaim.AsVerified). The caller — the control plane — selects which
// relays belong to the fabric and chooses a monotonic Epoch, a positive IssuedAtMS, and a
// positive (short) TTL. This function is the pure crypto composition (no DB, no policy beyond
// dedup + the tombstone/freshness resolution below).
type RosterAssembly struct {
	FabricID   string
	Epoch      int64                      // monotonic per fabric; must be >= 1
	IssuedAtMS int64                      // must be > 0; stamped into the roster + the TTL base
	TTLMS      int64                      // must be > 0; NotAfterMS = IssuedAtMS + TTLMS
	Claims     []VerifiedMeshRegistration // verified upstream via AsVerified
	Tombstones [][]byte                   // mesh ed25519 keys explicitly de-peered this epoch
}

// AssembleFabricPeerRoster builds and SIGNS a FabricPeerRoster from the assembly. It:
//   - requires a positive IssuedAtMS + TTLMS (a SHORT TTL is mandatory — never mint an immortal
//     roster) and guards the NotAfterMS sum against overflow;
//   - dedups the Tombstones;
//   - dedups Claims by mesh key, keeping the FRESHEST (highest IssuedAtMS; ties broken by PoP
//     bytes). Because Claims are VERIFIED, equal IssuedAtMS + equal PoP implies identical bound
//     content, so the assembly is fully order-independent;
//   - drops any claim whose key is TOMBSTONED (an explicit de-peer overrides a registration, so
//     the roster is never self-contradictory);
//   - projects survivors into PeerRosterEntries, sorts entries + tombstones deterministically;
//   - Validate()s the result (fail-closed — never signs a malformed roster) and Signs it.
func AssembleFabricPeerRoster(keyID string, priv ed25519.PrivateKey, a RosterAssembly) (FabricPeerRoster, error) {
	roster, err := BuildFabricPeerRoster(a)
	if err != nil {
		return FabricPeerRoster{}, err
	}
	return SignFabricPeerRoster(keyID, priv, roster)
}

// BuildFabricPeerRoster does everything AssembleFabricPeerRoster does EXCEPT signing: it
// validates the assembly inputs, dedups + tombstone-resolves + sorts the entries, and
// Validate()s the (unsigned) roster. Callers that hold the signing key only behind an
// interface (e.g. the control-plane MembershipSigner) build here, then sign via that
// interface's SignFabricPeerRoster. The returned roster has no SignerKeyID/Signature.
func BuildFabricPeerRoster(a RosterAssembly) (FabricPeerRoster, error) {
	if a.IssuedAtMS <= 0 || a.TTLMS <= 0 {
		return FabricPeerRoster{}, fmt.Errorf("%w: issued_at_ms and ttl_ms must both be > 0 (a short TTL is mandatory)", ErrRosterAssembly)
	}
	if a.TTLMS > math.MaxInt64-a.IssuedAtMS {
		return FabricPeerRoster{}, fmt.Errorf("%w: issued_at_ms + ttl_ms overflows", ErrRosterAssembly)
	}

	tomb := make(map[string]struct{}, len(a.Tombstones))
	tombstones := make([][]byte, 0, len(a.Tombstones))
	for _, t := range a.Tombstones {
		k := string(t)
		if _, dup := tomb[k]; dup {
			continue
		}
		tomb[k] = struct{}{}
		tombstones = append(tombstones, append([]byte(nil), t...))
	}

	// Dedup claims by mesh key, keeping the freshest; tombstoned keys are de-peered (skip). On
	// an IssuedAtMS tie, break deterministically by PoP bytes (verified claims always carry
	// one), so the signed roster is order-independent.
	latest := make(map[string]MeshRegistrationClaim, len(a.Claims))
	for _, v := range a.Claims {
		c := v.claim
		k := string(c.MeshPubKeyEd25519)
		if _, dead := tomb[k]; dead {
			continue
		}
		if prev, ok := latest[k]; ok {
			if prev.IssuedAtMS > c.IssuedAtMS {
				continue
			}
			if prev.IssuedAtMS == c.IssuedAtMS && bytes.Compare(prev.ProofOfPossession, c.ProofOfPossession) >= 0 {
				continue
			}
		}
		latest[k] = c
	}

	entries := make([]PeerRosterEntry, 0, len(latest))
	for _, c := range latest {
		entries = append(entries, c.ToRosterEntry())
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].MeshPubKeyEd25519, entries[j].MeshPubKeyEd25519) < 0
	})
	sort.Slice(tombstones, func(i, j int) bool {
		return bytes.Compare(tombstones[i], tombstones[j]) < 0
	})

	roster := FabricPeerRoster{
		FabricID:   a.FabricID,
		Epoch:      a.Epoch,
		IssuedAtMS: a.IssuedAtMS,
		NotAfterMS: a.IssuedAtMS + a.TTLMS,
		Entries:    entries,
		Tombstones: tombstones,
	}
	if err := roster.Validate(); err != nil {
		return FabricPeerRoster{}, err
	}
	return roster, nil
}
