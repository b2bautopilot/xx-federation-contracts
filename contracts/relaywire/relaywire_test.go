package relaywire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/transport"
)

// goldenFrames holds the compatibility vectors for the relaywire control frame
// contract (canonical source xx-federation-relay/relaywire at origin/dev
// 966f15b). The ported body is byte-identical (only the transport import path
// normalised); replaying these fixtures guards the length-prefixed control frame
// wire contract against silent drift.

func readRelayFixture(t *testing.T) map[string]string {
	t.Helper()
	paths := []string{
		filepath.Join("..", "..", "testdata", "parity", "relaywire.json"),
	}
	var raw []byte
	var err error
	for _, p := range paths {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("read relaywire parity fixture: %v", err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode relaywire parity fixture: %v", err)
	}
	return m
}

func TestGoldenWriteControlReplays(t *testing.T) {
	frames := readRelayFixture(t)
	wantTypes := []string{TypeRegister, TypeSubmit, TypeDeliver, TypeEstablished, TypeError, TypeBackplaneSubmit}
	for _, typ := range wantTypes {
		goldenHex, ok := frames[typ]
		if !ok {
			t.Fatalf("fixture missing frame type %q", typ)
		}
		golden, err := hex.DecodeString(goldenHex)
		if err != nil {
			t.Fatalf("%s: decode golden: %v", typ, err)
		}
		msg, err := ReadControl(bytes.NewReader(golden), 0)
		if err != nil {
			t.Fatalf("%s: ReadControl(golden): %v", typ, err)
		}
		if msg.Type != typ {
			t.Fatalf("%s: round-tripped type = %q", typ, msg.Type)
		}
		var buf bytes.Buffer
		if err := WriteControl(&buf, msg); err != nil {
			t.Fatalf("%s: WriteControl: %v", typ, err)
		}
		if got := hex.EncodeToString(buf.Bytes()); got != goldenHex {
			t.Fatalf("%s: rewritten frame = %s, want golden %s", typ, got, goldenHex)
		}
	}
}

func TestReadControl_RejectsOversizeFrameBeforeAllocation(t *testing.T) {
	// declare 8 MiB but cap is 64 KiB; must reject before reading body
	var prefix [4]byte
	prefix[0] = 0x00
	prefix[1] = 0x80 // 8 MiB >> 16
	prefix[2] = 0x00
	prefix[3] = 0x00
	_, err := ReadControl(bytes.NewReader(prefix[:]), 0)
	if !errors.Is(err, ErrControlFrameTooLarge) {
		t.Fatalf("expected ErrControlFrameTooLarge, got %v", err)
	}
}

func TestReadControl_RejectsEmptyFrame(t *testing.T) {
	var prefix [4]byte
	_, err := ReadControl(bytes.NewReader(prefix[:]), 0)
	if !errors.Is(err, ErrControlFrameEmpty) {
		t.Fatalf("expected ErrControlFrameEmpty, got %v", err)
	}
}

func TestReadControl_RejectsMalformedJSON(t *testing.T) {
	var buf bytes.Buffer
	body := []byte("{not json}")
	var prefix [4]byte
	prefix[0] = byte(len(body) >> 24)
	prefix[1] = byte(len(body) >> 16)
	prefix[2] = byte(len(body) >> 8)
	prefix[3] = byte(len(body))
	buf.Write(prefix[:])
	buf.Write(body)
	if _, err := ReadControl(&buf, 0); err == nil {
		t.Fatal("expected malformed JSON control frame to fail closed")
	}
}

func TestWriteControl_RejectsEmptyBody(t *testing.T) {
	// A zero-length body must be rejected by writeFrame (the empty-normalized JSON
	// for a fully-empty Control is `{"hop":0}` — never zero length — so we exercise
	// the guard directly at the writeFrame boundary below).
	if err := writeFrame(&bytes.Buffer{}, nil); !errors.Is(err, ErrControlFrameEmpty) {
		t.Fatalf("expected ErrControlFrameEmpty for empty body, got %v", err)
	}
}

func TestControlNormalized(t *testing.T) {
	msg := Control{
		Type:           " register ",
		Namespace:      " fed ",
		PresenceRef:    " pr ",
		ErrorCode:      " e ",
		TargetIdentity: transport.Identity{TenantID: " t ", GatewayID: " g "},
		SenderIdentity: transport.Identity{TenantID: " a "},
	}
	norm := msg.Normalized()
	if norm.Type != "register" || norm.Namespace != "fed" || norm.PresenceRef != "pr" || norm.ErrorCode != "e" {
		t.Fatalf("Normalized did not trim fields: %+v", norm)
	}
	if norm.TargetIdentity.TenantID != "t" || norm.SenderIdentity.TenantID != "a" {
		t.Fatalf("Normalized did not normalize identities: %+v", norm)
	}
}

// SanitizedErrorCode ensures a control frame's error code never carries internal
// host/IP topology that a forwarder error might otherwise expose.
func TestSanitizedErrorCode(t *testing.T) {
	for _, code := range []string{ErrorNoTarget, ErrorAtCapacity, ErrorUnauthorized, ErrorTimeout, ErrorMalformed, ErrorInternal} {
		if strings.TrimSpace(code) == "" {
			t.Fatalf("empty sanitized error code")
		}
		if strings.Contains(code, ".") || strings.Contains(code, ":") {
			t.Fatalf("error code leaks topology: %q", code)
		}
	}
}
