package samlsp_test

import (
	"bytes"
	"testing"

	"github.com/crewjam/saml/x/samlsp"
)

func TestReplayKey(t *testing.T) {
	k := samlsp.ReplayKey("https://idp.example.com/metadata", "_id-1")
	if len(k) != 32 {
		t.Fatalf("len = %d, want 32", len(k))
	}
	if !bytes.Equal(k, samlsp.ReplayKey("https://idp.example.com/metadata", "_id-1")) {
		t.Error("ReplayKey is not deterministic")
	}
	// Distinct pairs have distinct keys, including pairs whose
	// concatenations are equal.
	for _, other := range [][2]string{
		{"https://idp.example.com/metadata", "_id-2"},
		{"https://other.example.com/metadata", "_id-1"},
		{"https://idp.example.com/metadata_", "id-1"},
		{"https://idp.example.com/metadat", "a_id-1"},
		{"", "https://idp.example.com/metadata_id-1"},
	} {
		if bytes.Equal(k, samlsp.ReplayKey(other[0], other[1])) {
			t.Errorf("ReplayKey(%q, %q) collides", other[0], other[1])
		}
	}
}
