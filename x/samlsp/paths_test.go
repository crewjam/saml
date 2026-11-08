package samlsp_test

import (
	"testing"

	"github.com/crewjam/saml/x/samlsp"
)

func TestPaths(t *testing.T) {
	ti := newTestIDP(t)
	for _, tt := range []struct {
		entityID string
		opts     []samlsp.Option
		metadata string
		acs      string
	}{
		{"https://sp.example.com/saml/metadata", nil, "/saml/metadata", "/saml/acs"},
		{"https://sp.example.com", nil, "/", "/acs"},
		{"https://sp.example.com/a%20b/metadata", nil, "/a%20b/metadata", "/a%20b/acs"},
		{"https://sp.example.com/saml/metadata", []samlsp.Option{samlsp.WithACSURL("https://sp.example.com/auth/callback")}, "/saml/metadata", "/auth/callback"},
		{"urn:example:sp", []samlsp.Option{samlsp.WithACSURL("https://sp.example.com/saml/acs")}, "", "/saml/acs"},
	} {
		cfg, err := samlsp.New(staticIDP(ti), tt.entityID, tt.opts...)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.MetadataPath(); got != tt.metadata {
			t.Errorf("%s: MetadataPath = %q, want %q", tt.entityID, got, tt.metadata)
		}
		if got := cfg.ACSPath(); got != tt.acs {
			t.Errorf("%s: ACSPath = %q, want %q", tt.entityID, got, tt.acs)
		}
	}
}
