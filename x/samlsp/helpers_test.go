package samlsp_test

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// FormFields gives the fields of a POST message, which Write posts, and
// nothing for a redirect.
func TestMessageFormFields(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)

	post, err := cfg.AuthnRequest(t.Context(), "state-1", samlsp.WithBinding(saml.HTTPPostBinding))
	if err != nil {
		t.Fatal(err)
	}
	fields := post.FormFields()
	if fields.Get("RelayState") != "state-1" || fields.Get("SAMLRequest") == "" {
		t.Fatalf("FormFields = %v", fields)
	}
	xml, err := base64.StdEncoding.DecodeString(fields.Get("SAMLRequest"))
	if err != nil || !strings.Contains(string(xml), `ID="`+post.ID+`"`) {
		t.Errorf("SAMLRequest is not the AuthnRequest %s: %s (%v)", post.ID, xml, err)
	}
	// They are the fields Write posts.
	if got := formValues(writeBody(post)); got.Get("SAMLRequest") != fields.Get("SAMLRequest") || got.Get("RelayState") != "state-1" {
		t.Errorf("Write posts %v, FormFields gives %v", got, fields)
	}
	// The caller gets a copy.
	fields.Set("RelayState", "changed")
	if post.FormFields().Get("RelayState") != "state-1" {
		t.Error("changing FormFields' result changed the message")
	}

	redirect, err := cfg.AuthnRequest(t.Context(), "state-2", samlsp.WithBinding(saml.HTTPRedirectBinding))
	if err != nil {
		t.Fatal(err)
	}
	if f := redirect.FormFields(); f != nil {
		t.Errorf("FormFields of a redirect = %v, want nil", f)
	}
}

func TestWithForceAuthn(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	for _, tc := range []struct {
		name string
		opts []samlsp.AuthnOption
		want bool
	}{
		{"WithForceAuthn(true)", []samlsp.AuthnOption{samlsp.WithForceAuthn(true)}, true},
		{"WithForceAuthn(false)", []samlsp.AuthnOption{samlsp.WithForceAuthn(false)}, false},
		{"ForceAuthn, then WithForceAuthn(false)", []samlsp.AuthnOption{samlsp.ForceAuthn, samlsp.WithForceAuthn(false)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := cfg.AuthnRequest(t.Context(), "s", append(tc.opts, samlsp.WithBinding(saml.HTTPPostBinding))...)
			if err != nil {
				t.Fatal(err)
			}
			xml, err := base64.StdEncoding.DecodeString(msg.FormFields().Get("SAMLRequest"))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(xml), `ForceAuthn="true"`); got != tc.want {
				t.Errorf("ForceAuthn=\"true\" in the request: %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAttributesLegacyGet(t *testing.T) {
	attrs := samlsp.Attributes{
		{Name: "urn:oid:0.9.2342.19200300.100.1.3", FriendlyName: "mail", Values: []string{"alice@example.com"}},
		{Name: "urn:oid:2.5.4.42", FriendlyName: "givenName", Values: []string{"Alice"}},
		// An attribute whose Name is another's FriendlyName wins.
		{Name: "givenName", Values: []string{"Alice by Name"}},
		{Name: "empty", FriendlyName: "blank"},
	}
	for name, want := range map[string]string{
		"urn:oid:0.9.2342.19200300.100.1.3": "alice@example.com",
		"mail":                              "alice@example.com",
		"givenName":                         "Alice by Name",
		"blank":                             "",
		"missing":                           "",
	} {
		if got := attrs.LegacyGet(name); got != want {
			t.Errorf("LegacyGet(%q) = %q, want %q", name, got, want)
		}
	}
}

// writeBody returns the page msg.Write writes.
func writeBody(msg *samlsp.Message) string {
	w := httptest.NewRecorder()
	msg.Write(w)
	return w.Body.String()
}
