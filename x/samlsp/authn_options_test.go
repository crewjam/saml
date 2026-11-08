package samlsp_test

import (
	"errors"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func TestAuthnRequestFieldOptions(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	proxyCount := 2

	msg, err := cfg.AuthnRequest(t.Context(), "s",
		samlsp.WithSubject(saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"}),
		samlsp.WithScoping(saml.Scoping{ProxyCount: &proxyCount, RequesterIDs: []string{"https://requester.example.com"}}),
		samlsp.WithIDPList("https://idp1.example.com", "https://idp2.example.com"),
		samlsp.WithProviderName("Example SP"),
		samlsp.WithAttributeConsumingServiceIndex(3),
		samlsp.WithAllowCreate(false),
		samlsp.WithSPNameQualifier("https://affiliation.example.com"),
		samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error {
			req.Consent = "urn:oasis:names:tc:SAML:2.0:consent:obtained"
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := decodeRedirectRequest(t, msg.RedirectURL())

	if req.Subject == nil || req.Subject.NameID == nil || req.Subject.NameID.Value != "alice@example.com" {
		t.Errorf("Subject = %+v", req.Subject)
	}
	if s := req.Scoping; s == nil || s.ProxyCount == nil || *s.ProxyCount != 2 || len(s.RequesterIDs) != 1 ||
		s.IDPList == nil || len(s.IDPList.IDPEntries) != 2 || s.IDPList.IDPEntries[1].ProviderID != "https://idp2.example.com" {
		t.Errorf("Scoping = %+v", req.Scoping)
	}
	if req.ProviderName != "Example SP" || req.AttributeConsumingServiceIndex != "3" ||
		req.Consent != "urn:oasis:names:tc:SAML:2.0:consent:obtained" {
		t.Errorf("request = %+v", req)
	}
	if p := req.NameIDPolicy; p == nil || p.AllowCreate == nil || *p.AllowCreate ||
		p.SPNameQualifier == nil || *p.SPNameQualifier != "https://affiliation.example.com" {
		t.Errorf("NameIDPolicy = %+v", req.NameIDPolicy)
	}

	// Errors from WithAuthnRequest and from the checks of the options.
	boom := errors.New("boom")
	if _, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithAuthnRequest(func(*saml.AuthnRequest) error { return boom })); !errors.Is(err, boom) {
		t.Errorf("err = %v, want boom", err)
	}
	if _, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithAttributeConsumingServiceIndex(70000)); err == nil {
		t.Error("an out-of-range AttributeConsumingServiceIndex was accepted")
	}
}

// TestAuthnRequestModifiedThenSigned checks that WithAuthnRequest runs before
// the request is signed: the IdP verifies the signature of a modified POST
// request.
func TestAuthnRequestModifiedThenSigned(t *testing.T) {
	ti := newTestIDP(t)
	ti.idp.WantAuthnRequestsSigned = true
	cfg := newTestConfig(t, ti, samlsp.SignAuthnRequests)
	msg, err := cfg.AuthnRequest(t.Context(), "s",
		samlsp.WithBinding(saml.HTTPPostBinding),
		samlsp.WithProviderName("Signed After"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
}

func TestWithACSIndex(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)

	msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithACSIndex(1))
	if err != nil {
		t.Fatal(err)
	}
	req := decodeRedirectRequest(t, msg.RedirectURL())
	if req.AssertionConsumerServiceIndex != "1" || req.AssertionConsumerServiceURL != "" || req.ProtocolBinding != "" {
		t.Errorf("request names the ACS by %q, %q, %q", req.AssertionConsumerServiceIndex, req.AssertionConsumerServiceURL, req.ProtocolBinding)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatalf("login by ACS index: %v", err)
	}

	if _, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithACSIndex(9)); err == nil {
		t.Error("an ACS index that is not in the metadata was accepted")
	}
}

// WithACSIndex accepts an index that WithMetadata adds to the published
// metadata.
func TestWithACSIndexFromMetadataHook(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti, samlsp.WithMetadata(func(md *saml.EntityDescriptor) {
		d := &md.SPSSODescriptors[0]
		d.AssertionConsumerServices = append(d.AssertionConsumerServices, saml.IndexedEndpoint{
			Binding: saml.HTTPPostBinding, Location: "https://sp.example.com/saml/acs2", Index: 7,
		})
	}))
	msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithACSIndex(7))
	if err != nil {
		t.Fatal(err)
	}
	if req := decodeRedirectRequest(t, msg.RedirectURL()); req.AssertionConsumerServiceIndex != "7" {
		t.Errorf("AssertionConsumerServiceIndex = %q", req.AssertionConsumerServiceIndex)
	}
}

// Nil options are skipped, as New skips them, rather than panicking.
func TestNilOptionsSkipped(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), nil, samlsp.WithRequestID(msg.ID), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Send(t.Context(), pingRequest(), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.Prepare(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	// QueryAttributes fails for want of an AttributeService, not a nil option.
	if _, err := cfg.QueryAttributes(t.Context(), saml.NameID{Value: "alice"}, nil); !errors.Is(err, samlsp.ErrNoEndpoint) {
		t.Fatalf("QueryAttributes: %v", err)
	}
}
