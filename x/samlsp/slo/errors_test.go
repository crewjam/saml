package slo_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
)

func TestModifyErrors(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, []slo.EndpointOption{slo.BackChannel})
	boom := errors.New("boom")
	failRequest := samlsp.WithModify(func(*saml.LogoutRequest) error { return boom })
	failResponse := samlsp.WithModify(func(*saml.LogoutResponse) error { return boom })

	if _, err := s.Request(t.Context(), saml.NameID{Value: "alice"}, "r", failRequest); !errors.Is(err, boom) {
		t.Errorf("Request: %v", err)
	}
	if _, err := s.Response(t.Context(), &slo.Request{ID: "id-1"}, failResponse); !errors.Is(err, boom) {
		t.Errorf("Response: %v", err)
	}
	if _, err := s.Response(t.Context(), &slo.Request{ID: "id-1", Binding: saml.SOAPBinding}, failResponse); !errors.Is(err, boom) {
		t.Errorf("SOAP Response: %v", err)
	}
	if _, err := s.SendRequest(t.Context(), saml.NameID{Value: "alice"}, failRequest); err == nil {
		t.Error("SendRequest ignored the error of WithModify")
	}
}

func TestMetadataUnavailable(t *testing.T) {
	key, cert := newKeyPair(t)
	down := func(context.Context) (*saml.EntityDescriptor, error) { return nil, errors.New("metadata unavailable") }
	cfg, err := samlsp.New(down, spEntityID, samlsp.WithSigningKey(key, cert), slo.Endpoint(spSLOURL, slo.BackChannel))
	if err != nil {
		t.Fatal(err)
	}
	s, err := slo.New(cfg)
	if err != nil {
		t.Fatal(err) // New does not need the IdP's metadata
	}

	if _, err := s.Request(t.Context(), saml.NameID{Value: "alice"}, "r"); err == nil {
		t.Error("Request")
	}
	if _, err := s.Response(t.Context(), &slo.Request{ID: "id-1"}); err == nil {
		t.Error("Response")
	}
	if _, err := s.Response(t.Context(), &slo.Request{ID: "id-1", Binding: saml.SOAPBinding}); err == nil {
		t.Error("SOAP Response")
	}
	if _, err := s.ParseRequest(t.Context(), postForm(spSLOURL, nil)); err == nil {
		t.Error("ParseRequest")
	}
	if _, err := s.ParseResponse(t.Context(), postForm(spSLOURL, nil), "id-1"); err == nil {
		t.Error("ParseResponse")
	}
	if _, err := s.SendRequest(t.Context(), saml.NameID{Value: "alice"}); err == nil {
		t.Error("SendRequest")
	}
}

func TestParseMalformed(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, nil)
	bad := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, spSLOURL, strings.NewReader("SAMLResponse=%zz"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	if _, err := s.ParseResponse(t.Context(), bad(), "id-1"); err == nil {
		t.Error("ParseResponse accepted a malformed form")
	}
	if _, err := s.ParseRequest(t.Context(), bad()); err == nil {
		t.Error("ParseRequest accepted a malformed form")
	}
}
