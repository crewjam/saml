package slo_test

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
)

func soapRequest(body []byte) *http.Request {
	env := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>` +
		string(body) + `</soapenv:Body></soapenv:Envelope>`
	r := httptest.NewRequest(http.MethodPost, spSLOURL, strings.NewReader(env))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	return r
}

func TestBackChannelReceive(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, []slo.EndpointOption{slo.BackChannel})

	req, buf := idpLogoutRequest(t, ti)
	r := soapRequest(buf)
	if !slo.IsRequest(r) || slo.IsResponse(r) {
		t.Fatal("a SOAP LogoutRequest is not recognized")
	}
	got, err := s.ParseRequest(t.Context(), r)
	if err != nil {
		t.Fatalf("ParseRequest: %v (%v)", err, errors.Unwrap(err))
	}
	if got.Binding != saml.SOAPBinding || got.ID != req.ID {
		t.Fatalf("request %+v", got)
	}

	msg, err := s.Response(t.Context(), got, samlsp.WithBinding(saml.HTTPRedirectBinding),
		slo.WithStatus(saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess,
			StatusCode: &saml.StatusCode{Value: saml.StatusPartialLogout}}}))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Binding != saml.SOAPBinding || msg.ID == "" {
		t.Fatalf("SOAP request not answered with SOAP: %+v", msg)
	}
	w := httptest.NewRecorder()
	msg.Write(w)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/xml") ||
		!strings.Contains(body, `InResponseTo="id-logout-1"`) || !strings.Contains(body, "SignatureValue") ||
		!strings.Contains(body, saml.StatusPartialLogout) || !strings.Contains(body, `ID="`+msg.ID+`"`) {
		t.Fatalf("SOAP response: %d %s", w.Code, body)
	}
}

func TestBackChannelRefused(t *testing.T) {
	ti := newTestIDP(t)

	// Not enabled.
	_, plain := newService(t, ti, nil)
	_, buf := idpLogoutRequest(t, ti)
	if _, err := plain.ParseRequest(t.Context(), soapRequest(buf)); err == nil {
		t.Error("a SOAP LogoutRequest was accepted without BackChannel")
	}
	if _, err := plain.SendRequest(t.Context(), saml.NameID{Value: "alice"}); err == nil {
		t.Error("SendRequest worked without BackChannel")
	}

	// Unsigned.
	_, s := newService(t, ti, []slo.EndpointOption{slo.BackChannel})
	req, _ := idpLogoutRequest(t, ti)
	unsigned, err := xml.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := soapRequest(unsigned)
	if _, err := s.ParseRequest(t.Context(), r); err == nil {
		t.Fatal("an unsigned SOAP LogoutRequest was accepted")
	}
	w := httptest.NewRecorder()
	slo.WriteRequestError(w, r)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Fault") {
		t.Errorf("SOAP error: %d %s", w.Code, w.Body.String())
	}
}

func TestBackChannelSend(t *testing.T) {
	ti := newTestIDP(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(ti.idp.ServeSLO))
	t.Cleanup(srv.Close)
	ti.idp.LogoutURL = mustURL(srv.URL + "/slo")
	ti.idp.LogoutBindings = append(ti.idp.LogoutBindings, saml.SOAPBinding)

	_, s := newService(t, ti, []slo.EndpointOption{slo.BackChannel}, samlsp.WithHTTPClient(srv.Client()))
	resp, err := s.SendRequest(t.Context(), saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"},
		slo.WithSessionIndex("index-1"), slo.WithReason(saml.LogoutReasonAdmin))
	if err != nil {
		t.Fatalf("SendRequest: %v (%v)", err, errors.Unwrap(err))
	}
	if resp.Status.StatusCode.Value != saml.StatusSuccess || !ti.loggedOut {
		t.Fatalf("status %s, logged out %v", resp.Status.StatusCode.Value, ti.loggedOut)
	}

	ti.idp.LogoutBindings = []string{saml.HTTPRedirectBinding}
	if _, err := s.SendRequest(t.Context(), saml.NameID{Value: "alice"}); !errors.Is(err, samlsp.ErrNoEndpoint) {
		t.Errorf("err = %v, want ErrNoEndpoint", err)
	}
}

// A multi-tenant SP finds the IdP of a back-channel LogoutRequest with
// samlsp.PeekIssuer, which leaves the body for ParseRequest to verify.
func TestBackChannelPeekIssuer(t *testing.T) {
	ti := newTestIDP(t)
	cfg, _ := newService(t, ti, []slo.EndpointOption{slo.BackChannel})
	s, err := slo.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req, buf := idpLogoutRequest(t, ti)
	r := soapRequest(buf)

	issuer, err := samlsp.PeekIssuer(r)
	if err != nil {
		t.Fatal(err)
	}
	if issuer != ti.idp.Metadata().EntityID {
		t.Fatalf("PeekIssuer = %q", issuer)
	}
	ctx := samlsp.IdentityProviderContext(t.Context(), func(context.Context) (*saml.EntityDescriptor, error) {
		return ti.idp.Metadata(), nil
	})
	got, err := s.ParseRequest(ctx, r)
	if err != nil {
		t.Fatalf("ParseRequest after PeekIssuer: %v (%v)", err, errors.Unwrap(err))
	}
	if got.ID != req.ID {
		t.Errorf("ID = %q", got.ID)
	}
}
