package samlsp_test

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

const soapEnvelopeStart = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>`
const soapEnvelopeEnd = `</soapenv:Body></soapenv:Envelope>`

func soapRequest(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, spSLOURL, strings.NewReader(soapEnvelopeStart+string(body)+soapEnvelopeEnd))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	return r
}

func TestBackChannelLogoutReceive(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti, samlsp.BackChannelLogout)

	md := cfg.Metadata(t.Context())
	found := false
	for _, slo := range md.SPSSODescriptors[0].SingleLogoutServices {
		found = found || slo.Binding == saml.SOAPBinding && slo.Location == spSLOURL
	}
	if !found {
		t.Fatal("the SOAP SingleLogoutService is not advertised")
	}

	req, buf := idpLogoutRequest(t, ti)
	r := soapRequest(buf)
	if !samlsp.IsLogoutRequest(r) || samlsp.IsLogoutResponse(r) {
		t.Fatal("a SOAP LogoutRequest is not recognized")
	}
	got, err := cfg.ParseLogoutRequest(t.Context(), r)
	if err != nil {
		t.Fatalf("ParseLogoutRequest: %v (%v)", err, errors.Unwrap(err))
	}
	if got.Binding != saml.SOAPBinding || got.ID != req.ID || got.NameID.Value != "alice@example.com" ||
		len(got.SessionIndexes) != 1 {
		t.Fatalf("unexpected request %+v", got)
	}

	msg, err := cfg.LogoutResponse(t.Context(), got, samlsp.WithBinding(saml.HTTPRedirectBinding))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Binding != saml.SOAPBinding || msg.RedirectURL() != nil {
		t.Fatalf("SOAP request not answered with SOAP: %+v", msg)
	}
	w := httptest.NewRecorder()
	msg.Write(w)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/xml") ||
		!strings.Contains(body, "LogoutResponse") || !strings.Contains(body, `InResponseTo="id-logout-1"`) ||
		!strings.Contains(body, "SignatureValue") || !strings.Contains(body, saml.StatusSuccess) {
		t.Fatalf("SOAP response: %d %s", w.Code, body)
	}
}

func TestBackChannelLogoutRefused(t *testing.T) {
	ti := newTestIDP(t)

	// Not enabled.
	cfg := newTestConfig(t, ti)
	_, buf := idpLogoutRequest(t, ti)
	if _, err := cfg.ParseLogoutRequest(t.Context(), soapRequest(buf)); err == nil {
		t.Error("a SOAP LogoutRequest was accepted without BackChannelLogout")
	}
	if md := cfg.Metadata(t.Context()); len(md.SPSSODescriptors[0].SingleLogoutServices) != 2 {
		t.Errorf("SOAP advertised without BackChannelLogout: %+v", md.SPSSODescriptors[0].SingleLogoutServices)
	}

	// Unsigned.
	cfg = newTestConfig(t, ti, samlsp.BackChannelLogout)
	req, _ := idpLogoutRequest(t, ti)
	unsigned, err := xml.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := soapRequest(unsigned)
	if _, err := cfg.ParseLogoutRequest(t.Context(), r); err == nil {
		t.Fatal("an unsigned SOAP LogoutRequest was accepted")
	}
	w := httptest.NewRecorder()
	samlsp.WriteLogoutRequestError(w, r)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Fault") {
		t.Errorf("SOAP error: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	samlsp.WriteLogoutRequestError(w, postForm(spSLOURL, url.Values{"SAMLRequest": {"x"}}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("browser error: %d", w.Code)
	}

	// Configuration.
	idp := staticIDP(ti)
	if _, err := samlsp.New(idp, spEntityID, samlsp.BackChannelLogout); err == nil {
		t.Error("BackChannelLogout accepted without an SLO URL")
	}
	if _, err := samlsp.New(idp, spEntityID, samlsp.BackChannelLogout, samlsp.WithSLOURL(spSLOURL)); err == nil {
		t.Error("BackChannelLogout accepted without a key")
	}
}

func TestBackChannelLogoutSend(t *testing.T) {
	ti := newTestIDP(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(ti.idp.ServeSLO))
	t.Cleanup(srv.Close)
	ti.idp.LogoutURL = mustURL(srv.URL + "/slo")
	ti.idp.LogoutBindings = append(ti.idp.LogoutBindings, saml.SOAPBinding)

	cfg := newTestConfig(t, ti, samlsp.BackChannelLogout, samlsp.WithHTTPClient(srv.Client()))
	ctx := t.Context()
	resp, err := cfg.SendLogoutRequest(ctx, saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"},
		samlsp.WithSessionIndex("index-1"))
	if err != nil {
		t.Fatalf("SendLogoutRequest: %v (%v)", err, errors.Unwrap(err))
	}
	if resp.Status.StatusCode.Value != saml.StatusSuccess || !ti.loggedOut {
		t.Fatalf("status %s, IdP logged out: %v", resp.Status.StatusCode.Value, ti.loggedOut)
	}

	// An IdP without a SOAP endpoint.
	ti.idp.LogoutBindings = []string{saml.HTTPRedirectBinding}
	if _, err := cfg.SendLogoutRequest(ctx, saml.NameID{Value: "alice"}); !errors.Is(err, samlsp.ErrNoEndpoint) {
		t.Errorf("err = %v, want ErrNoEndpoint", err)
	}

	// Not enabled.
	plain := newTestConfig(t, ti)
	if _, err := plain.SendLogoutRequest(ctx, saml.NameID{Value: "alice"}); err == nil {
		t.Error("SendLogoutRequest worked without BackChannelLogout")
	}
}
