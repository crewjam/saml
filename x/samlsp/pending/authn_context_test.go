package pending_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

// The cookie keeps the authentication context the AuthnRequest asked
// for, and Login.ResponseOption makes ParseResponse enforce it.
func TestAuthnContextRemembered(t *testing.T) {
	cfg, ti := newConfig(t) // the IdP authenticates with PasswordProtectedTransport
	tr := newTracker(t, cfg)

	for _, tt := range []struct {
		name    string
		opt     samlsp.AuthnOption
		want    *saml.RequestedAuthnContext
		wantErr error
	}{
		{"none", nil, nil, nil},
		{
			"satisfied",
			samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextPasswordProtectedTransport),
			&saml.RequestedAuthnContext{Comparison: "exact", AuthnContextClassRefs: []string{string(saml.AuthnContextPasswordProtectedTransport)}},
			nil,
		},
		{
			"not satisfied",
			samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509, "https://example.com/ac/mfa"),
			&saml.RequestedAuthnContext{Comparison: "exact", AuthnContextClassRefs: []string{string(saml.AuthnContextX509), "https://example.com/ac/mfa"}},
			saml.ErrAuthnContextMismatch,
		},
	} {
		msg, err := cfg.AuthnRequest(t.Context(), "state-"+tt.name, tt.opt)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		if err := tr.Remember(w, msg, "/next"); err != nil {
			t.Fatal(err)
		}
		idpW := httptest.NewRecorder()
		ti.idp.ServeSSO(idpW, httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), nil))
		r := acsRequest(formValues(idpW.Body.String()), w)

		login, err := tr.Find(httptest.NewRecorder(), r)
		if err != nil {
			t.Fatalf("%s: Find: %v", tt.name, err)
		}
		if !reflect.DeepEqual(login.AuthnContext, tt.want) {
			t.Errorf("%s: AuthnContext = %+v, want %+v", tt.name, login.AuthnContext, tt.want)
		}
		_, err = cfg.ParseResponse(t.Context(), r, login.ResponseOption())
		if tt.wantErr == nil && err != nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: ParseResponse: %v, want %v", tt.name, err, tt.wantErr)
		}
	}

	var none *pending.Login
	if none.ResponseOption() != nil {
		t.Error("a nil Login has a ResponseOption")
	}
}

// The authentication context takes little room in the cookie: 56 bytes
// for PasswordProtectedTransport alone, as the doc of Remember says.
func TestAuthnContextCookieSize(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	size := func(opts ...samlsp.AuthnOption) int {
		t.Helper()
		msg, err := cfg.AuthnRequest(t.Context(), "state-1", opts...)
		if err != nil {
			t.Fatal(err)
		}
		msg.ID = "id-fixed-length-0123456789" // IDs are random but of one length
		w := httptest.NewRecorder()
		if err := tr.Remember(w, msg, "/next"); err != nil {
			t.Fatal(err)
		}
		return len(onlyCookie(t, w).Value)
	}
	without := size()
	with := size(samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextPasswordProtectedTransport))
	if d := with - without; d < 50 || d > 60 {
		t.Errorf("PasswordProtectedTransport takes %d bytes of the cookie, not about 56", d)
	}
}
