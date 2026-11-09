package pending_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

// tenants is an SP that trusts two IdPs, a and b, as a multi-tenant
// application does: one Config, with the IdP named per call.
type tenants struct {
	cfg  *samlsp.Config
	a, b *testIDP
}

func newTenantIDP(t *testing.T, entityID string) *testIDP {
	t.Helper()
	key, cert := newKeyPair(t)
	ti := &testIDP{}
	ti.idp = &saml.IdentityProvider{
		Key: key, Certificate: cert,
		MetadataURL:             mustURL(entityID),
		SSOURL:                  mustURL("https://idp.example.net/sso"),
		ServiceProviderProvider: ti,
		SessionProvider:         ti,
	}
	return ti
}

func newTenants(t *testing.T) *tenants {
	t.Helper()
	key, cert := newKeyPair(t)
	cfg, err := samlsp.New(entityID, nil, samlsp.WithSigningKey(key, cert))
	if err != nil {
		t.Fatal(err)
	}
	ts := &tenants{
		cfg: cfg,
		a:   newTenantIDP(t, "https://idp-a.example.com/metadata"),
		b:   newTenantIDP(t, "https://idp-b.example.com/metadata"),
	}
	ts.a.spMeta = cfg.Metadata(t.Context())
	ts.b.spMeta = ts.a.spMeta
	return ts
}

func entityIDOf(ti *testIDP) string { return ti.idp.Metadata().EntityID }

func idpOption(ti *testIDP) samlsp.IdentityProviderOption {
	return samlsp.WithIdentityProvider(func(context.Context) (*saml.EntityDescriptor, error) { return ti.idp.Metadata(), nil })
}

// answer returns the form that ti posts to the ACS in answer to an
// AuthnRequest with the ID id and the RelayState relayState: an honest
// answer if the request was sent to ti, and otherwise one that ti, the IdP
// of another tenant, made for a login started with another IdP, whose ID
// and RelayState it learned.
func (ts *tenants) answer(t *testing.T, ti *testIDP, id, relayState string) url.Values {
	t.Helper()
	msg, err := ts.cfg.AuthnRequest(t.Context(), relayState, idpOption(ti),
		samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error { req.ID = id; return nil }))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ti.idp.ServeSSO(w, httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), nil))
	form := formValues(w.Body.String())
	if form.Get("SAMLResponse") == "" {
		t.Fatalf("the IdP did not answer: %s", w.Body.String())
	}
	return form
}

// acs is an ACS that chooses the IdP to verify the Response with by its
// unverified Issuer, as an SP that trusts several IdPs may, and relies on
// Login.ResponseOption to refuse an IdP other than the login's.
func (ts *tenants) acs(t *testing.T, tr *pending.Tracker, r *http.Request) (*pending.Login, *samlsp.Assertion, error) {
	t.Helper()
	login, err := tr.Find(httptest.NewRecorder(), r)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	issuer, err := samlsp.PeekUnverifiedIssuer(r)
	if err != nil {
		t.Fatal(err)
	}
	var ti *testIDP
	switch issuer {
	case entityIDOf(ts.a):
		ti = ts.a
	case entityIDOf(ts.b):
		ti = ts.b
	default:
		t.Fatalf("unknown issuer %q", issuer)
	}
	a, err := ts.cfg.ParseResponse(t.Context(), r, login.ResponseOption(), idpOption(ti))
	return login, a, err
}

// A login sent to IdP A is accepted from A only: a Response from B, another
// IdP the SP trusts, to the same request is refused, even when the ACS
// chooses B's metadata to verify it with.
func TestIssuerOfLogin(t *testing.T) {
	ts := newTenants(t)
	tr := newTracker(t, ts.cfg)
	msg, err := ts.cfg.AuthnRequest(t.Context(), "state-a", idpOption(ts.a))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := msg.IdentityProvider(), entityIDOf(ts.a); got != want {
		t.Fatalf("Message.IdentityProvider = %q, want %q", got, want)
	}
	w := httptest.NewRecorder()
	if err := tr.Remember(w, msg, "/next"); err != nil {
		t.Fatal(err)
	}

	t.Run("from the IdP asked", func(t *testing.T) {
		r := acsRequest(ts.answer(t, ts.a, msg.ID, "state-a"), w)
		login, a, err := ts.acs(t, tr, r)
		if err != nil {
			t.Fatal(err)
		}
		if login.IdentityProvider != entityIDOf(ts.a) || a.Issuer != entityIDOf(ts.a) {
			t.Errorf("Login.IdentityProvider = %q, Issuer = %q, want %q", login.IdentityProvider, a.Issuer, entityIDOf(ts.a))
		}
	})

	t.Run("from another IdP", func(t *testing.T) {
		form := ts.answer(t, ts.b, msg.ID, "state-a")
		// The request ID alone does not tell B's Response from A's.
		if _, err := ts.cfg.ParseResponse(t.Context(), acsRequest(form, w), samlsp.WithRequestID(msg.ID), idpOption(ts.b)); err != nil {
			t.Fatalf("WithRequestID: %v", err)
		}
		_, a, err := ts.acs(t, tr, acsRequest(form, w))
		if a != nil || !errors.Is(err, samlsp.ErrUnexpectedIssuer) || !errors.Is(err, saml.ErrIssuerMismatch) {
			t.Fatalf("ParseResponse = %v, %v; want ErrUnexpectedIssuer and saml.ErrIssuerMismatch", a, err)
		}
		var ire *saml.InvalidResponseError
		if !errors.As(err, &ire) {
			t.Errorf("err = %T, want *saml.InvalidResponseError", err)
		}
	})
}

// A cookie set before Remember kept the IdP is still found, with no
// IdentityProvider, and its Response is accepted without the check, as the
// package documentation says.
func TestIssuerOldCookie(t *testing.T) {
	ts := newTenants(t)
	tr := newTracker(t, ts.cfg)
	msg, err := ts.cfg.AuthnRequest(t.Context(), "state-a", idpOption(ts.a))
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Minute).Unix()
	name, value := tr.Seal("state-a", fmt.Appendf(nil, `{"i":%q,"r":"state-a","e":%d,"d":"/next"}`, msg.ID, expires))

	for _, ti := range []*testIDP{ts.a, ts.b} {
		r := acsRequest(ts.answer(t, ti, msg.ID, "state-a"), httptest.NewRecorder())
		r.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // G124: a request cookie carries no attributes
		login, _, err := ts.acs(t, tr, r)
		if err != nil {
			t.Errorf("Response from %s: %v", entityIDOf(ti), err)
		}
		if login.IdentityProvider != "" || login.Data != "/next" {
			t.Errorf("Login = %+v, want no IdentityProvider", login)
		}
	}
}

// The IdP is kept compactly, and the cookie of a malformed one is refused.
func TestIssuerCookie(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	expires := time.Now().Add(time.Minute).Unix()
	for _, tc := range []struct {
		idp, want string
		err       error
	}{
		{`"~idp.example.com/metadata"`, "https://idp.example.com/metadata", nil},
		{`"=urn:example:idp"`, "urn:example:idp", nil},
		{`""`, "", nil},
		{`"idp.example.com"`, "", pending.ErrInvalid},
		{`"="`, "", pending.ErrInvalid},
	} {
		name, value := tr.Seal("s", fmt.Appendf(nil, `{"i":"id-1","r":"s","e":%d,"p":%s}`, expires, tc.idp))
		r := acsRequest(url.Values{"RelayState": {"s"}}, httptest.NewRecorder())
		r.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // G124: a request cookie carries no attributes
		login, err := tr.Find(httptest.NewRecorder(), r)
		if !errors.Is(err, tc.err) || err == nil && login.IdentityProvider != tc.want {
			t.Errorf("p %s: Find = %+v, %v; want IdentityProvider %q, err %v", tc.idp, login, err, tc.want, tc.err)
		}
	}
}

// The entity ID takes the room in the cookie that Remember's doc says.
func TestIssuerCookieSize(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	const id = "id-fixed-length-0123456789" // IDs are random but of one length
	size := func(msg *samlsp.Message) int {
		t.Helper()
		msg.ID = id
		w := httptest.NewRecorder()
		if err := tr.Remember(w, msg, "/next"); err != nil {
			t.Fatal(err)
		}
		return len(onlyCookie(t, w).Value)
	}
	without := size(&samlsp.Message{RelayState: "state-1"})
	for _, tc := range []struct {
		entityID string
		want     int
	}{
		{"https://idp.example.com/metadata", 32 * 4 / 3},
		{"https://sts.windows.net/00000000-0000-0000-0000-000000000000/", 61 * 4 / 3},
		{"urn:example:idp", (15 + 8) * 4 / 3},
	} {
		msg, err := cfg.AuthnRequest(t.Context(), "state-1", idpOption(newTenantIDP(t, tc.entityID)))
		if err != nil {
			t.Fatal(err)
		}
		if msg.IdentityProvider() != tc.entityID {
			t.Fatalf("IdentityProvider = %q, want %q", msg.IdentityProvider(), tc.entityID)
		}
		if d := size(msg) - without; d < tc.want-2 || d > tc.want+2 {
			t.Errorf("%s takes %d bytes of the cookie, not about %d", tc.entityID, d, tc.want)
		}
	}
}
