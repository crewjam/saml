package samlsp_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// WithExpectedIssuer accepts a Response from the IdP the request was sent
// to (Message.IdentityProvider), and refuses one verified against another
// IdP's metadata.
func TestWithExpectedIssuer(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	const idpEntityID = "https://idp.example.com/metadata"

	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if msg.IdentityProvider() != idpEntityID {
		t.Fatalf("IdentityProvider = %q, want %q", msg.IdentityProvider(), idpEntityID)
	}

	t.Run("expected", func(t *testing.T) {
		msg, err := cfg.AuthnRequest(t.Context(), "s")
		if err != nil {
			t.Fatal(err)
		}
		a, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID),
			samlsp.WithExpectedIssuer(msg.IdentityProvider()), samlsp.WithExpectedIssuer(idpEntityID))
		if err != nil {
			t.Fatal(err)
		}
		if a.Issuer != idpEntityID {
			t.Errorf("Issuer = %q", a.Issuer)
		}
	})

	for _, tc := range []struct {
		name string
		opts []samlsp.ResponseOption
		err  []error
	}{
		{"other IdP", []samlsp.ResponseOption{samlsp.WithExpectedIssuer("https://idp-b.example.com/metadata")},
			[]error{samlsp.ErrUnexpectedIssuer, saml.ErrIssuerMismatch}},
		{"conflicting", []samlsp.ResponseOption{samlsp.WithExpectedIssuer(idpEntityID), samlsp.WithExpectedIssuer("https://idp-b.example.com/metadata")},
			[]error{samlsp.ErrConflictingIssuers}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := cfg.AuthnRequest(t.Context(), "s")
			if err != nil {
				t.Fatal(err)
			}
			a, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), append(tc.opts, samlsp.WithRequestID(msg.ID))...)
			if a != nil {
				t.Fatal("accepted")
			}
			for _, want := range tc.err {
				if !errors.Is(err, want) {
					t.Errorf("err = %v, want %v", err, want)
				}
			}
		})
	}

	t.Run("empty", func(t *testing.T) {
		msg, err := cfg.AuthnRequest(t.Context(), "s")
		if err != nil {
			t.Fatal(err)
		}
		if a, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID), samlsp.WithExpectedIssuer("")); a != nil || err == nil {
			t.Errorf("WithExpectedIssuer(\"\") = %v, %v; want an error", a, err)
		}
	})

	if m := samlsp.NewMessage("id", saml.SOAPBinding, func(http.ResponseWriter) {}); m.IdentityProvider() != "" {
		t.Errorf("NewMessage: IdentityProvider = %q", m.IdentityProvider())
	}
}

// Message.IdentityProvider is the IdP that the call used, however it was
// named.
func TestMessageIdentityProvider(t *testing.T) {
	a, b := newTestIDP(t), newTestIDP(t)
	b.idp.MetadataURL = mustURL("https://idp-b.example.com/metadata")
	cfg := newTestConfig(t, a)
	b.spMeta = a.spMeta
	ctx := t.Context()

	for _, tc := range []struct {
		name string
		ctx  context.Context
		opts []samlsp.AuthnOption
		want string
	}{
		{"New", ctx, nil, "https://idp.example.com/metadata"},
		{"WithIdentityProvider", ctx, []samlsp.AuthnOption{samlsp.WithIdentityProvider(staticIDP(b))}, "https://idp-b.example.com/metadata"},
		{"IdentityProviderContext", samlsp.IdentityProviderContext(ctx, staticIDP(b)), nil, "https://idp-b.example.com/metadata"},
	} {
		msg, err := cfg.AuthnRequest(tc.ctx, "s", tc.opts...)
		if err != nil {
			t.Fatal(err)
		}
		if msg.IdentityProvider() != tc.want {
			t.Errorf("%s: IdentityProvider = %q, want %q", tc.name, msg.IdentityProvider(), tc.want)
		}
	}
}

// ResponseOptions applies each of its options, and ignores nil ones.
func TestResponseOptions(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	opt := samlsp.ResponseOptions(nil, samlsp.WithRequestID(msg.ID), samlsp.WithExpectedIssuer(msg.IdentityProvider()))
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), opt); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.ResponseOptions()); !errors.Is(err, samlsp.ErrNoRequestID) {
		t.Errorf("no options: err = %v, want ErrNoRequestID", err)
	}
}

// An application that keeps its logins in progress in a server-side
// session records the IdP each AuthnRequest is sent to, and accepts a
// Response from that IdP only. (x/samlsp/pending does this for an
// application that keeps them in a cookie.)
func ExampleWithExpectedIssuer() {
	config, err := samlsp.New("https://sp.example.com/saml/metadata", nil)
	if err != nil {
		log.Fatal(err)
	}
	type loginInProgress struct{ requestID, idpEntityID string }
	// The application's session store, keyed by RelayState and tied to
	// the browser.
	var (
		save func(r *http.Request, relayState string, l loginInProgress)
		load func(r *http.Request) (loginInProgress, bool)
	)
	// tenantIDP returns the metadata of the IdP with this entity ID.
	tenantIDP := func(string) samlsp.MetadataFunc { return nil }
	tenantOf := func(*http.Request) samlsp.MetadataFunc { return nil }

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		relayState := rand.Text()
		msg, err := config.AuthnRequest(r.Context(), relayState, samlsp.WithIdentityProvider(tenantOf(r)))
		if err != nil {
			http.Error(w, "cannot start login", http.StatusInternalServerError)
			return
		}
		save(r, relayState, loginInProgress{msg.ID, msg.IdentityProvider()})
		msg.Write(w)
	})

	http.HandleFunc(config.ACSPath(), func(w http.ResponseWriter, r *http.Request) {
		l, ok := load(r)
		if !ok {
			http.Error(w, "no login in progress", http.StatusBadRequest)
			return
		}
		assertion, err := config.ParseResponse(r.Context(), r,
			samlsp.WithRequestID(l.requestID),
			samlsp.WithIdentityProvider(tenantIDP(l.idpEntityID)),
			samlsp.WithExpectedIssuer(l.idpEntityID))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
	})
}
