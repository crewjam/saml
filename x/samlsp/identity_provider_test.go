package samlsp_test

import (
	"context"
	"errors"
	"log"
	"net/http"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// failingIDP is a MetadataFunc that must not be called.
func failingIDP(t *testing.T) samlsp.MetadataFunc {
	return func(context.Context) (*saml.EntityDescriptor, error) {
		t.Error("the Config's MetadataFunc was called")
		return nil, errors.New("not this IdP")
	}
}

// TestWithIdentityProvider logs in with the IdP named per call, which takes
// the place of the Config's MetadataFunc.
func TestWithIdentityProvider(t *testing.T) {
	for name, configIDP := range map[string]func(t *testing.T) samlsp.MetadataFunc{
		"no MetadataFunc":    func(*testing.T) samlsp.MetadataFunc { return nil },
		"other MetadataFunc": failingIDP,
	} {
		t.Run(name, func(t *testing.T) {
			ti := newTestIDP(t)
			cfg := newTestConfigWithIDP(t, ti, configIDP(t))
			idp := samlsp.WithIdentityProvider(staticIDP(ti))

			msg, err := cfg.AuthnRequest(t.Context(), "s", idp)
			if err != nil {
				t.Fatal(err)
			}
			a, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID), idp)
			if err != nil {
				t.Fatal(err)
			}
			if a.Issuer != ti.idp.Metadata().EntityID {
				t.Errorf("Issuer = %q", a.Issuer)
			}

			sp, _, err := cfg.Prepare(t.Context(), idp)
			if err != nil {
				t.Fatal(err)
			}
			if sp.IDPMetadata.EntityID != ti.idp.Metadata().EntityID {
				t.Errorf("Prepare used IdP %q", sp.IDPMetadata.EntityID)
			}
		})
	}
}

// TestIdentityProviderContext names the IdP in the context, for calls that
// take no option for it.
func TestIdentityProviderContext(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfigWithIDP(t, ti, failingIDP(t))
	ctx := samlsp.IdentityProviderContext(t.Context(), staticIDP(ti))

	sp, err := cfg.ServiceProvider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sp.IDPMetadata.EntityID != ti.idp.Metadata().EntityID {
		t.Errorf("ServiceProvider used IdP %q", sp.IDPMetadata.EntityID)
	}

	// The context also serves a whole login.
	msg, err := cfg.AuthnRequest(ctx, "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(ctx, login(t, ti, msg), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
}

// TestNoIdentityProvider checks that a Config made without a MetadataFunc
// fails every call that names no IdP, and still serves its metadata.
func TestNoIdentityProvider(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfigWithIDP(t, ti, nil)
	ctx := t.Context()

	for name, call := range map[string]func() error{
		"AuthnRequest": func() error { _, err := cfg.AuthnRequest(ctx, "s"); return err },
		"ParseResponse": func() error {
			_, err := cfg.ParseResponse(ctx, postForm(spACSURL, nil), samlsp.AllowUnsolicited)
			return err
		},
		"QueryAttributes": func() error {
			_, err := cfg.QueryAttributes(ctx, saml.NameID{Value: "alice"})
			return err
		},
		"Prepare":         func() error { _, _, err := cfg.Prepare(ctx); return err },
		"ServiceProvider": func() error { _, err := cfg.ServiceProvider(ctx); return err },
	} {
		if err := call(); !errors.Is(err, samlsp.ErrNoIdentityProvider) {
			t.Errorf("%s: err = %v, want ErrNoIdentityProvider", name, err)
		}
	}

	if md := cfg.Metadata(ctx); md.EntityID != spEntityID {
		t.Errorf("Metadata().EntityID = %q", md.EntityID)
	}
}

// An ACS that accepts IdP-initiated logins for many tenants finds the
// tenant of an unsolicited Response by its Issuer, then verifies the
// Response against that tenant's IdP.
func ExamplePeekIssuer() {
	config, err := samlsp.New(nil, "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}
	// tenantIDP returns the metadata of the tenant whose IdP has this
	// entity ID, from the application's database.
	tenantIDP := func(string) (samlsp.MetadataFunc, bool) { return nil, false }

	http.HandleFunc(config.ACSPath(), func(w http.ResponseWriter, r *http.Request) {
		issuer, err := samlsp.PeekIssuer(r) // unverified: only chooses the IdP
		if err != nil {
			http.Error(w, "login failed", http.StatusBadRequest)
			return
		}
		idp, ok := tenantIDP(issuer)
		if !ok {
			http.Error(w, "unknown IdP", http.StatusForbidden)
			return
		}
		assertion, err := config.ParseResponse(r.Context(), r,
			samlsp.AllowUnsolicited, samlsp.WithIdentityProvider(idp))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}
