package samlsp_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
	"github.com/crewjam/saml/x/samlsp/replay"
)

// exampleIDP returns the metadata of an identity provider with
// HTTP-Redirect and HTTP-POST single sign-on and single logout endpoints.
// Real applications get it from RemoteMetadata or StaticMetadataBytes.
func exampleIDP() samlsp.MetadataFunc {
	endpoints := func(location string) []saml.Endpoint {
		return []saml.Endpoint{
			{Binding: saml.HTTPRedirectBinding, Location: location},
			{Binding: saml.HTTPPostBinding, Location: location},
		}
	}
	return samlsp.StaticMetadata(&saml.EntityDescriptor{
		EntityID: "https://idp.example.com/metadata",
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor:       saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol"},
				SingleLogoutServices: endpoints("https://idp.example.com/slo"),
			},
			SingleSignOnServices: endpoints("https://idp.example.com/sso"),
		}},
	})
}

// The entity ID is usually the URL of the SP metadata, and the other
// ACS is beside it unless WithACSURL says otherwise.
func ExampleNew() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(config.ACSURL())
	// Output:
	// https://sp.example.com/saml/acs
}

// Use WithACSURL when the ACS is elsewhere.
func ExampleNew_customURLs() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithACSURL("https://sp.example.com/auth/saml/callback"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(config.ACSURL())
	// Output:
	// https://sp.example.com/auth/saml/callback
}

// An entity ID that is not a URL, such as a URN, needs WithACSURL.
func ExampleNew_urnEntityID() {
	entityID := "urn:example:sp"
	_, err := samlsp.New(entityID, exampleIDP())
	fmt.Println(err)

	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithACSURL("https://sp.example.com/saml/acs"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(config.EntityID(), config.ACSURL())
	// Output:
	// samlsp: the entity ID "urn:example:sp" is not a URL to put the ACS beside; use WithACSURL
	// urn:example:sp https://sp.example.com/saml/acs
}

// ServeMetadata serves the SP metadata, which the IdP administrator needs
// to register the SP. Serve it at the entity ID.
func ExampleConfig_ServeMetadata() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP())
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)

	w := httptest.NewRecorder()
	config.ServeMetadata(w, httptest.NewRequest(http.MethodGet, "/saml/metadata", nil))
	fmt.Println(w.Header().Get("Content-Type"))
	fmt.Println(strings.Contains(w.Body.String(), `Location="https://sp.example.com/saml/acs"`))
	// Output:
	// application/samlmetadata+xml
	// true
}

// WithServiceProvider reaches settings of saml.ServiceProvider that have no
// Option of their own. Passed to New, it applies to every call.
func ExampleWithServiceProvider() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
			// This IdP signs only its assertions and encrypts them with
			// AES-CBC, which the default hardening refuses.
			sp.RequireSignedResponseForCBC = false
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = config
}

// A ServiceProviderOption passed to a single call applies to that call
// only, after the ones passed to New.
func ExampleServiceProviderOption_perCall() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP())
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc(config.ACSPath(), func(w http.ResponseWriter, r *http.Request) {
		requestID := takePendingRequest(r)
		assertion, err := config.ParseResponse(r.Context(), r,
			samlsp.WithRequestID(requestID),
			samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
				// This endpoint serves an IdP that rejects
				// AudienceRestrictions it does not recognize; accept any.
				sp.ValidateAudienceRestriction = func(*saml.Assertion) error { return nil }
			}))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
	})
}

// The application's own session and pending-request storage, which this
// package leaves to it. The examples use these stand-ins.

func takePendingRequest(_ *http.Request) string               { return "" }
func startSession(_ http.ResponseWriter, _ *samlsp.Assertion) {}

// sqlReplayState records accepted message IDs in a database table that
// every process shares:
//
//	CREATE TABLE saml_replay (key bytea PRIMARY KEY, expires_at timestamptz NOT NULL);
type sqlReplayState struct{ db *sql.DB }

func (s sqlReplayState) Consume(ctx context.Context, key []byte, expiresAt time.Time) error {
	// Insert the key, or take over an expired record of it. Nothing
	// changes if an unexpired record exists: that is a replay. ctx is that
	// of the request whose message is accepted.
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO saml_replay (key, expires_at) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE saml_replay.expires_at < now()`, key, expiresAt)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return saml.ErrAssertionReplayed
	}
	return nil
}

// By default a Config remembers accepted messages in memory, which protects
// one process. WithReplayState shares the record between processes.
func ExampleWithReplayState() {
	var db *sql.DB // opened by the application

	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithReplayState(sqlReplayState{db}))
	if err != nil {
		log.Fatal(err)
	}
	_ = config

	// Expired records can go at any time, for example from a periodic job:
	//	DELETE FROM saml_replay WHERE expires_at < now()
}

// tenant is an SP tenant, with its IdP's metadata as an administrator
// uploaded it (see ParseMetadata).
type tenant struct {
	name        string
	idpMetadata *saml.EntityDescriptor
}

// lookupTenant finds the tenant named in a request path.
func lookupTenant(string) (*tenant, bool) { return nil, false }

// When the SP itself differs per tenant, here by its entity ID and ACS
// URL, build a Config per request: New is cheap. The replay record and the
// pending-login cookies must outlive the request, so they are made once
// and shared by every Config.
func ExampleNew_perRequest() {
	accepted := replay.NewMemory() // or a table every process shares
	var cookieKey []byte           // 32 or more random bytes, from the application's secrets

	configFor := func(t *tenant) (*samlsp.Config, *pending.Tracker, error) {
		entityID := "https://sp.example.com/t/" + t.name + "/saml/metadata" // the ACS is .../saml/acs
		config, err := samlsp.New(entityID, samlsp.StaticMetadata(t.idpMetadata),
			samlsp.WithReplayState(accepted))
		if err != nil {
			return nil, nil, err
		}
		tracker, err := pending.New(config, cookieKey)
		return config, tracker, err
	}

	http.HandleFunc("/t/{tenant}/login", func(w http.ResponseWriter, r *http.Request) {
		t, ok := lookupTenant(r.PathValue("tenant"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		config, tracker, err := configFor(t)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		msg, err := config.AuthnRequest(r.Context(), rand.Text())
		if err == nil {
			err = tracker.Remember(w, msg, "")
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	})

	http.HandleFunc("/t/{tenant}/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		t, ok := lookupTenant(r.PathValue("tenant"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		config, tracker, err := configFor(t)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		login, err := tracker.Take(w, r)
		if err != nil {
			http.Error(w, "no login in progress", http.StatusBadRequest)
			return
		}
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
	})
}

// When only the IdP differs per tenant, one Config serves them all: each
// call names the tenant's IdP. The pending login remembers the tenant, so
// the ACS knows which IdP the Response must come from.
func ExampleWithIdentityProvider() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, nil)
	if err != nil {
		log.Fatal(err)
	}
	var cookieKey []byte // 32 or more random bytes, from the application's secrets
	tracker, err := pending.New(config, cookieKey)
	if err != nil {
		log.Fatal(err)
	}
	idpOf := func(t *tenant) samlsp.IdentityProviderOption {
		return samlsp.WithIdentityProvider(samlsp.StaticMetadata(t.idpMetadata))
	}

	http.HandleFunc("/t/{tenant}/login", func(w http.ResponseWriter, r *http.Request) {
		t, ok := lookupTenant(r.PathValue("tenant"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		msg, err := config.AuthnRequest(r.Context(), rand.Text(), idpOf(t))
		if err == nil {
			err = tracker.Remember(w, msg, t.name)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	})

	http.HandleFunc(config.ACSPath(), func(w http.ResponseWriter, r *http.Request) {
		login, err := tracker.Take(w, r)
		if err != nil {
			http.Error(w, "no login in progress", http.StatusBadRequest)
			return
		}
		t, ok := lookupTenant(login.Data)
		if !ok {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID), idpOf(t))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
	})
}
