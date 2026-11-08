package samlsp_test

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
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
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(config.ACSURL())
	// Output:
	// https://sp.example.com/saml/acs
}

// Use WithACSURL when the ACS is elsewhere.
func ExampleNew_customURLs() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
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
	_, err := samlsp.New(exampleIDP(), "urn:example:sp")
	fmt.Println(err)

	config, err := samlsp.New(exampleIDP(), "urn:example:sp",
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
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
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
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
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
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
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
//	CREATE TABLE saml_replay (id text PRIMARY KEY, expires_at timestamptz NOT NULL);
type sqlReplayState struct{ db *sql.DB }

func (s sqlReplayState) Consume(id string, expiresAt time.Time) error {
	// Insert the ID, or take over an expired record of it. Nothing changes
	// if an unexpired record exists: that is a replay.
	res, err := s.db.Exec(`
		INSERT INTO saml_replay (id, expires_at) VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE saml_replay.expires_at < now()`, id, expiresAt)
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

	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithReplayState(sqlReplayState{db}))
	if err != nil {
		log.Fatal(err)
	}
	_ = config

	// Expired records can go at any time, for example from a periodic job:
	//	DELETE FROM saml_replay WHERE expires_at < now()
}
