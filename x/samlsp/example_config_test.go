package samlsp_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/crewjam/saml"
	oldsamlsp "github.com/crewjam/saml/samlsp"
	"github.com/crewjam/saml/x/samlsp"
)

// exampleIDP returns the metadata of an identity provider with
// HTTP-Redirect and HTTP-POST single sign-on and single logout endpoints.
// Real applications get it from RemoteMetadata or ParseMetadata.
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
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithSLOURL("https://sp.example.com/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(config.ACSURL())
	fmt.Println(config.SLOURL())
	// Output:
	// https://sp.example.com/saml/acs
	// https://sp.example.com/saml/slo
}

// Use WithACSURL when the ACS is elsewhere.
func ExampleNew_customURLs() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithACSURL("https://sp.example.com/auth/saml/callback"),
		samlsp.WithSLOURL("https://sp.example.com/auth/saml/logout"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(config.ACSURL())
	fmt.Println(config.SLOURL())
	// Output:
	// https://sp.example.com/auth/saml/callback
	// https://sp.example.com/auth/saml/logout
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
	http.HandleFunc("/saml/metadata", config.ServeMetadata)

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
	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
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

func takePendingRequest(_ *http.Request) string                  { return "" }
func startSession(_ http.ResponseWriter, _ *samlsp.Assertion)    {}
func endSession(_ http.ResponseWriter, _ *http.Request)          {}
func endSessionsOf(_ context.Context, _ saml.NameID, _ []string) {}

// currentSession returns what the application kept from the user's login.
func currentSession(_ *http.Request) (nameID saml.NameID, sessionIndexes []string, ok bool) {
	return saml.NameID{}, nil, false
}

// WithReplayState makes ParseResponse accept each assertion only once, so
// that a Response copied from a browser's history cannot be used again.
// The state must be shared by every process that serves the ACS.
func ExampleWithReplayState() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithReplayState(oldsamlsp.NewMemoryReplayCache(10000))) // one process only
	if err != nil {
		log.Fatal(err)
	}
	_ = config
}
