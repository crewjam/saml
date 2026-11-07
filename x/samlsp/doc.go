// Package samlsp is an experimental, minimal API for implementing a SAML 2.0
// service provider (SP) with the Web Browser SSO and Single Logout profiles.
//
// It is a thin layer over saml.ServiceProvider. It deals with the SAML
// protocol only: building AuthnRequests, verifying Responses, single logout,
// and SP metadata. It does not manage sessions, cookies, JWTs or pending
// requests. Those belong to the application. For a ready-made middleware
// that does all of that, see github.com/crewjam/saml/samlsp.
//
// The shape of the API follows golang.org/x/oauth2 and
// github.com/coreos/go-oidc: a plain Config struct, an IdentityProvider
// built from metadata, functional options per message, and verified
// results as plain structs.
//
// # Setup
//
//	idp, err := samlsp.NewIdentityProvider(ctx, "https://idp.example.com/metadata")
//	config := &samlsp.Config{
//		IdentityProvider: idp,
//		EntityID:         "https://sp.example.com/saml/metadata",
//		MetadataURL:      "https://sp.example.com/saml/metadata",
//		ACSURL:           "https://sp.example.com/saml/acs",
//		SLOURL:           "https://sp.example.com/saml/slo",
//		Key:              key,
//		Certificate:      cert,
//	}
//	http.HandleFunc("/saml/metadata", config.ServeMetadata)
//
// # Web Browser SSO
//
// Login has two steps. First, send the browser to the IdP with an
// AuthnRequest. The application must remember the request's ID, keyed by
// the RelayState, until the Response arrives:
//
//	func login(w http.ResponseWriter, r *http.Request) {
//		relayState := rand.Text()
//		req, err := config.AuthnRequest(relayState)
//		if err != nil { ... }
//		rememberPendingRequest(w, relayState, req.ID) // e.g. in a signed cookie
//		req.Write(w)
//	}
//
// Second, at the assertion consumer service (ACS), verify the Response and
// check that its InResponseTo is the remembered ID:
//
//	func acs(w http.ResponseWriter, r *http.Request) {
//		requestID := takePendingRequest(w, r, r.FormValue("RelayState"))
//		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(requestID))
//		if err != nil { ... }
//		startSession(w, assertion.NameID, assertion.SessionIndexes, assertion.Attributes)
//	}
//
// ParseResponse returns a verified Assertion. It accepts the HTTP-POST,
// HTTP-POST-SimpleSign and HTTP-Artifact bindings. For HTTP-Artifact it
// resolves the artifact with the IdP, using the HTTP client from
// ClientContext. It accepts an unsolicited (IdP-initiated) Response only
// when AllowUnsolicited is passed.
//
// # Single Logout
//
// LogoutRequest starts single logout at the IdP, and ParseLogoutResponse
// verifies the IdP's LogoutResponse. When the IdP starts logout instead,
// ParseLogoutRequest verifies its LogoutRequest and LogoutResponse builds
// the reply. All of these are sent through the browser. The SOAP binding
// (back-channel logout) is not supported yet.
//
// # Errors
//
// Errors from verifying a message come from package saml unchanged. Match
// them with errors.Is against the saml.Err* values, such as
// saml.ErrUntrustedCertificate and saml.ErrExpired. When the IdP answered
// with a status other than Success, such as NoPassive for an IsPassive
// request, use errors.As with saml.ErrBadStatus.
//
// # Stability
//
// This package is under x/ and its API may change.
package samlsp
