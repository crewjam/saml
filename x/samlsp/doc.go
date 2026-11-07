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
// github.com/coreos/go-oidc: a plain Config struct, a function that
// supplies the identity provider's metadata, functional options per
// message, and verified results as plain structs.
//
// # Setup
//
//	config, err := samlsp.New(
//		samlsp.RemoteMetadata("https://idp.example.com/metadata"),
//		"https://sp.example.com/saml/metadata", // the SP's entity ID
//		samlsp.WithKey(key, cert),
//		samlsp.WithSLOURL("slo"),
//	)
//	http.HandleFunc("/saml/metadata", config.ServeMetadata)
//	http.HandleFunc("/saml/acs", acs)       // config.ACSURL()
//	http.HandleFunc("/saml/slo", slo)       // config.SLOURL()
//
// The entity ID is conventionally the URL of the SP metadata. The SP's
// other URLs are resolved against it: the ACS is at "acs" unless
// WithACSURL says otherwise, so here it is https://sp.example.com/saml/acs,
// and WithSLOURL("slo") puts single logout at
// https://sp.example.com/saml/slo.
//
// The first argument is a MetadataFunc that supplies the identity
// provider's metadata. Every method calls it with its context.
// RemoteMetadata fetches and caches metadata from a URL, ParseMetadata and
// StaticMetadata use metadata the application already has, and an
// application can supply its own function: for example, one that reads
// metadata from a database, or picks the IdP for the tenant named in the
// context.
//
// Settings that have no Option of their own are reached with a
// ServiceProviderOption, which adjusts the saml.ServiceProvider that each
// method builds. Pass it to New for every call, or to a single call
// alongside its other options:
//
//	config, err := samlsp.New(idp, entityID, samlsp.SignMetadata)
//	config.ParseResponse(ctx, r, samlsp.WithRequestID(id), samlsp.RejectUnknownConditions)
//
// # Web Browser SSO
//
// Login has two steps. First, send the browser to the IdP with an
// AuthnRequest. The application must remember the request's ID, keyed by
// the RelayState, until the Response arrives:
//
//	func login(w http.ResponseWriter, r *http.Request) {
//		relayState := rand.Text()
//		req, err := config.AuthnRequest(r.Context(), relayState)
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
