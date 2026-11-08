// Package samlsp is an experimental, minimal API for implementing a SAML 2.0
// service provider (SP) with the Web Browser SSO profile.
//
// It is a thin layer over saml.ServiceProvider that builds AuthnRequests,
// verifies Responses, and serves the SP metadata. Single logout is in
// github.com/crewjam/saml/x/samlsp/slo. For a ready-made middleware with
// sessions, see github.com/crewjam/saml/samlsp.
//
// The shape of the API follows golang.org/x/oauth2 and
// github.com/coreos/go-oidc: a Config made once with New, a function that
// supplies the identity provider's metadata, functional options per call,
// and verified results as plain structs.
//
// # Setup
//
//	config, err := samlsp.New(
//		samlsp.RemoteMetadata("https://idp.example.com/metadata"),
//		"https://sp.example.com/saml/metadata", // the SP's entity ID
//		samlsp.WithKey(key, cert),
//	)
//	http.HandleFunc("/saml/metadata", config.ServeMetadata)
//	http.HandleFunc("/saml/acs", acs) // config.ACSURL()
//
// The entity ID is conventionally the URL of the SP metadata. Unless
// WithACSURL says otherwise, the ACS is beside it, at "acs": here,
// https://sp.example.com/saml/acs.
//
// The first argument is a MetadataFunc that supplies the identity
// provider's metadata. The methods that deal with the IdP call it with
// their context; those that only describe the SP, such as ServeMetadata,
// do not. RemoteMetadata fetches and caches metadata from a URL, StaticMetadata and
// StaticMetadataBytes use metadata the application already has, and an
// application can supply its own function: for example, one that reads
// metadata from a database, or picks the IdP for the tenant named in the
// context.
//
// Settings that have no Option of their own are reached with a
// ServiceProviderOption, which adjusts the saml.ServiceProvider that each
// method builds. Pass it to New for every call, or to a single call
// alongside its other options:
//
//	config, err := samlsp.New(idp, entityID, samlsp.WithKey(key, cert), samlsp.SignMetadata)
//	config.ParseResponse(ctx, r, samlsp.WithRequestID(id), samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
//		sp.ValidateAudienceRestriction = func(*saml.Assertion) error { return nil }
//	}))
//
// # Hardening
//
// The saml.ServiceProvider that each method builds turns on checks that
// package saml leaves off by default for compatibility. It validates the
// authentication context, and refuses unknown conditions, AES-CBC
// encrypted assertions in unsigned Responses, SHA-1 signatures, expired
// IdP metadata, non-standard artifacts, and requests whose RelayState is
// longer than the 80 bytes the bindings allow. A ServiceProviderOption can
// turn one off for an IdP that needs it:
//
//	samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
//		sp.RequireSignedResponseForCBC = false // this IdP signs only assertions
//	})
//
// Microsoft Entra ID with token encryption, and Okta with an encrypted
// assertion, sign the assertion but not the Response, and encrypt with
// AES-CBC. Relax RequireSignedResponseForCBC for them, or have the IdP
// sign the Response. Older IdPs that sign with SHA-1 need
// RejectSHA1Signatures relaxed.
//
// # Replay protection
//
// ParseResponse accepts each assertion only once (and x/samlsp/slo each
// LogoutRequest), so that a message copied from a browser's history or a
// log cannot be used again. By default the IDs are kept in memory.
// They need no size limit: an ID is recorded only once the message is fully
// verified as one the IdP issued for this SP, and only until the message
// expires, at most saml.MaxIssueDelay after it was issued, plus clock
// skew. So the memory used follows the rate of real logins, and an attacker cannot add
// to it.
//
// The default protects a single process. Applications served by several
// processes share the state with WithReplayState.
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
// resolves the artifact with the IdP, using the HTTP client of
// WithHTTPClient. It accepts an unsolicited (IdP-initiated) Response only
// with AllowUnsolicited.
//
// # Single Logout and other extensions
//
// Single logout is in a separate package, github.com/crewjam/saml/x/samlsp/slo,
// so that SPs that do not need it do not carry it. Like
// github.com/crewjam/saml/x/samlsp/artifact, which sends messages with the
// HTTP-Artifact binding, it is built only on this package's public API:
// Send builds and sends any protocol message, WithModify lets a package
// give its own options, WithCustomBinding adds bindings, SignElement signs
// with the SP's key, and WithMetadata, WithCheck and ServiceProvider reach
// the configuration.
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
