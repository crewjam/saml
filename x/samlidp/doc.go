// Package samlidp implements the SAML 2.0 Web Browser SSO profile
// (saml-profiles §4.1) for an identity provider (IdP): it verifies
// service providers' AuthnRequests, makes signed Responses that tell them
// who the user is, and serves the IdP metadata.
//
// It is the counterpart of github.com/crewjam/saml/x/samlsp, and is
// shaped like an OAuth 2.0 or OpenID Connect provider library: the
// application owns users, sessions, login pages and consent, and calls
// this package at the two ends of a login. There are no stores, templates
// or user types here; github.com/crewjam/saml/samlidp is a complete,
// stand-alone IdP built on package saml instead.
//
// # Setup
//
//	entityID := "https://idp.example.com/saml/metadata"
//	sps := samlidp.StaticServiceProviders(spMetadata...)
//	config, err := samlidp.New(entityID, sps, samlidp.WithSigningKey(key, cert))
//	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)
//	http.HandleFunc(config.SSOPath(), sso)
//
// The entity ID names the IdP to the SPs. It is conventionally the URL of
// the IdP metadata. Unless WithSSOURL says otherwise, the single sign-on
// service is beside it, at "sso": here, https://idp.example.com/saml/sso.
// MetadataPath and SSOPath return the paths of those URLs.
//
// The second argument is a ServiceProviderFunc that supplies the metadata
// of an SP by its entity ID. StaticServiceProviders serves a fixed set,
// ParseMetadata checks metadata an administrator uploads, and an
// application can supply its own function: for example, one that reads
// metadata from a database.
//
// Settings that have no Option of their own are reached with an
// IdentityProviderOption, which adjusts the saml.IdentityProvider that
// each method builds:
//
//	config, err := samlidp.New(entityID, sps, samlidp.WithSigningKey(key, cert),
//		samlidp.SignMetadata,
//		samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
//			enc := xmlenc.OAEP_SHA256()
//			enc.BlockCipher = xmlenc.AES256GCM
//			idp.AssertionEncrypter = enc
//		}))
//
// Assertions are encrypted for SPs whose metadata publishes an encryption
// certificate, only with AES-GCM and with RSA-OAEP key transport using
// SHA-256: the IdP refuses to encrypt to an SP whose metadata lists only
// AES-CBC, or only SHA-1 key transport, unless New is passed
// EnableInsecureAESCBC or EnableInsecureRSAOAEPSHA1.
//
// # Web Browser SSO
//
// Login has two steps, as in an OAuth 2.0 authorization endpoint. First,
// at the SSO URL, verify the SP's request:
//
//	func sso(w http.ResponseWriter, r *http.Request) {
//		req, err := config.ParseAuthnRequest(r.Context(), r)
//		var status *saml.StatusError
//		if errors.As(err, &status) && req != nil {
//			msg, err := config.ErrorResponse(r.Context(), req, status)
//			...
//			msg.Write(w)
//			return
//		}
//		if err != nil { ... }
//		continueLogin(w, r, req)
//	}
//
// The AuthnRequest is plain data: what of the request bears on the
// answer. If the user must log in, or consent, first, keep it, such as in
// a server-side session, until they have: unlike the request it came in,
// it does not expire during a slow login. Delete it once it is answered:
// Response does not stop it from being answered again.
// Second, once the user is authenticated, answer it:
//
//	func continueLogin(w http.ResponseWriter, r *http.Request, req *samlidp.AuthnRequest) {
//		user := currentUser(r)
//		if user == nil || req.ForceAuthn {
//			if req.IsPassive {
//				msg, err := config.ErrorResponse(r.Context(), req, &saml.StatusError{
//					TopLevel: saml.StatusResponder, SecondLevel: saml.StatusNoPassive})
//				...
//			}
//			showLogin(w, r, req) // and come back here once logged in
//			return
//		}
//		msg, err := config.Response(r.Context(), req, samlidp.Subject{
//			NameID:       user.ID,
//			NameIDFormat: saml.PersistentNameIDFormat,
//			AuthnInstant: user.LoginTime,
//			Attributes: []samlidp.Attribute{
//				{Name: "mail", Values: []string{user.Email}},
//			},
//		})
//		...
//		msg.Write(w)
//	}
//
// Message.Write sends the Response to the SP's assertion consumer service
// with the HTTP-POST (or HTTP-POST-SimpleSign) binding: an HTML form that
// submits itself. For SPs that ask for the HTTP-Artifact binding, see
// github.com/crewjam/saml/x/samlidp/idpartifact, which plugs in with
// WithCustomBinding.
//
// For an IdP-initiated login, such as from a portal of applications, make
// the AuthnRequest with IDPInitiated instead of ParseAuthnRequest.
//
// # Checks
//
// ParseAuthnRequest checks requests as package saml does: they must be
// current, addressed to the SSO URL, from a known SP, signed by it if it
// says it signs, and name one of its assertion consumer services. The
// saml.IdentityProvider each method builds turns on checks that package
// saml leaves off by default for compatibility: it refuses SHA-1
// signatures, enforces the request's NameIDPolicy and
// RequestedAuthnContext, and answers expired requests with a SAML error
// Response. An IdentityProviderOption can turn one off for an SP that
// needs it:
//
//	samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
//		idp.EnforceNameIDPolicy = false // this SP asks for a format it does not need
//	})
//
// A NameIDPolicy SPNameQualifier other than the SP's own entity ID is
// refused, with StatusInvalidNameIDPolicy, unless WithAffiliation says
// the SP is a member of that affiliation (saml-core §3.4.1.1). Whether a
// NameID may be created is the application's to decide: if the user has
// none for the SP yet, such as a persistent one, and the request's
// AllowCreate is false, answer with ErrorResponse and
// StatusInvalidNameIDPolicy:
//
//	nameID, ok := persistentID(user, req.ServiceProvider)
//	if !ok && !req.AllowCreate {
//		msg, err := config.ErrorResponse(r.Context(), req, &saml.StatusError{
//			TopLevel: saml.StatusRequester, SecondLevel: saml.StatusInvalidNameIDPolicy})
//		...
//	}
//
// A signed AuthnRequest is accepted only once (and each LogoutRequest and
// LogoutResponse of x/samlidp/idpslo). By default the record is kept in
// memory, which protects a single process; see WithReplayState.
//
// # Errors
//
// Errors from verifying a request come from package saml unchanged. Match
// them with errors.Is against the saml.Err* values, such as
// saml.ErrUnknownServiceProvider and saml.ErrInvalidSignature. Errors that
// must be reported to the SP, rather than to the user, match
// *saml.StatusError; send them with ErrorResponse.
//
// # Single logout
//
// Single logout is in a separate package,
// github.com/crewjam/saml/x/samlidp/idpslo, built on this package's public
// API: Send signs and sends any protocol message, SignElement signs with
// the IdP's key, Consume records messages for replay protection, and
// IdentityProvider reaches the configuration. Keep the Participant of
// each Response with the user's IdP session: it names the session that
// single logout must end at the SP. Give each SP its own opaque
// SessionIndex, such as an HMAC of the session's ID and the SP's entity
// ID, never the session token itself: SPs see it (saml-core §2.7.2).
//
// # Stability
//
// This package is under x/ and its API may change.
package samlidp
