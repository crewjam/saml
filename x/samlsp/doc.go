// Package samlsp implements the SAML 2.0 Web Browser SSO profile
// (saml-profiles §4.1) for a service provider (SP): it builds
// AuthnRequests, verifies the identity provider's Responses, and serves
// the SP metadata. Single logout is in github.com/crewjam/saml/x/samlsp/slo.
// Sessions are the application's; github.com/crewjam/saml/x/samlsp/pending
// keeps the one piece of state every login needs, the ID of the request in
// progress, in a cookie.
//
// # Setup
//
//	entityID := "https://sp.example.com/saml/metadata"
//	idp := samlsp.RemoteMetadata("https://idp.example.com/metadata")
//	config, err := samlsp.New(entityID, idp, samlsp.WithSigningKey(key, cert))
//	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)
//	http.HandleFunc(config.ACSPath(), acs)
//
// The entity ID names the SP to the IdP. It is conventionally the URL of
// the SP metadata. Unless
// WithACSURL says otherwise, the ACS is beside it, at "acs": here,
// https://sp.example.com/saml/acs. MetadataPath and ACSPath return the
// paths of those URLs, so that the handlers are served where the IdP
// expects them.
//
// The key of WithSigningKey signs. The IdP can encrypt assertions only to
// the key of WithEncryptionKey, which may be the same RSA key.
//
// The second argument is a MetadataFunc that supplies the identity
// provider's metadata. The methods that deal with the IdP call it with
// their context; those that only describe the SP, such as ServeMetadata,
// do not. RemoteMetadata fetches and caches metadata from a URL, StaticMetadata and
// StaticMetadataBytes use metadata the application already has, and an
// application can supply its own function: for example, one that reads
// metadata from a database.
//
// An SP that serves several IdPs, such as one per tenant, can instead
// name the IdP per call with WithIdentityProvider, and pass New a nil
// MetadataFunc. IdentityProviderContext names it for calls that take no
// such option. A message that carries none of the SP's own state, such as
// an IdP-initiated Response or an IdP's LogoutRequest, names its IdP only
// in its Issuer: PeekUnverifiedIssuer reads it, unverified, to choose the IdP that
// verifies the message. When the SP itself differs per tenant, by entity
// ID or ACS URL, build a Config per request; New is cheap, but see
// WithReplayState.
//
// Settings that have no Option of their own are reached with a
// ServiceProviderOption, which adjusts the saml.ServiceProvider that each
// method builds. Pass it to New for every call, or to a single call
// alongside its other options:
//
//	config, err := samlsp.New(entityID, idp, samlsp.WithSigningKey(key, cert), samlsp.SignMetadata)
//	config.ParseResponse(ctx, r, samlsp.WithRequestID(id), samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
//		sp.ValidateAudienceRestriction = func(*saml.Assertion) error { return nil }
//	}))
//
// # Key rotation
//
// The IdP trusts the SP's signatures, and encrypts to the SP, with the
// certificates of the SP metadata, which it fetches again only from time
// to time (or which its administrator uploads). To replace a key without a
// moment when the IdP and the SP disagree on it, publish the new
// certificate first:
//
//  1. Publish the next certificates with WithNextSigningCertificates and
//     WithNextEncryptionCertificates, and pass the next encryption key to
//     WithDecryptionKeys at the same time, since an IdP may encrypt to any
//     certificate the metadata lists (New refuses a next encryption
//     certificate without its key).
//  2. Wait until every IdP has the new metadata: at least the
//     cacheDuration or validUntil the SP metadata states, or as long as
//     its IdPs take to refresh it; an IdP given an uploaded copy needs
//     the new copy uploaded.
//  3. Switch: pass the next keys to WithSigningKey and WithEncryptionKey,
//     move the previous encryption key to WithDecryptionKeys, for
//     assertions already encrypted to it, and pass the previous
//     certificates to WithNextSigningCertificates and
//     WithNextEncryptionCertificates, so that IdPs that have not yet
//     refreshed keep working.
//  4. Once every IdP has refreshed again, and assertions encrypted to the
//     previous key have expired, drop the previous key and certificates.
//
// For example, in step 1, with the key pair (signKey, signCert) in use and
// (nextKey, nextCert) to replace it, for both signing and encryption:
//
//	samlsp.New(entityID, idp,
//		samlsp.WithSigningKey(signKey, signCert),
//		samlsp.WithEncryptionKey(signKey, signCert),
//		samlsp.WithNextSigningCertificates(nextCert),
//		samlsp.WithNextEncryptionCertificates(nextCert),
//		samlsp.WithDecryptionKeys(nextKey))
//
// and in step 3:
//
//	samlsp.New(entityID, idp,
//		samlsp.WithSigningKey(nextKey, nextCert),
//		samlsp.WithEncryptionKey(nextKey, nextCert),
//		samlsp.WithNextSigningCertificates(signCert),
//		samlsp.WithNextEncryptionCertificates(signCert),
//		samlsp.WithDecryptionKeys(signKey))
//
// The IdP's own keys rotate the same way, in the IdP metadata (see
// RemoteMetadata).
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
// ParseResponse accepts each assertion and each resolved artifact only
// once (and x/samlsp/slo each LogoutRequest and LogoutResponse), so that a message copied from a browser's history or a
// log cannot be used again. Each message is recorded under a hash of its
// ID and of the IdP's entity ID (ReplayKey), so the messages of different
// IdPs never collide, and one record can serve every tenant of an SP. By
// default the record is kept in memory, in a replay.Memory of package
// github.com/crewjam/saml/x/samlsp/replay, which protects a single process.
// Applications served by several processes, or that build a Config per
// request, share a record with WithReplayState. Its Consume gets the
// context of the call that accepts the message, so a record kept in a
// database can use the request's deadline.
//
// # Web Browser SSO
//
// Login has two steps. First, send the browser to the IdP with an
// AuthnRequest. The application must remember the request's ID, keyed by
// the RelayState, in this browser, until the Response arrives. Package
// github.com/crewjam/saml/x/samlsp/pending keeps it in a cookie:
//
//	tracker, err := pending.New(config, cookieKey)
//
//	func login(w http.ResponseWriter, r *http.Request) {
//		req, err := config.AuthnRequest(r.Context(), rand.Text())
//		if err != nil { ... }
//		if err := tracker.Remember(w, req, ""); err != nil { ... }
//		req.Write(w)
//	}
//
// Second, at the assertion consumer service (ACS), verify the Response and
// check that its InResponseTo is the remembered ID, and that the
// authentication context is one the request asked for, if it asked for
// one with WithAuthnContext:
//
//	func acs(w http.ResponseWriter, r *http.Request) {
//		login, err := tracker.Find(w, r)
//		if err != nil { ... }
//		assertion, err := config.ParseResponse(r.Context(), r, login.ResponseOption())
//		if err != nil { ... }
//		tracker.Forget(w, login) // only once the Response is verified
//		startSession(w, assertion.NameID, assertion.SessionIndexes, assertion.Attributes)
//	}
//
// An application can keep the ID elsewhere instead, such as in a
// server-side session, with the Message's RequestedAuthnContext, and pass
// both to ParseResponse with WithRequest. A cookie for them must reach the
// ACS with the IdP's cross-site POST, so it must be SameSite=None and
// Secure.
//
// ParseResponse returns a verified Assertion. It accepts the HTTP-POST
// and HTTP-POST-SimpleSign bindings, and, with AcceptArtifactResponses,
// which lists the ACS with it in the SP metadata, the HTTP-Artifact
// binding: it then resolves the artifact with the IdP, using the HTTP
// client of WithHTTPClient. It accepts an unsolicited (IdP-initiated)
// Response only with AllowUnsolicited.
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
// with a status other than Success, the error matches saml.ErrBadStatus,
// whose SubStatus holds the second-level status, such as NoPassive for an
// IsPassive request. errors.Is matches a saml.ErrBadStatus that leaves
// SubStatus empty against any second-level status.
//
// A Response that does not verify gives a *saml.InvalidResponseError,
// whose message reveals nothing an attacker could use ("Authentication
// failed"), so it can be shown to the user. Log errors.Unwrap(err), which
// says what was wrong.
//
// # Stability
//
// This package is under x/ and its API may change.
package samlsp
