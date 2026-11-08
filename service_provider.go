package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/crewjam/saml/internal/xmlroundtrip"

	"github.com/crewjam/saml/internal/signerutil"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/xmlenc"
)

// NameIDFormat is the format of the id
type NameIDFormat string

// Element returns an XML element representation of n.
func (n NameIDFormat) Element() *etree.Element {
	el := etree.NewElement("")
	el.SetText(string(n))
	return el
}

// Name ID formats
const (
	UnspecifiedNameIDFormat  NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	TransientNameIDFormat    NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	EmailAddressNameIDFormat NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	PersistentNameIDFormat   NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// SignedElementVerifier is a SignatureVerifier that also returns what the
// signature covers: the element without its Signature, as dsig's
// ValidationContext.Validate returns it. When the ServiceProvider's
// SignatureVerifier implements it, the service provider reads the signed
// message from the element it returns rather than from the message as
// received. A SignatureVerifier that does not implement it keeps the old
// behaviour: the message is read as received.
type SignedElementVerifier interface {
	SignatureVerifier
	VerifySignedElement(validationContext *dsig.ValidationContext, el *etree.Element) (*etree.Element, error)
}

// SignatureVerifier verifies a signature
//
// Can be implemented in order to override ServiceProvider's default
// way of verifying signatures.
type SignatureVerifier interface {
	VerifySignature(validationContext *dsig.ValidationContext, el *etree.Element) error
}

// ServiceProvider implements SAML Service provider.
//
// In SAML, service providers delegate responsibility for identifying
// clients to an identity provider. If you are writing an application
// that uses passwords (or whatever) stored somewhere else, then you
// are service provider.
//
// See the example directory for an example of a web application using
// the service provider interface.
type ServiceProvider struct {
	// Entity ID is optional - if not specified then MetadataURL will be used
	EntityID string

	// Key is the private key we use to sign requests. Its public key must be
	// an *rsa.PublicKey or an *ecdsa.PublicKey. Any crypto.Signer works for
	// signing, including keys held in a KMS or HSM. Unless EncryptionKey is
	// set, Key is also used to decrypt encrypted assertions, which only works
	// when Key is an *rsa.PrivateKey.
	Key crypto.Signer

	// Certificate is the public part of Key.
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate

	// EncryptionKey, if set, is the private key used to decrypt encrypted
	// assertions, instead of Key. Use it to keep separate signing and
	// encryption keys, for example when Key is an ECDSA key, which cannot be
	// used for XML encryption.
	EncryptionKey *rsa.PrivateKey

	// EncryptionCertificate is the public part of EncryptionKey. It is
	// advertised in the metadata as the encryption key. If it is nil, the
	// metadata advertises Certificate for encryption, but only when its public
	// key is an RSA key.
	EncryptionCertificate *x509.Certificate

	// DecryptionKeys are further private keys that decrypt encrypted
	// assertions, tried in order after EncryptionKey (or Key, if
	// EncryptionKey is unset). Set them while rotating the SP encryption key,
	// so that an assertion the IdP encrypted to either the old or the new key
	// is accepted. They are never used for signing, and are not advertised in
	// the metadata.
	DecryptionKeys []*rsa.PrivateKey

	// KeyOnlySigns, if true, keeps Key to signing: when EncryptionKey is
	// unset, Key does not decrypt assertions, and Certificate is not
	// advertised in the metadata for encryption. Encrypted assertions are
	// then accepted only with EncryptionKey or DecryptionKeys set.
	KeyOnlySigns bool

	// HTTPClient to use for SOAP exchanges with the IdP: SAML artifact
	// resolution, attribute queries (QueryAttributes) and SOAP single logout.
	// If nil, a client with a 10 second timeout that follows no redirects,
	// and connects only to public addresses, is used: the endpoints come
	// from the IdP metadata, which could otherwise point them at services
	// on your own network. Set a client to reach an IdP on your own
	// network; it is used as it is, so guard its dialer (such as with
	// code.dny.dev/ssrf) if the metadata is not fully trusted. Whichever
	// client is used, a redirect to a location that is not https (or
	// http, with AllowInsecureSOAPEndpoints) is not followed.
	HTTPClient *http.Client

	// AllowInsecureSOAPEndpoints lets the service provider send SOAP
	// messages (ArtifactResolve, AttributeQuery and SOAP LogoutRequest) to
	// http endpoints of the IdP. By default they are sent only to https
	// endpoints, and an http one fails with an error matching
	// ErrInsecureSOAPEndpoint, so that the user's NameID, attributes and
	// assertions never cross the network in the clear. Set it only for
	// tests and development setups.
	AllowInsecureSOAPEndpoints bool

	// MetadataURL is the full URL to the metadata endpoint on this host,
	// i.e. https://example.com/saml/metadata
	MetadataURL url.URL

	// AcsURL is the full URL to the SAML Assertion Customer Service endpoint
	// on this host, i.e. https://example.com/saml/acs
	AcsURL url.URL

	// AcsIndex, if set, makes authentication requests carry
	// AssertionConsumerServiceIndex with this value, instead of
	// AssertionConsumerServiceURL and ProtocolBinding (SAML core §3.4.1
	// does not allow both). The IdP then sends the response to the
	// AssertionConsumerService endpoint with this index in the SP metadata it
	// has on file, using that endpoint's binding. That endpoint's Location
	// must still be AcsURL, because responses are only accepted there. If nil,
	// requests carry AssertionConsumerServiceURL and ProtocolBinding.
	AcsIndex *int

	// SloURL is the full URL to the SAML Single Logout endpoint on this host.
	// i.e. https://example.com/saml/slo
	SloURL url.URL

	// IDPMetadata is the metadata from the identity provider.
	IDPMetadata *EntityDescriptor

	// IDPCertificateFingerprint is fingerprint of the idp public certificate. If this field is specified,
	// IDPCertificateFingerprintAlgorithm must also be specified, and IDPCertificate must not be specified.
	IDPCertificateFingerprint *string
	// IDPCertificateFingerprintAlgorithm is fingerprint algorithm used to obtain fingerprint of the idp public
	// certificate.
	// If this field is specified, IDPCertificateFingerprint must also be specified, and IDPCertificate must not be specified.
	IDPCertificateFingerprintAlgorithm *string

	// IDPCertificate to use as idp public certificate. If this field is specified, IDPCertificateFingerprint and
	// IDPCertificateFingerprintAlgorithm must not be specified.
	IDPCertificate *string

	// AuthnNameIDFormat is the format used in the NameIDPolicy for
	// authentication requests
	AuthnNameIDFormat NameIDFormat

	// SendUnspecifiedNameIDFormat, when true and AuthnNameIDFormat is
	// UnspecifiedNameIDFormat, sends the full unspecified URI as the Format
	// of the AuthnRequest NameIDPolicy and the LogoutRequest NameID. By
	// default the Format is left off, which the spec reads as unspecified
	// (SAML Core §2.2.2, §3.4.1.1), but some IdPs (e.g. Keycloak) reject a
	// request without it.
	SendUnspecifiedNameIDFormat bool

	// Scoping, when set, is sent in authentication requests. Proxying identity
	// providers (gateways) use its IDPList to choose which identity provider to
	// delegate authentication to.
	Scoping *Scoping

	// MetadataValidDuration is a duration used to calculate validUntil
	// attribute in the metadata endpoint
	MetadataValidDuration time.Duration

	// MetadataOmitValidUntil, when true, omits the optional validUntil
	// attribute from the metadata (saml-metadata-2.0-os §2.3.2). Because the
	// root element must carry validUntil or cacheDuration (§2.3.1), the
	// metadata then carries cacheDuration (DefaultCacheDuration) instead.
	// MetadataValidDuration is ignored when this is set.
	MetadataOmitValidUntil bool

	// ForceAuthn allows you to force re-authentication of users even if the user
	// has a SSO session at the IdP.
	ForceAuthn *bool

	// RequestedAuthnContext allow you to specify the requested authentication
	// context in authentication requests
	RequestedAuthnContext *RequestedAuthnContext

	// ValidateAuthnContextClassRef, if true, requires an assertion to carry
	// an AuthnStatement whose AuthnContextClassRef is one of the classes in
	// RequestedAuthnContext. It has no effect if RequestedAuthnContext is
	// nil or names no class.
	//
	// The "exact" Comparison (or an empty one, which means "exact") is
	// supported directly. The ordering that "minimum", "better" and
	// "maximum" refer to is defined by each deployment, not by the SAML
	// specification (saml-core §3.3.2.2.1), so for any other Comparison
	// AuthnContextClassRefComparator decides; without it, every assertion
	// is rejected rather than accepted unchecked.
	ValidateAuthnContextClassRef bool

	// AuthnContextClassRefComparator, if set, lets ValidateAuthnContextClassRef
	// check a RequestedAuthnContext whose Comparison is not "exact" (for
	// example "minimum", "better" or "maximum"), using the deployment's own
	// ordering of authentication context classes.
	//
	// It is called with the Comparison, the requested classes (in order of
	// preference) and the AuthnContextClassRef of one AuthnStatement of the
	// assertion, and reports whether that class satisfies the request. The
	// assertion is accepted if it returns true for any AuthnStatement. It
	// should return false for a Comparison it does not know.
	//
	// It is not called for the "exact" Comparison, which is always checked
	// by string equality.
	AuthnContextClassRefComparator func(comparison string, requested []string, got string) bool

	// AllowIDPInitiated accepts unsolicited (IdP-initiated) responses, which
	// have no InResponseTo. A response or assertion that does carry an
	// InResponseTo must still match a request this SP made; set
	// ValidateRequestID to accept IdPs that send one on IdP-initiated logins.
	AllowIDPInitiated bool

	// DefaultRedirectURI where untracked requests (as of IDPInitiated) are redirected to
	DefaultRedirectURI string

	// SignatureVerifier, if non-nil, allows you to implement an alternative way
	// to verify signatures.
	SignatureVerifier SignatureVerifier

	// SignatureMethod, if non-empty, authentication requests will be signed.
	//
	// The method specified here must be consistent with the type of Key.
	//
	// If Key is *rsa.PrivateKey, then this must be one of dsig.RSASHA1SignatureMethod,
	// dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, or
	// dsig.RSASHA512SignatureMethod:
	//
	// If Key is *ecdsa.PrivateKey, then this must be one of dsig.ECDSASHA1SignatureMethod,
	// dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, or
	// dsig.ECDSASHA512SignatureMethod.
	SignatureMethod string

	// LogoutSignatureMethod, if non-empty, is used instead of
	// SignatureMethod to sign the LogoutRequests and LogoutResponses the SP
	// sends, so that they can be signed while AuthnRequests are not. The
	// single logout profile requires LogoutRequests and LogoutResponses sent
	// with the HTTP-Redirect or HTTP-POST binding to be signed
	// (saml-profiles §4.4.3.1 and §4.4.3.4). If empty, SignatureMethod is
	// used for them too. It takes the same values as SignatureMethod.
	LogoutSignatureMethod string

	// SignMetadata, if true, asks that the SP metadata be published with an
	// enveloped XML signature made with Key; samlsp.Middleware.ServeMetadata
	// honors it. See SignedMetadata.
	SignMetadata bool

	// LogoutBindings specify the bindings available for SLO endpoint. If empty,
	// HTTP-POST binding is used. HTTPPostSimpleSignBinding may be listed: the
	// logout validation functions accept HTTP-POST-SimpleSign messages.
	LogoutBindings []string

	// AssertionConsumerServiceBindings specify the bindings advertised for the
	// AssertionConsumerService endpoint in the SP metadata, in order of
	// preference. If empty, both HTTP-POST and HTTP-Artifact bindings are
	// advertised. Set this to []string{HTTPPostBinding} to stop advertising
	// the HTTP-Artifact binding, for example when the IDP does not publish an
	// ArtifactResolutionService or the SP cannot reach it. Include
	// HTTPPostSimpleSignBinding to advertise that the ACS accepts
	// HTTP-POST-SimpleSign responses (ParseResponse always accepts them).
	AssertionConsumerServiceBindings []string

	// ValidateAudienceRestriction allows you to override the default audience validation
	// for an assertion. If nil, the default audience validation is used: the
	// assertion must have at least one AudienceRestriction, and every
	// AudienceRestriction must list this SP's audience (EntityID, or
	// MetadataURL when EntityID is empty) among its audiences (saml-core
	// §2.5.1.4).
	ValidateAudienceRestriction func(assertion *Assertion) error

	// RejectUnknownConditions, if true, refuses an assertion whose
	// Conditions has child elements this package does not understand, named
	// in Conditions.UnknownConditions: anything but AudienceRestriction,
	// OneTimeUse and ProxyRestriction, such as a saml:Condition extended
	// with xsi:type. saml-core §2.5.1.1 makes such an assertion
	// Indeterminate, and says it MUST be rejected; the error matches
	// ErrUnsupported. It is off by default, so such conditions are ignored,
	// because some IdPs send extension conditions (delegation restrictions,
	// for example) that refusing would break. ValidateUnknownConditions, if
	// set, decides instead.
	RejectUnknownConditions bool

	// RequireSignedResponseForCBC, if true, refuses to decrypt an
	// EncryptedAssertion whose EncryptedData uses a CBC block cipher
	// (aes128-cbc, aes192-cbc, aes256-cbc or tripledes-cbc) unless the
	// message that carries it was authenticated before decryption: a
	// Response (or, for the HTTP-Artifact binding, an ArtifactResponse)
	// with a valid signature by the IdP, or a Response whose
	// HTTP-POST-SimpleSign signature is valid. The saml-core errata (E93,
	// §6.2) say that "when CBC-mode algorithms are used for data
	// encryption, relying parties SHOULD require the presence of integrity
	// protection before processing encrypted SAML assertions", since
	// decrypting unauthenticated CBC ciphertext is what padding and format
	// oracle attacks on XML Encryption need. A signature on the assertion
	// inside the encryption does not count, because it can only be checked
	// after decrypting. The refusal matches ErrInvalidSignature, and
	// happens before any decryption. AES-GCM is authenticated encryption,
	// so it is not affected. ParseXMLAttributeQueryResponse applies it to
	// the Response the attribute authority sends.
	//
	// It is off by default, because many IdPs sign only the assertion and
	// encrypt it with AES-CBC; with it on, configure the IdP to sign the
	// Response or to encrypt with AES-GCM.
	RequireSignedResponseForCBC bool

	// ValidateUnknownConditions, if set, decides an assertion whose
	// Conditions has child elements this package does not understand (see
	// RejectUnknownConditions), whatever RejectUnknownConditions says:
	// return nil to accept the assertion, or an error to refuse it. It is
	// called only when there are unknown conditions, and for login and
	// attribute query assertions alike.
	ValidateUnknownConditions func(assertion *Assertion) error

	// ValidateRequestID allows you to override the default request ID validation.
	// If nil, the default request ID validation is used. With AllowIDPInitiated
	// set, it also decides a non-empty assertion SubjectConfirmationData
	// InResponseTo, passed as Response.InResponseTo.
	ValidateRequestID func(response Response, possibleRequestIDs []string) error

	// Clock, if non-nil, is the time source for everything this
	// ServiceProvider does that depends on the current time: timestamps on
	// the requests and metadata it issues, assertion and logout message time
	// checks, and certificate validity during XML and redirect binding
	// signature validation.
	//
	// If nil, the real clock is used (through the deprecated package-level
	// TimeNow and Clock). Setting this field instead of replacing those
	// globals allows ServiceProviders with different clocks to be used
	// concurrently, for example in parallel tests.
	Clock *dsig.Clock

	// Rand, if non-nil, is the source of the cryptographically random
	// bytes this ServiceProvider needs: the IDs of the requests, responses
	// and metadata it issues, and the keys, IVs and nonces used to encrypt
	// NameIDs in its LogoutRequests (unless LogoutNameIDEncrypter has a
	// source of its own). It must be safe for concurrent use if the
	// ServiceProvider is.
	//
	// If nil, crypto/rand is used (through the deprecated package-level
	// RandReader, and xmlenc.RandReader for encryption).
	Rand io.Reader

	// MaxClockSkew, if not zero, replaces the package-level MaxClockSkew for
	// this ServiceProvider: the leeway allowed for the IDP's clock when
	// checking IssueInstant, NotBefore and NotOnOrAfter times.
	MaxClockSkew time.Duration

	// MaxIssueDelay, if not zero, replaces the package-level MaxIssueDelay
	// for this ServiceProvider: the longest allowed time between a
	// message's IssueInstant and its receipt, which also bounds how long
	// replay records are kept.
	MaxIssueDelay time.Duration

	// IgnoreCertificateExpiry, if true, disables the check that the IDP's
	// signing certificate is within its validity period (NotBefore and
	// NotAfter) when validating XML and HTTP-Redirect binding signatures.
	// The signature must still be made by a key in one of the trusted IDP
	// certificates.
	//
	// The SAML V2.0 Metadata Interoperability Profile treats certificates in
	// metadata only as a container for a public key, and permits them to be
	// expired or not yet valid. Some IDPs publish expired signing
	// certificates as a result. Enabling this allows interoperating with
	// them.
	IgnoreCertificateExpiry bool

	// RejectExpiredIDPMetadata, if true, refuses to rely on IDPMetadata once
	// it has expired: when the signing certificates for a Response,
	// Assertion, ArtifactResponse, LogoutRequest, LogoutResponse or attribute
	// query response are taken from IDPMetadata, and the validUntil of the
	// EntityDescriptor, or of an IDPSSODescriptor (or, for attribute query
	// responses, AttributeAuthorityDescriptor) they are taken from, has
	// passed, the message is refused with an error matching ErrExpired (and
	// ErrInvalidSignature, for XML signatures). saml-metadata-2.0-os §4.3.1
	// says expired metadata must not be relied on and a fresh copy must be
	// retrieved. When IDPCertificate or IDPCertificateFingerprint is set the
	// certificates do not come from IDPMetadata, and it is not checked.
	//
	// Only validUntil is checked; cacheDuration is not, since the
	// ServiceProvider does not know when IDPMetadata was retrieved. The
	// samlsp Parse and Fetch metadata functions set the ValidUntil of the
	// returned EntityDescriptor to the earliest validUntil of the entity and
	// of the EntitiesDescriptor elements that enclose it.
	//
	// It is off by default, because metadata whose validUntil has passed is
	// commonly kept in use, and enabling this rejects every login until the
	// metadata is refreshed.
	RejectExpiredIDPMetadata bool

	// RejectSHA1Signatures, if true, refuses messages from the IDP that are
	// signed with a SHA-1 based algorithm: an XML signature whose
	// SignatureMethod or any DigestMethod is SHA-1 based (rsa-sha1,
	// ecdsa-sha1, dsa-sha1, hmac-sha1 or sha1), and an HTTP-Redirect or
	// HTTP-POST-SimpleSign signature whose SigAlg is. The check applies to
	// every signature the ServiceProvider verifies, including those checked
	// by SignatureVerifier, and the error matches ErrUnsupported (and, for
	// XML signatures, ErrInvalidSignature). If false, SHA-1 is accepted.
	RejectSHA1Signatures bool

	// ReplayCache, if set, records the ID of the assertion each accepted
	// response is accepted for, and refuses a response whose assertion it
	// has already recorded. Without it, a captured assertion is accepted
	// again until it expires, and an IdP-initiated one has no request ID to
	// tie it to a single use. If nil, assertions are not checked for replay.
	//
	// It also records the ID of each LogoutRequest that ValidateLogoutRequest
	// (and the other LogoutRequest validation methods) accept, and refuses a
	// LogoutRequest whose ID it has already recorded. These IDs are recorded
	// under the key "LogoutRequest:" followed by the ID, so they cannot
	// collide with assertion IDs, which are recorded as is and, being
	// xs:ID values, contain no colon.
	//
	// It also records each artifact ParseResponse resolves, once the IdP
	// has resolved it to a verified Response, and refuses an artifact it has
	// already recorded (saml-bindings-2.0-os §3.6.5.2: an artifact is
	// resolved only once). A
	// type 0x0004 artifact is recorded under "Artifact:" followed by the hex
	// SourceID, a colon and the hex MessageHandle; any other artifact under
	// "Artifact:raw:" followed by its value.
	ReplayCache AssertionReplayCache

	// RequireStandardArtifacts, if true, makes ParseResponse refuse a
	// SAMLart that is not a type 0x0004 artifact (saml-bindings-2.0-os
	// §3.6.4: base64 of a 2-byte TypeCode 0x0004, a 2-byte EndpointIndex, a
	// 20-byte SourceID and a 20-byte MessageHandle), or whose SourceID is
	// not the SHA-1 hash of the IdP's entityID (§3.6.4.1), without
	// contacting the IdP. The error matches ErrArtifactResolution, and also
	// ErrMalformedMessage, ErrUnsupported or ErrIssuerMismatch. If false,
	// such an artifact is sent unchanged to the IdP's first SOAP
	// ArtifactResolutionService, as before.
	//
	// Either way, the EndpointIndex of a type 0x0004 artifact selects the
	// indexed SOAP ArtifactResolutionService it names in the IdP metadata,
	// falling back to the first SOAP ArtifactResolutionService when none
	// has that index, and a SAMLart longer than 256 bytes or with bytes
	// outside printable ASCII is refused without contacting the IdP.
	RequireStandardArtifacts bool

	// EncryptLogoutNameID, if true, makes MakeLogoutRequest,
	// MakeRedirectLogoutRequest and MakeSimpleSignLogoutRequest identify the
	// principal with a saml:EncryptedID instead of a NameID: the NameID is
	// encrypted to the IDP's encryption certificate from IDPMetadata (see
	// EncryptLogoutRequestNameID). Set it when the IDP requires it, or so
	// that the NameID is not disclosed to the browser.
	EncryptLogoutNameID bool

	// LogoutNameIDEncrypter, if set, encrypts the NameID of LogoutRequests
	// for the IDP (see EncryptLogoutNameID). It is passed the IDP's
	// *x509.Certificate as the key. Use it to select the key transport,
	// digest and block cipher the IDP supports, for example:
	//
	//	enc := xmlenc.OAEP()
	//	enc.BlockCipher = xmlenc.AES256GCM
	//	sp.LogoutNameIDEncrypter = enc
	//
	// When nil, RSA-OAEP-MGF1P with a SHA-1 digest is used with the
	// strongest block cipher that the IDP metadata lists in the
	// EncryptionMethods of its encryption key: AES-GCM (256, 128 then 192
	// bit keys) before AES-CBC. If the metadata lists none of them,
	// AES-256-GCM is used; set LogoutNameIDEncrypter for an IDP that cannot
	// decrypt AES-GCM and does not say so in its metadata.
	LogoutNameIDEncrypter xmlenc.Encrypter

	// LimitRelayStateLength, if true, makes the calls that start an exchange
	// with the IDP refuse a RelayState longer than MaxRelayStateLength (80
	// bytes), as the SAML bindings require of senders (saml-bindings-2.0-os
	// §3.4.3 and §3.5.3), with an error matching ErrRelayStateTooLong:
	// AuthnRequest.Redirect, MakeRedirectAuthenticationRequest,
	// MakePostAuthenticationRequest, AuthnRequest.SimpleSign,
	// RedirectLogoutRequestURL, MakeRedirectLogoutRequest,
	// MakePostLogoutRequest and LogoutRequest.SimpleSign, and samlsp's
	// CookieRequestTracker for a RelayStateFunc result. It is off by
	// default, because many IdPs accept a longer RelayState and
	// applications rely on it. A RelayState the SP echoes in a
	// LogoutResponse is never checked.
	LimitRelayStateLength bool

	// AcceptLogoutRequestBaseID, if true, lets ValidateLogoutRequest accept
	// a LogoutRequest whose principal is a saml:BaseID (in the clear, or in
	// an EncryptedID) rather than a NameID. The returned request's BaseID
	// then holds the element and its NameID is nil, so the caller must
	// interpret the BaseID itself. If false, such a request is refused with
	// an error matching ErrUnsupported.
	AcceptLogoutRequestBaseID bool

	// AcceptAssertionBaseID, if true, lets the SP accept an assertion whose
	// Subject identifies the principal with a saml:BaseID (in the clear, or
	// in an EncryptedID) rather than a NameID (saml-core-2.0-os §2.2.3 and
	// §2.4.1). The returned assertion's Subject.BaseID then holds the
	// element and its Subject.NameID is nil, so the caller must interpret
	// the BaseID itself: samlsp, for one, takes the session subject from
	// the NameID only. If false, such an assertion is refused with an error
	// matching ErrUnsupported. An assertion whose Subject has none of
	// BaseID, NameID and EncryptedID is always refused (ErrMissingElement).
	AcceptAssertionBaseID bool
}

// AssertionReplayCache records the IDs of accepted assertions, so that each
// is accepted only once. Implementations must be safe for concurrent use, and
// should be shared by every server that accepts assertions for the same
// service provider.
//
// ServiceProvider.ReplayCache and IdentityProvider.ReplayCache also record
// the IDs of accepted LogoutRequests in it, under keys prefixed with
// "LogoutRequest:", and ServiceProvider.ReplayCache records the artifacts
// it resolves under keys prefixed with "Artifact:".
type AssertionReplayCache interface {
	// Consume atomically records assertionID as used until expiresAt, after
	// which the ServiceProvider no longer accepts the assertion; then the
	// record may be dropped. It returns ErrAssertionReplayed if
	// assertionID is already recorded, and any other error if it cannot
	// record it. Any error refuses the assertion.
	Consume(assertionID string, expiresAt time.Time) error
}

// ErrAssertionReplayed is returned by an AssertionReplayCache for an
// assertion ID it has already recorded.
var ErrAssertionReplayed = errors.New("assertion has already been used")

// now returns the current time as seen by this ServiceProvider.
func (sp *ServiceProvider) now() time.Time {
	return clockNow(sp.Clock)
}

// limits returns the clock skew and issue delay this ServiceProvider allows.
func (sp *ServiceProvider) limits() timeLimits {
	return timeLimits{clockSkew: sp.MaxClockSkew, issueDelay: sp.MaxIssueDelay}
}

// maxClockSkew returns MaxClockSkew, or the package-level MaxClockSkew if it
// is zero.
func (sp *ServiceProvider) maxClockSkew() time.Duration { return sp.limits().skew() }

// maxIssueDelay returns MaxIssueDelay, or the package-level MaxIssueDelay if
// it is zero.
func (sp *ServiceProvider) maxIssueDelay() time.Duration { return sp.limits().delay() }

// dsigClock returns the clock to use for signature validation. It may be
// nil, in which case dsig uses the real clock.
func (sp *ServiceProvider) dsigClock() *dsig.Clock {
	return dsigClockOrDefault(sp.Clock)
}

// MaxIssueDelay is the longest allowed time between when a SAML assertion is
// issued by the IDP and the time it is received by ParseResponse. This is used
// to prevent old responses from being replayed (while allowing for some clock
// drift between the SP and IDP).
var MaxIssueDelay = time.Second * 90

// MaxClockSkew allows for leeway for clock skew between the IDP and SP when
// validating assertions. It defaults to 180 seconds (matches shibboleth).
var MaxClockSkew = time.Second * 180

// timeLimits is the clock skew and issue delay a provider allows. A zero
// field means the package-level MaxClockSkew or MaxIssueDelay, read when it
// is used.
type timeLimits struct {
	clockSkew  time.Duration
	issueDelay time.Duration
}

func (l timeLimits) skew() time.Duration {
	if l.clockSkew != 0 {
		return l.clockSkew
	}
	return MaxClockSkew
}

func (l timeLimits) delay() time.Duration {
	if l.issueDelay != 0 {
		return l.issueDelay
	}
	return MaxIssueDelay
}

// MaxArtifactResponseSize is the largest SOAP response body, in bytes, that
// the service provider reads from the IDP's ArtifactResolutionService when it
// resolves an artifact received with the HTTP-Artifact binding. A larger
// response is rejected without being parsed.
var MaxArtifactResponseSize int64 = 10 << 20

// DefaultValidDuration is how long we assert that the SP metadata is valid.
const DefaultValidDuration = time.Hour * 24 * 2

// DefaultCacheDuration is how long we ask the IDP to cache the SP metadata.
const DefaultCacheDuration = time.Hour * 24 * 1

// Metadata returns the service provider metadata
func (sp *ServiceProvider) Metadata() *EntityDescriptor {
	validDuration := DefaultValidDuration
	if sp.MetadataValidDuration > 0 {
		validDuration = sp.MetadataValidDuration
	}

	authnRequestsSigned := len(sp.SignatureMethod) > 0
	wantAssertionsSigned := true
	validUntil := sp.now().Add(validDuration)

	var entityValidUntil time.Time
	var roleValidUntil *time.Time
	var cacheDuration time.Duration
	if sp.MetadataOmitValidUntil {
		cacheDuration = DefaultCacheDuration
	} else {
		entityValidUntil = validUntil
		roleValidUntil = &validUntil
	}

	var keyDescriptors []KeyDescriptor
	// Metadata publishes only the SP's own certificate. Intermediates belong
	// in signatures' KeyInfo, not here: consumers treat each certificate in
	// a KeyDescriptor as a key the SP uses, and appending their DER to the
	// leaf's made the certificate unparseable.
	var certBytes []byte
	if sp.Certificate != nil {
		certBytes = sp.Certificate.Raw
	}

	// Advertise a key for encryption only if it is one the IdP can encrypt
	// to: XML encryption (key transport) requires an RSA key.
	var encryptionCertBytes []byte
	if sp.EncryptionCertificate != nil {
		encryptionCertBytes = sp.EncryptionCertificate.Raw
	} else if sp.Certificate != nil && !sp.KeyOnlySigns {
		if _, ok := sp.Certificate.PublicKey.(*rsa.PublicKey); ok {
			encryptionCertBytes = certBytes
		}
	}
	if encryptionCertBytes != nil {
		keyDescriptors = append(keyDescriptors, KeyDescriptor{
			Use: "encryption",
			KeyInfo: KeyInfo{
				X509Data: X509Data{
					X509Certificates: []X509Certificate{
						{Data: base64.StdEncoding.EncodeToString(encryptionCertBytes)},
					},
				},
			},
			// In order of preference. AES-GCM comes first: CBC has no
			// integrity check, so a sender of modified ciphertexts can learn
			// about the plaintext from whether it decrypts to valid XML. CBC
			// stays listed for IdPs that cannot use GCM.
			EncryptionMethods: []EncryptionMethod{
				{Algorithm: xmlenc.AES256GCM.Algorithm()},
				{Algorithm: xmlenc.AES128GCM.Algorithm()},
				{Algorithm: xmlenc.AES192GCM.Algorithm()},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
				{Algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep"},
			},
		})
	}

	if sp.Certificate != nil {
		if sp.signsMessages() {
			keyDescriptors = append(keyDescriptors, KeyDescriptor{
				Use: "signing",
				KeyInfo: KeyInfo{
					X509Data: X509Data{
						X509Certificates: []X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(certBytes)},
						},
					},
				},
			})
		}
	}

	sloEndpoints := make([]Endpoint, len(sp.LogoutBindings))
	for i, binding := range sp.LogoutBindings {
		sloEndpoints[i] = Endpoint{
			Binding:          binding,
			Location:         sp.SloURL.String(),
			ResponseLocation: sp.SloURL.String(),
		}
		if binding == SOAPBinding {
			// The SOAP binding is synchronous: the response goes back
			// over the requester's own connection, so a separate
			// ResponseLocation means nothing for it.
			sloEndpoints[i].ResponseLocation = ""
		}
	}

	acsBindings := sp.AssertionConsumerServiceBindings
	if len(acsBindings) == 0 {
		acsBindings = []string{HTTPPostBinding, HTTPArtifactBinding}
	}
	acsEndpoints := make([]IndexedEndpoint, len(acsBindings))
	for i, binding := range acsBindings {
		acsEndpoints[i] = IndexedEndpoint{
			Binding:  binding,
			Location: sp.AcsURL.String(),
			Index:    i + 1,
		}
	}

	return &EntityDescriptor{
		EntityID:      firstSet(sp.EntityID, sp.MetadataURL.String()),
		ValidUntil:    entityValidUntil,
		CacheDuration: cacheDuration,

		SPSSODescriptors: []SPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
						ValidUntil:                 roleValidUntil,
					},
					SingleLogoutServices: sloEndpoints,
					NameIDFormats:        []NameIDFormat{sp.metadataNameIDFormat()},
				},
				AuthnRequestsSigned:  &authnRequestsSigned,
				WantAssertionsSigned: &wantAssertionsSigned,

				AssertionConsumerServices: acsEndpoints,
			},
		},
	}
}

// MakeRedirectAuthenticationRequest creates a SAML authentication request using
// the HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the auth process.
func (sp *ServiceProvider) MakeRedirectAuthenticationRequest(relayState string) (*url.URL, error) {
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
	if err != nil {
		return nil, err
	}
	return req.Redirect(relayState, sp)
}

// Redirect returns a URL suitable for using the redirect binding with the request.
// If sp.SignatureMethod is set, the query string is signed as described in
// saml-bindings-2.0-os section 3.4.4.1. Any enveloped XML signature is omitted,
// as required by the HTTP-Redirect binding.
func (r *AuthnRequest) Redirect(relayState string, sp *ServiceProvider) (*url.URL, error) {
	if err := checkRelayState(sp.LimitRelayStateLength, relayState); err != nil {
		return nil, err
	}
	unsigned := *r
	unsigned.Signature = nil
	encoded, err := deflateAndEncode(unsigned.Element())
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(r.Destination, redirectParamSAMLRequest, encoded, relayState, sp.SignatureMethod)
}

// GetSSOBindingLocation returns URL for the IDP's Single Sign On Service binding
// of the specified type (HTTPRedirectBinding, HTTPPostBinding or
// HTTPPostSimpleSignBinding), or "" if there is none or IDPMetadata is nil.
func (sp *ServiceProvider) GetSSOBindingLocation(binding string) string {
	if sp.IDPMetadata == nil {
		return ""
	}
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, singleSignOnService := range idpSSODescriptor.SingleSignOnServices {
			if singleSignOnService.Binding == binding {
				return singleSignOnService.Location
			}
		}
	}
	return ""
}

// GetArtifactBindingLocation returns URL for the IDP's Artifact binding of the
// specified type, or "" if there is none or IDPMetadata is nil.
func (sp *ServiceProvider) GetArtifactBindingLocation(binding string) string {
	if sp.IDPMetadata == nil {
		return ""
	}
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		// The deprecated IDPSSODescriptor.ArtifactResolutionServices is
		// consulted first, so that a caller that changed it after parsing
		// the metadata gets what it set. The indexed endpoints are used when
		// it is empty, as it is when the descriptor was built in code with
		// only SSODescriptor.ArtifactResolutionServices.
		for _, artifactResolutionService := range idpSSODescriptor.ArtifactResolutionServices {
			if artifactResolutionService.Binding == binding {
				return artifactResolutionService.Location
			}
		}
		if len(idpSSODescriptor.ArtifactResolutionServices) > 0 {
			continue
		}
		for _, artifactResolutionService := range idpSSODescriptor.SSODescriptor.ArtifactResolutionServices {
			if artifactResolutionService.Binding == binding {
				return artifactResolutionService.Location
			}
		}
	}
	return ""
}

// GetSLOBindingLocation returns URL for the IDP's Single Log Out Service binding
// of the specified type (HTTPRedirectBinding or HTTPPostBinding), or "" if
// there is none or IDPMetadata is nil.
func (sp *ServiceProvider) GetSLOBindingLocation(binding string) string {
	if sp.IDPMetadata == nil {
		return ""
	}
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, singleLogoutService := range idpSSODescriptor.SingleLogoutServices {
			if singleLogoutService.Binding == binding {
				return singleLogoutService.Location
			}
		}
	}
	return ""
}

// getIDPSigningCerts returns the certificates which we can use to verify things
// signed by the IDP in PEM format, or nil if no such certificate is found.
func (sp *ServiceProvider) getIDPSigningCerts() ([]*x509.Certificate, error) {
	if err := sp.checkIDPMetadataNotExpired(); err != nil {
		return nil, err
	}
	for i := range sp.IDPMetadata.IDPSSODescriptors {
		if err := sp.checkRoleNotExpired(&sp.IDPMetadata.IDPSSODescriptors[i].RoleDescriptor, "IDPSSODescriptor"); err != nil {
			return nil, err
		}
	}
	var keyDescriptors []KeyDescriptor
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		keyDescriptors = append(keyDescriptors, idpSSODescriptor.KeyDescriptors...)
	}
	certs, err := signingCerts(keyDescriptors)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("cannot find any signing certificate in the IDP SSO descriptor")
	}
	return certs, nil
}

// checkIDPMetadataNotExpired returns an error matching ErrExpired if
// RejectExpiredIDPMetadata is set and the validUntil of the IDPMetadata
// EntityDescriptor has passed.
func (sp *ServiceProvider) checkIDPMetadataNotExpired() error {
	if !sp.RejectExpiredIDPMetadata || sp.IDPMetadata.ValidUntil.IsZero() {
		return nil
	}
	if now := sp.now(); !now.Before(sp.IDPMetadata.ValidUntil) {
		return classify(fmt.Errorf("IDP metadata expired at %s", sp.IDPMetadata.ValidUntil.UTC().Format(time.RFC3339)), ErrExpired)
	}
	return nil
}

// checkRoleNotExpired is checkIDPMetadataNotExpired for a role descriptor
// of the IDPMetadata, named kind.
func (sp *ServiceProvider) checkRoleNotExpired(role *RoleDescriptor, kind string) error {
	if !sp.RejectExpiredIDPMetadata || role.ValidUntil == nil || role.ValidUntil.IsZero() {
		return nil
	}
	if now := sp.now(); !now.Before(*role.ValidUntil) {
		return classify(fmt.Errorf("IDP metadata %s expired at %s", kind, role.ValidUntil.UTC().Format(time.RFC3339)), ErrExpired)
	}
	return nil
}

// signingCerts parses the certificates in keyDescriptors that may be used for
// signing, those whose "use" attribute is "signing" or missing. It returns
// nil if there are none.
func signingCerts(keyDescriptors []KeyDescriptor) ([]*x509.Certificate, error) {
	var certStrs []string
	for _, keyDescriptor := range keyDescriptors {
		switch keyDescriptor.Use {
		case "", "signing":
			for _, certificate := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
				certStrs = append(certStrs, certificate.Data)
			}
		}
	}
	if len(certStrs) == 0 {
		return nil, nil
	}

	certs := make([]*x509.Certificate, len(certStrs))

	// cleanup whitespace
	regex := regexp.MustCompile(`\s+`)
	for i, certStr := range certStrs {
		certStr = regex.ReplaceAllString(certStr, "")
		certBytes, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, classify(fmt.Errorf("cannot parse certificate: %w", err), ErrInvalidCertificate)
		}

		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, classify(err, ErrInvalidCertificate)
		}
		certs[i] = parsedCert
	}

	return certs, nil
}

func (sp *ServiceProvider) getCertBasedOnFingerprint(el *etree.Element) ([]*x509.Certificate, error) {
	x509CertEl := el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate")
	if x509CertEl == nil {
		return nil, fmt.Errorf("cannot validate signature on %s: no certificate present", el.Tag)
	}
	if len(x509CertEl.Child) != 1 {
		return nil, fmt.Errorf("cannot validate signature on %s: x509 cert el child len != 1: %d", el.Tag, len(x509CertEl.Child))
	}

	x509CertElCharData, ok := x509CertEl.Child[0].(*etree.CharData)
	if !ok {
		return nil, fmt.Errorf("cannot validate signature on %s: x509 cert el first child not char data: %T", el.Tag, x509CertEl.Child[0])
	}

	cert, err := parseCert(x509CertElCharData.Data)
	if err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
	}

	finP, err := fingerprint(cert, *sp.IDPCertificateFingerprintAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
	}

	if *sp.IDPCertificateFingerprint != finP {
		return nil, classify(fmt.Errorf("cannot validate signature on %s: fingerprint mismatch", el.Tag), ErrUntrustedCertificate)
	}

	return []*x509.Certificate{cert}, nil

}

func parseCert(x509Data string) (*x509.Certificate, error) {
	// cleanup whitespace
	regex := regexp.MustCompile(`\s+`)
	certStr := regex.ReplaceAllString(x509Data, "")
	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, classify(fmt.Errorf("parse cert, cannot base64 decode cert string: %w", err), ErrInvalidCertificate)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, classify(fmt.Errorf("parse cert, cannot parse certificate: %w", err), ErrInvalidCertificate)
	}

	return parsedCert, nil
}

func fingerprint(cert *x509.Certificate, fingerprintAlgorithm string) (string, error) {
	switch fingerprintAlgorithm {
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		fp := sha256.Sum256(cert.Raw)
		return fingerprintFormat(fp[:])
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		fp := sha512.Sum512(cert.Raw)
		return fingerprintFormat(fp[:])
	default:
		return "", fmt.Errorf("fingerprint, unknown algorithm: %s", fingerprintAlgorithm)
	}
}

func fingerprintFormat(fp []byte) (string, error) {
	var buf bytes.Buffer
	for i, f := range fp {
		if i > 0 {
			_, err := fmt.Fprintf(&buf, ":")
			if err != nil {
				return "", fmt.Errorf("fingerprint format, print ':': %w", err)
			}
		}
		_, err := fmt.Fprintf(&buf, "%02X", f)
		if err != nil {
			return "", fmt.Errorf("fingerprint format, print bytes: %w", err)
		}
	}
	return buf.String(), nil
}

// MakeArtifactResolveRequest produces a new ArtifactResolve object to send to the idp's Artifact resolver
func (sp *ServiceProvider) MakeArtifactResolveRequest(artifactID string) (*ArtifactResolve, error) {
	req := ArtifactResolve{
		ID:           fmt.Sprintf("id-%x", randomBytes(sp.randReader(), 20)),
		IssueInstant: sp.now(),
		Version:      "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(sp.EntityID, sp.MetadataURL.String()),
		},
		Artifact: artifactID,
	}

	if len(sp.SignatureMethod) > 0 {
		if err := sp.SignArtifactResolve(&req); err != nil {
			return nil, err
		}
	}

	return &req, nil
}

// MakeAuthenticationRequest produces a new AuthnRequest object to send to the idpURL
// that uses the specified binding (HTTPRedirectBinding or HTTPPostBinding)
func (sp *ServiceProvider) MakeAuthenticationRequest(idpURL string, binding string, resultBinding string) (*AuthnRequest, error) {

	allowCreate := true
	nameIDFormat := sp.nameIDFormat()
	req := AuthnRequest{
		AssertionConsumerServiceURL: sp.AcsURL.String(),
		Destination:                 idpURL,
		ProtocolBinding:             resultBinding, // default binding for the response
		ID:                          fmt.Sprintf("id-%x", randomBytes(sp.randReader(), 20)),
		IssueInstant:                sp.now(),
		Version:                     "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(sp.EntityID, sp.MetadataURL.String()),
		},
		NameIDPolicy: &NameIDPolicy{
			AllowCreate: &allowCreate,
			// TODO(ross): figure out exactly policy we need
			// urn:mace:shibboleth:1.0:nameIdentifier
			// urn:oasis:names:tc:SAML:2.0:nameid-format:transient
			Format: &nameIDFormat,
		},
		ForceAuthn:            sp.ForceAuthn,
		RequestedAuthnContext: sp.RequestedAuthnContext,
		Scoping:               sp.Scoping,
	}
	if sp.AcsIndex != nil {
		// AssertionConsumerServiceIndex is an xs:unsignedShort.
		if *sp.AcsIndex < 0 || *sp.AcsIndex > math.MaxUint16 {
			return nil, fmt.Errorf("AcsIndex %d is not between 0 and %d", *sp.AcsIndex, math.MaxUint16)
		}
		req.AssertionConsumerServiceIndex = strconv.Itoa(*sp.AcsIndex)
		req.AssertionConsumerServiceURL = ""
		req.ProtocolBinding = ""
	}
	// We don't need to sign the XML document if the IDP uses HTTP-Redirect binding
	if len(sp.SignatureMethod) > 0 && binding == HTTPPostBinding {
		if err := sp.SignAuthnRequest(&req); err != nil {
			return nil, err
		}
	}
	return &req, nil
}

// SignedMetadata returns the SP metadata as an XML element carrying an
// enveloped signature made with Key and Certificate (saml-metadata-2.0-os §3).
//
// It signs with SignatureMethod, or, when that is empty, with SHA-256 for the
// key type; signing metadata does not require request signing to be enabled.
// The signature references the EntityDescriptor by its ID attribute; one is
// generated if the metadata does not have one. The returned element must be
// serialized as-is: re-indenting it changes the signed content.
func (sp *ServiceProvider) SignedMetadata() (*etree.Element, error) {
	return sp.SignEntityDescriptor(sp.Metadata())
}

// SignEntityDescriptor returns ed as an XML element carrying an enveloped
// signature made with Key and Certificate, as SignedMetadata does for
// Metadata. Use it to sign SP metadata that has been changed after
// Metadata built it, such as with an Organization or ContactPersons. ed is
// not modified; the returned element must be serialized as-is.
func (sp *ServiceProvider) SignEntityDescriptor(ed *EntityDescriptor) (*etree.Element, error) {
	signatureMethod := sp.SignatureMethod
	if signatureMethod == "" && !signerutil.IsNil(sp.Key) {
		signatureMethod = defaultSignatureMethod(sp.Key.Public())
	}
	signingContext, err := sp.signingContext(signatureMethod)
	if err != nil {
		return nil, err
	}
	return signMetadata(ed, signingContext, sp.randReader())
}

// GetSigningContext returns a dsig.SigningContext initialized based on the Service Provider's configuration
func GetSigningContext(sp *ServiceProvider) (*dsig.SigningContext, error) {
	return sp.signingContext(sp.SignatureMethod)
}

// signsMessages reports whether the SP signs messages the IdP must verify
// with the certificate in the SP metadata, so that the metadata must publish
// it for signing: AuthnRequests (SignatureMethod), logout messages
// (LogoutSignatureMethod), and SOAP LogoutRequests and LogoutResponses,
// which are signed whenever Key is set.
//
// Attribute queries are also signed whenever Key is set, but advertising an
// AttributeService in IDPMetadata does not mean the SP queries it; an SP
// that sends attribute queries sets SignatureMethod or LogoutSignatureMethod
// to publish its signing certificate.
func (sp *ServiceProvider) signsMessages() bool {
	if sp.SignatureMethod != "" || sp.LogoutSignatureMethod != "" {
		return true
	}
	if signerutil.IsNil(sp.Key) {
		return false
	}
	for _, binding := range sp.LogoutBindings {
		if binding == SOAPBinding {
			return true
		}
	}
	return false
}

// logoutSignatureMethod returns the signature method for the logout
// messages the SP sends: LogoutSignatureMethod, or SignatureMethod if that
// is empty. An empty result means they are not signed.
func (sp *ServiceProvider) logoutSignatureMethod() string {
	if sp.LogoutSignatureMethod != "" {
		return sp.LogoutSignatureMethod
	}
	return sp.SignatureMethod
}

// signingContext returns a signing context for the SP's key and certificate
// that signs with signatureMethod.
func (sp *ServiceProvider) signingContext(signatureMethod string) (*dsig.SigningContext, error) {
	if signerutil.IsNil(sp.Key) {
		return nil, fmt.Errorf("signature method %s requires a non-nil private key", signatureMethod)
	}
	if sp.Certificate == nil {
		return nil, errors.New("cannot sign: ServiceProvider.Certificate is nil")
	}

	// The chain, leaf first, is placed in each signature's KeyInfo so that a
	// verifier can build a path from the SP certificate to a trusted root.
	keyPair := tls.Certificate{
		Certificate: [][]byte{sp.Certificate.Raw},
		PrivateKey:  sp.Key,
		Leaf:        sp.Certificate,
	}
	for _, cert := range sp.Intermediates {
		keyPair.Certificate = append(keyPair.Certificate, cert.Raw)
	}

	// Validate that the key type matches the signature method.
	// We check the public key type to support crypto.Signer implementations
	// (like KMS/HSM signers) that aren't literal *rsa.PrivateKey or *ecdsa.PrivateKey.
	pubKey := sp.Key.Public()
	switch signatureMethod {
	case dsig.RSASHA1SignatureMethod,
		dsig.RSASHA256SignatureMethod,
		dsig.RSASHA384SignatureMethod,
		dsig.RSASHA512SignatureMethod:
		if _, ok := pubKey.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("signature method %s requires an RSA key, got %T", signatureMethod, pubKey)
		}

	case dsig.ECDSASHA1SignatureMethod,
		dsig.ECDSASHA256SignatureMethod,
		dsig.ECDSASHA384SignatureMethod,
		dsig.ECDSASHA512SignatureMethod:
		if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("signature method %s requires an ECDSA key, got %T", signatureMethod, pubKey)
		}
	default:
		return nil, fmt.Errorf("invalid signing method %s", signatureMethod)
	}

	keyStore := dsig.TLSCertKeyStore(keyPair)
	chain, err := keyStore.GetChain()
	if err != nil {
		return nil, err
	}
	signingContext, err := dsig.NewSigningContext(sp.Key, chain)
	if err != nil {
		return nil, err
	}
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(canonicalizerPrefixList)
	if err := signingContext.SetSignatureMethod(signatureMethod); err != nil {
		return nil, err
	}

	return signingContext, nil
}

// SignArtifactResolve adds the `Signature` element to the `ArtifactResolve`.
func (sp *ServiceProvider) SignArtifactResolve(req *ArtifactResolve) error {
	signingContext, err := GetSigningContext(sp)
	if err != nil {
		return err
	}
	assertionEl := req.Element()

	signedRequestEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return err
	}

	sigEl := signedRequestEl.Child[len(signedRequestEl.Child)-1]
	req.Signature = sigEl.(*etree.Element)
	return nil
}

// SignAuthnRequest adds the `Signature` element to the `AuthnRequest`.
func (sp *ServiceProvider) SignAuthnRequest(req *AuthnRequest) error {

	signingContext, err := GetSigningContext(sp)
	if err != nil {
		return err
	}
	assertionEl := req.Element()

	signedRequestEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return err
	}

	sigEl := signedRequestEl.Child[len(signedRequestEl.Child)-1]
	req.Signature = sigEl.(*etree.Element)
	return nil
}

// MakePostAuthenticationRequest creates a SAML authentication request using
// the HTTP-POST binding. It returns HTML text representing an HTML form that
// can be sent presented to a browser to initiate the login process.
func (sp *ServiceProvider) MakePostAuthenticationRequest(relayState string) ([]byte, error) {
	if err := checkRelayState(sp.LimitRelayStateLength, relayState); err != nil {
		return nil, err
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPPostBinding), HTTPPostBinding, HTTPPostBinding)
	if err != nil {
		return nil, err
	}
	return req.Post(relayState), nil
}

// Post returns an HTML form suitable for using the HTTP-POST binding with the request
func (r *AuthnRequest) Post(relayState string) []byte {
	return r.PostWithNonce(relayState, "")
}

// PostWithNonce is like Post, but if nonce is not empty it is set as the
// nonce attribute of the form's auto-submit <script> element, so that the
// form can be served under a Content-Security-Policy that allows scripts by
// nonce.
func (r *AuthnRequest) PostWithNonce(relayState, nonce string) []byte {
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())
	reqBuf, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	encodedReqBuf := base64.StdEncoding.EncodeToString(reqBuf)

	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<form method="post" action="{{.URL}}" id="SAMLRequestForm">` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script{{with .Nonce}} nonce="{{.}}"{{end}}>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLRequestForm').submit();</script>`))
	data := struct {
		URL         string
		SAMLRequest string
		RelayState  string
		Nonce       string
	}{
		URL:         r.Destination,
		SAMLRequest: encodedReqBuf,
		RelayState:  relayState,
		Nonce:       nonce,
	}

	rv := bytes.Buffer{}
	if err := tmpl.Execute(&rv, data); err != nil {
		panic(err)
	}

	return rv.Bytes()
}

// AssertionAttributes is a list of AssertionAttribute
type AssertionAttributes []AssertionAttribute

// Get returns the assertion attribute whose Name or FriendlyName
// matches name, or nil if no matching attribute is found.
//
// FriendlyName "MUST NOT be used as a basis for formally identifying SAML
// attributes" (saml-core §2.7.3.1): an attribute's FriendlyName can equal
// another attribute's Name.
//
// Deprecated: Get can return an attribute whose FriendlyName equals the
// Name asked for, in place of the attribute with that Name. Use GetByName.
func (aa AssertionAttributes) Get(name string) *AssertionAttribute {
	for _, attr := range aa {
		if attr.Name == name {
			return &attr
		}
		if attr.FriendlyName == name {
			return &attr
		}
	}
	return nil
}

// GetByName returns the assertion attribute whose Name is name, or nil if
// there is none. Unlike Get, it never matches a FriendlyName.
func (aa AssertionAttributes) GetByName(name string) *AssertionAttribute {
	for _, attr := range aa {
		if attr.Name == name {
			return &attr
		}
	}
	return nil
}

// AssertionAttribute represents an attribute of the user extracted from
// a SAML Assertion.
type AssertionAttribute struct {
	FriendlyName string
	Name         string
	Value        string
}

// InvalidResponseError is the error produced by ParseResponse when it fails.
// The underlying error is in PrivateErr. Response is the response as it was
// known at the time validation failed. Now is the time that was used to validate
// time-dependent parts of the assertion.
type InvalidResponseError struct {
	PrivateErr error
	Response   string
	Now        time.Time
}

func (ivr *InvalidResponseError) Error() string {
	return "Authentication failed"
}

// ErrBadStatus is returned when the assertion provided is valid but the
// status code is not "urn:oasis:names:tc:SAML:2.0:status:Success".
type ErrBadStatus struct {
	// Status is the top-level status code, such as StatusResponder.
	Status string

	// SubStatus is the second-level status code, if any, which says more
	// (saml-core §3.2.2.2): for example StatusNoPassive under
	// StatusResponder.
	SubStatus string

	// Message is the StatusMessage, if any.
	Message string
}

// newErrBadStatus returns the ErrBadStatus that reports status.
func newErrBadStatus(status Status) ErrBadStatus {
	e := ErrBadStatus{Status: status.StatusCode.Value}
	if second := status.StatusCode.StatusCode; second != nil {
		e.SubStatus = second.Value
	}
	if status.StatusMessage != nil {
		e.Message = status.StatusMessage.Value
	}
	return e
}

func (e ErrBadStatus) Error() string {
	s := e.Status
	if e.SubStatus != "" {
		s += " (" + e.SubStatus + ")"
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Is reports whether target is an ErrBadStatus with the same Status, and
// with the same SubStatus and Message unless target leaves them empty, so
// that errors.Is(err, ErrBadStatus{Status: StatusResponder}) matches any
// Responder status.
func (e ErrBadStatus) Is(target error) bool {
	t, ok := target.(ErrBadStatus)
	return ok && t.Status == e.Status &&
		(t.SubStatus == "" || t.SubStatus == e.SubStatus) &&
		(t.Message == "" || t.Message == e.Message)
}

// ParseResponse extracts the SAML IDP response received in req, resolves
// artifacts when necessary, validates it, and returns the verified assertion.
// req.ParseForm must have been called.
//
// A posted form that carries a SigAlg or Signature field is an
// HTTP-POST-SimpleSign message (sstc-saml-binding-simplesign-cs-01 section
// 2.10). Its SimpleSign signature must then be valid, or the response is
// rejected; it is never accepted on the strength of XML signatures alone. A
// valid SimpleSign signature authenticates the whole Response, so the
// assertions need not be signed, and the Response must carry a Destination.
// An enveloped XML signature on the Response is still checked when present.
// Every other check (Destination, InResponseTo, Issuer, Status, assertion
// conditions, decryption, ReplayCache) applies as for HTTP-POST. A form
// without SigAlg and Signature is handled as HTTP-POST, as before.
func (sp *ServiceProvider) ParseResponse(req *http.Request, possibleRequestIDs []string) (*Assertion, error) {
	if artifactID := req.Form.Get("SAMLart"); artifactID != "" {
		return sp.handleArtifactRequest(req.Context(), artifactID, possibleRequestIDs)
	}
	return sp.parseResponseHTTP(req, possibleRequestIDs)
}

func (sp *ServiceProvider) handleArtifactRequest(ctx context.Context, artifactID string, possibleRequestIDs []string) (*Assertion, error) {
	retErr := &InvalidResponseError{Now: sp.now()}

	artifact, err := sp.checkArtifact(artifactID)
	if err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("invalid artifact: %w", err), ErrArtifactResolution)
		return nil, retErr
	}
	artifactResolveRequest, err := sp.MakeArtifactResolveRequest(artifactID)
	if err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("cannot generate artifact resolution request: %w", err), ErrArtifactResolution)
		return nil, retErr
	}

	requestBody, err := elementToBytes(artifactResolveRequest.SoapRequest())
	if err != nil {
		retErr.PrivateErr = classify(err, ErrArtifactResolution)
		return nil, retErr
	}

	location := sp.artifactResolutionLocation(artifact)
	if err := checkSOAPEndpoint(location, sp.AllowInsecureSOAPEndpoints); err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("cannot resolve artifact: %w", err), ErrArtifactResolution)
		return nil, retErr
	}
	req, err := http.NewRequestWithContext(ctx, "POST", location, bytes.NewReader(requestBody))
	if err != nil {
		retErr.PrivateErr = classify(err, ErrArtifactResolution)
		return nil, retErr
	}
	// The SOAP binding over HTTP requires a SOAPAction header
	// (saml-bindings-2.0-os §3.2.3, SOAP 1.1 §6.1.1).
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("SOAPAction", soapActionSAML)
	setNoCacheHeaders(req.Header)

	httpClient := soapHTTPClient(sp.HTTPClient, sp.AllowInsecureSOAPEndpoints)
	response, err := httpClient.Do(req) //nolint:gosec // G704: the URL is the IdP's ArtifactResolutionService from its metadata, not from the request
	if err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("cannot resolve artifact: %w", err), ErrArtifactResolution)
		return nil, retErr
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			logger.DefaultLogger.Printf("Error while closing response body during artifact resolution: %v", err)
		}
	}()
	if response.StatusCode != 200 {
		retErr.PrivateErr = classify(fmt.Errorf("Error during artifact resolution: HTTP status %d (%s)", response.StatusCode, response.Status), ErrArtifactResolution)
		return nil, retErr
	}
	limit := MaxArtifactResponseSize
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("Error during artifact resolution: %w", err), ErrArtifactResolution)
		return nil, retErr
	}
	if int64(len(responseBody)) > limit {
		retErr.PrivateErr = classify(fmt.Errorf("Error during artifact resolution: response body is larger than %d bytes", limit), ErrArtifactResolution)
		return nil, retErr
	}
	// The Response inside the ArtifactResponse was delivered, by reference,
	// to the ACS, so its Destination is checked against AcsURL. req.URL is
	// the IdP's ArtifactResolutionService, which a Response for this SP
	// must never name.
	assertion, err := sp.ParseXMLArtifactResponse(responseBody, possibleRequestIDs, artifactResolveRequest.ID, sp.AcsURL)
	if err != nil {
		return nil, err
	}
	// The artifact is recorded only now that the IdP has resolved it to a
	// verified Response, so that a SAMLart the IdP never issued leaves no
	// record. A second resolution of the same artifact, even concurrent
	// with this one, is still refused: by the IdP, which returns the message
	// only once (saml-bindings-2.0-os §3.6.5.2), by the ReplayCache record
	// of the assertion, and by this record.
	if err := sp.consumeArtifact(artifactID, artifact); err != nil {
		retErr.PrivateErr = classify(err, ErrArtifactResolution)
		return nil, retErr
	}
	return assertion, nil
}

func (sp *ServiceProvider) parseResponseHTTP(req *http.Request, possibleRequestIDs []string) (*Assertion, error) {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	simpleSign, err := parseSimpleSignRequest(req, redirectParamSAMLResponse)
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if simpleSign != nil {
		return sp.parseSimpleSignResponse(simpleSign, possibleRequestIDs, *req.URL)
	}

	rawResponseBuf, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("cannot parse base64: %w", err), ErrMalformedMessage)
		return nil, retErr
	}

	assertion, err := sp.ParseXMLResponse(rawResponseBuf, possibleRequestIDs, *req.URL)
	if err != nil {
		return nil, err
	}
	return assertion, nil
}

// ParseXMLArtifactResponse validates the SAML Artifact resolver response
// and returns the verified assertion.
//
// This function handles verifying the digital signature, and verifying
// that the specified conditions and properties are met.
//
// If the function fails it will return an InvalidResponseError whose
// properties are useful in describing which part of the parsing process
// failed. However, to discourage inadvertent disclosure the diagnostic
// information, the Error() method returns a static string.
func (sp *ServiceProvider) ParseXMLArtifactResponse(soapResponseXML []byte, possibleRequestIDs []string, artifactRequestID string, currentURL url.URL) (*Assertion, error) {
	now := sp.now()
	retErr := &InvalidResponseError{
		Response: string(soapResponseXML),
		Now:      now,
	}

	// ensure that the response XML is well-formed before we parse it
	if err := xmlroundtrip.Validate(soapResponseXML); err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("invalid xml: %w", err), ErrMalformedMessage)
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(soapResponseXML); err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("cannot unmarshal response: %w", err), ErrMalformedMessage)
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = classify(errors.New("invalid xml: no root"), ErrMalformedMessage)
		return nil, retErr
	}
	if doc.Root().NamespaceURI() != "http://schemas.xmlsoap.org/soap/envelope/" ||
		doc.Root().Tag != "Envelope" {
		retErr.PrivateErr = classify(fmt.Errorf("expected a SOAP Envelope"), ErrMalformedMessage)
		return nil, retErr
	}

	soapBodyEl, err := findOneChild(doc.Root(), "http://schemas.xmlsoap.org/soap/envelope/", "Body")
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	artifactResponseEl, err := findOneChild(soapBodyEl, "urn:oasis:names:tc:SAML:2.0:protocol", "ArtifactResponse")
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	return sp.parseArtifactResponse(artifactResponseEl, possibleRequestIDs, artifactRequestID, now, currentURL)
}

func (sp *ServiceProvider) parseArtifactResponse(artifactResponseEl *etree.Element, possibleRequestIDs []string, artifactRequestID string, now time.Time, currentURL url.URL) (*Assertion, error) {
	retErr := &InvalidResponseError{
		Now:      now,
		Response: elementToString(artifactResponseEl),
	}

	{
		var artifactResponse ArtifactResponse
		if err := unmarshalElement(artifactResponseEl, &artifactResponse); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
		if err := checkVersion("ArtifactResponse", artifactResponse.Version); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
		if artifactResponse.InResponseTo != artifactRequestID {
			retErr.PrivateErr = classify(fmt.Errorf("`InResponseTo` does not match the artifact request ID (expected %s)", artifactRequestID), ErrRequestIDMismatch)
			return nil, retErr
		}
		if err := sp.limits().checkIssueInstant("response IssueInstant", artifactResponse.IssueInstant, now); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
		if artifactResponse.Issuer != nil && artifactResponse.Issuer.Value != sp.IDPMetadata.EntityID {
			retErr.PrivateErr = classify(fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
			return nil, retErr
		}
		if artifactResponse.Status.StatusCode.Value != StatusSuccess {
			retErr.PrivateErr = newErrBadStatus(artifactResponse.Status)
			return nil, retErr
		}
	}

	var signatureRequirement signatureRequirement
	receivedArtifactResponseEl := artifactResponseEl
	signedArtifactResponseEl, sigErr := sp.validatedElement(artifactResponseEl)
	switch sigErr {
	case nil:
		signatureRequirement = signatureNotRequired
		// Take the Response from what the signature covers.
		artifactResponseEl = signedArtifactResponseEl
	case errSignatureElementNotPresent:
		signatureRequirement = signatureRequired
	default:
		retErr.PrivateErr = sigErr
		return nil, retErr
	}

	if _, err := findOneChild(artifactResponseEl, "urn:oasis:names:tc:SAML:2.0:protocol", "Response"); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	// The Response's own signature, if any, is checked on the Response as
	// received.
	responseEls, receivedResponseEls, err := receivedChildren(artifactResponseEl, receivedArtifactResponseEl, "urn:oasis:names:tc:SAML:2.0:protocol", "Response")
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	assertion, err := sp.parseReceivedResponse(responseEls[0], receivedResponseEls[0], possibleRequestIDs, now, signatureRequirement, currentURL)
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	return assertion, nil
}

// ParseXMLResponse parses and validates the SAML IDP response and
// returns the verified assertion.
//
// This function handles decrypting the message, verifying the digital
// signature on the assertion, and verifying that the specified conditions
// and properties are met. A Subject identified by an EncryptedID is given
// the NameID it holds, decrypted like an EncryptedAssertion.
//
// If the function fails it will return an InvalidResponseError whose
// properties are useful in describing which part of the parsing process
// failed. However, to discourage inadvertent disclosure the diagnostic
// information, the Error() method returns a static string.
func (sp *ServiceProvider) ParseXMLResponse(decodedResponseXML []byte, possibleRequestIDs []string, currentURL url.URL) (*Assertion, error) {
	return sp.parseXMLResponse(decodedResponseXML, possibleRequestIDs, currentURL, signatureRequired)
}

// parseSimpleSignResponse validates a Response received at the ACS with the
// HTTP-POST-SimpleSign binding. The SimpleSign signature is checked before
// anything else. A valid one authenticates the whole Response, as a valid
// XML signature on the Response element does, so the assertions need no
// signature of their own; everything else is validated as for HTTP-POST.
func (sp *ServiceProvider) parseSimpleSignResponse(m *simpleSignMessage, possibleRequestIDs []string, currentURL url.URL) (*Assertion, error) {
	if err := sp.verifySimpleSignSignature(m); err != nil {
		return nil, &InvalidResponseError{
			Now:        sp.now(),
			Response:   string(m.XML),
			PrivateErr: err,
		}
	}
	return sp.parseXMLResponse(m.XML, possibleRequestIDs, currentURL, signatureVerifiedByBinding)
}

// parseXMLResponse is ParseXMLResponse with the signature requirement for
// the Response element given by signatureRequirement.
func (sp *ServiceProvider) parseXMLResponse(decodedResponseXML []byte, possibleRequestIDs []string, currentURL url.URL, signatureRequirement signatureRequirement) (*Assertion, error) {
	now := sp.now()
	var err error
	retErr := &InvalidResponseError{
		Now:      now,
		Response: string(decodedResponseXML),
	}

	// ensure that the response XML is well-formed before we parse it
	if err := xmlroundtrip.Validate(decodedResponseXML); err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("invalid xml: %w", err), ErrMalformedMessage)
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(decodedResponseXML); err != nil {
		retErr.PrivateErr = classify(err, ErrMalformedMessage)
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = classify(errors.New("invalid xml: no root"), ErrMalformedMessage)
		return nil, retErr
	}

	assertion, err := sp.parseResponse(doc.Root(), possibleRequestIDs, now, signatureRequirement, currentURL)
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	return assertion, nil
}

type signatureRequirement int

const (
	signatureRequired signatureRequirement = iota
	signatureNotRequired

	// signatureVerifiedByBinding means the binding (HTTP-POST-SimpleSign)
	// has already authenticated the whole Response with a detached
	// signature. The Response then counts as signed: its Destination is
	// required, an enveloped XML signature it carries must still be valid,
	// and the assertions need no signature of their own.
	signatureVerifiedByBinding
)

// validateXMLResponse validates the SAML IDP response and returns
// the verified assertion.
//
// This function handles decrypting the message, verifying the digital
// signature on the assertion, and verifying that the specified conditions
// and properties are met.
func (sp *ServiceProvider) parseResponse(responseEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement, currentURL url.URL) (*Assertion, error) {
	return sp.parseReceivedResponse(responseEl, responseEl, possibleRequestIDs, now, signatureRequirement, currentURL)
}

// parseReceivedResponse is parseResponse, where receivedEl is responseEl as
// received: responseEl itself, or, inside a signed ArtifactResponse, its
// counterpart in the ArtifactResponse as received (see receivedChildren).
// Its signature, and those of its assertions, are checked there.
// checkResponseSignature checks the signature of the Response responseEl
// (received as receivedEl) as signatureRequirement asks, and returns the
// element to read the Response from (what its signature covers, if it is
// signed), whether the Response is signed (or vouched for by the binding),
// and the requirement left for its assertions.
func (sp *ServiceProvider) checkResponseSignature(responseEl, receivedEl *etree.Element, signatureRequirement signatureRequirement) (*etree.Element, bool, signatureRequirement, error) {
	var responseSignatureErr error
	var responseHasSignature bool
	switch signatureRequirement {
	case signatureRequired:
		var signed *etree.Element
		signed, responseSignatureErr = sp.validatedElement(responseEl)
		switch responseSignatureErr {
		case nil:
			responseHasSignature = true
			// Read the Response, and the assertions in it, from what the
			// signature covers.
			responseEl = signed
		case errSignatureElementNotPresent:
			// the Response is not signed, so each Assertion must be (checked below)
		default:
			// A Signature is present but invalid: reject the Response before
			// looking at any of its other contents.
			return nil, false, signatureRequirement, responseSignatureErr
		}
	case signatureVerifiedByBinding:
		responseHasSignature = true
		if err := sp.validateSignature(responseEl); err != nil && err != errSignatureElementNotPresent {
			return nil, false, signatureRequirement, err
		}
		signatureRequirement = signatureNotRequired
	case signatureNotRequired:
		// The enclosing ArtifactResponse is signed, but a signature the
		// Response carries must still be valid.
		signed, err := sp.validatedElement(receivedEl)
		switch err {
		case nil:
			responseEl = signed
		case errSignatureElementNotPresent:
		default:
			return nil, false, signatureRequirement, err
		}
	}
	return responseEl, responseHasSignature, signatureRequirement, nil
}

func (sp *ServiceProvider) parseReceivedResponse(responseEl, receivedEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement, currentURL url.URL) (*Assertion, error) {
	responseEl, responseHasSignature, signatureRequirement, err := sp.checkResponseSignature(responseEl, receivedEl, signatureRequirement)
	if err != nil {
		return nil, err
	}

	// assertionRequestIDs are the request IDs an assertion may answer.
	assertionRequestIDs := possibleRequestIDs

	// validate request attributes
	{
		var response Response
		if err := unmarshalElement(responseEl, &response); err != nil {
			return nil, classify(fmt.Errorf("cannot unmarshal response: %w", err), ErrMalformedMessage)
		}
		if err := checkVersion("response", response.Version); err != nil {
			return nil, err
		}

		// If the response is *not* signed, the Destination may be omitted.
		if responseHasSignature || response.Destination != "" {
			// Per section 3.4.5.2 of the SAML spec, Destination must match the location at which the response was received, i.e. currentURL.
			// Historically, we checked against the SP's ACS URL instead of currentURL, which is usually the same but may differ in query params.
			// To mitigate the risk of switching to comparing against currentURL, we still allow it if the ACS URL matches, even if the current URL doesn't.
			if response.Destination != currentURL.String() && response.Destination != sp.AcsURL.String() {
				return nil, classify(fmt.Errorf("`Destination` does not match requested URL or AcsURL (destination %q, requested %q, acs %q)", response.Destination, currentURL.String(), sp.AcsURL.String()), ErrDestinationMismatch)
			}
		}

		if err := sp.validateRequestID(response, possibleRequestIDs); err != nil {
			return nil, err
		}
		// A Response to an AuthnRequest carries assertions issued for that
		// same request (saml-profiles §4.1.4.2), so an assertion issued for
		// another pending request cannot be rewrapped in it. An assertion
		// without InResponseTo is still accepted with AllowIDPInitiated:
		// it would be accepted on its own anyway.
		if response.InResponseTo != "" {
			assertionRequestIDs = []string{response.InResponseTo}
		}

		if err := sp.limits().checkIssueInstant("response IssueInstant", response.IssueInstant, now); err != nil {
			return nil, err
		}
		if response.Issuer != nil && response.Issuer.Value != sp.IDPMetadata.EntityID {
			return nil, classify(fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
		}
		if response.Status.StatusCode.Value != StatusSuccess {
			return nil, newErrBadStatus(response.Status)
		}
	}

	if responseHasSignature {
		// since the Response has a valid signature, none of the Assertions need one
		signatureRequirement = signatureNotRequired
	}

	encryptedAssertionEls, err := findChildren(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion")
	if err != nil {
		return nil, err
	}
	assertionEls, receivedAssertionEls, err := receivedChildren(responseEl, receivedEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
	if err != nil {
		return nil, err
	}

	// Nothing has authenticated an unsigned Response, so each of its
	// assertions must be decrypted and its signature checked, which costs
	// more for each one and more again for each namespace declaration in
	// scope. A Response carries one assertion in practice (and only the
	// first is returned), and other SAML libraries refuse an unsigned
	// Response with more than one, so refuse it before doing any of that.
	if signatureRequirement == signatureRequired {
		if n := len(encryptedAssertionEls) + len(assertionEls); n > 1 {
			return nil, classify(fmt.Errorf("an unsigned Response must contain exactly one Assertion or EncryptedAssertion, not %d", n), ErrMalformedMessage)
		}
	}

	var errs []error
	var assertions []Assertion

	// look for encrypted assertions
	{
		for _, encryptedAssertionEl := range encryptedAssertionEls {
			assertion, err := sp.parseEncryptedAssertion(encryptedAssertionEl, assertionRequestIDs, now, signatureRequirement)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			assertions = append(assertions, *assertion)
		}
	}

	// look for plaintext assertions
	{
		for i, assertionEl := range assertionEls {
			assertion, err := sp.parseReceivedAssertion(assertionEl, receivedAssertionEls[i], assertionRequestIDs, now, signatureRequirement)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			assertions = append(assertions, *assertion)
		}
	}

	if len(assertions) == 0 {
		if len(errs) > 0 {
			return nil, errs[0]
		}
		return nil, classify(fmt.Errorf("expected at least one valid Assertion, none found"), ErrMissingElement)
	}

	// if we have at least one assertion, return the first one. It is almost universally true that valid responses
	// contain only one assertion. This is less that fully correct, but we didn't realize that there could be more
	// than one assertion at the time of establishing the public interface of ParseXMLResponse(), so for compatibility
	// we return the first one.
	if err := sp.consumeAssertion(&assertions[0]); err != nil {
		return nil, err
	}
	return &assertions[0], nil
}

func (sp *ServiceProvider) validateRequestID(response Response, possibleRequestIDs []string) error {
	if sp.ValidateRequestID != nil {
		return sp.ValidateRequestID(response, possibleRequestIDs)
	}

	requestIDvalid := false

	// With AllowIDPInitiated set, an empty InResponseTo is an unsolicited
	// response and is accepted. A non-empty one names an SP-initiated
	// request and must match, so that a response issued for one login
	// cannot be replayed as an IdP-initiated one. IdPs that send a
	// non-empty InResponseTo on IdP-initiated responses (e.g. Rippling)
	// need a ValidateRequestID hook.
	if sp.AllowIDPInitiated && response.InResponseTo == "" {
		requestIDvalid = true
	} else {
		// An empty entry of possibleRequestIDs never matches: it would
		// accept an unsolicited response without AllowIDPInitiated.
		for _, possibleRequestID := range possibleRequestIDs {
			if possibleRequestID != "" && response.InResponseTo == possibleRequestID {
				requestIDvalid = true
			}
		}
	}
	if !requestIDvalid {
		return classify(fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs), ErrRequestIDMismatch)
	}
	return nil
}

// cbcAlgorithms are the XML Encryption block ciphers in CBC mode, which do
// not authenticate the ciphertext.
var cbcAlgorithms = map[string]bool{
	xmlenc.AES128CBC.Algorithm(): true,
	xmlenc.AES192CBC.Algorithm(): true,
	xmlenc.AES256CBC.Algorithm(): true,
	xmlenc.TripleDES.Algorithm(): true,
}

// checkCBCIntegrity implements RequireSignedResponseForCBC: it refuses
// encryptedEl, an EncryptedAssertion, if one of its EncryptedData children
// is encrypted with a CBC block cipher and responseAuthenticated is false,
// that is, nothing authenticated the message carrying it before decryption.
// It only reads the EncryptionMethod, so nothing is decrypted.
func (sp *ServiceProvider) checkCBCIntegrity(encryptedEl *etree.Element, responseAuthenticated bool) error {
	if !sp.RequireSignedResponseForCBC || responseAuthenticated {
		return nil
	}
	for _, encryptedDataEl := range encryptedEl.ChildElements() {
		if encryptedDataEl.Tag != "EncryptedData" {
			continue
		}
		for _, methodEl := range encryptedDataEl.ChildElements() {
			if methodEl.Tag != "EncryptionMethod" {
				continue
			}
			if algorithm := methodEl.SelectAttrValue("Algorithm", ""); cbcAlgorithms[algorithm] {
				return classify(fmt.Errorf("the Response is not signed, and RequireSignedResponseForCBC refuses to decrypt an EncryptedAssertion encrypted with %s", algorithm), ErrInvalidSignature)
			}
		}
	}
	return nil
}

func (sp *ServiceProvider) parseEncryptedAssertion(encryptedAssertionEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement) (*Assertion, error) {
	if err := sp.checkCBCIntegrity(encryptedAssertionEl, signatureRequirement != signatureRequired); err != nil {
		return nil, err
	}
	assertionEl, err := sp.decryptElement(encryptedAssertionEl)
	if err != nil {
		return nil, classify(fmt.Errorf("failed to decrypt EncryptedAssertion: %w", err), ErrDecryptionFailed)
	}
	return sp.parseAssertion(assertionEl, possibleRequestIDs, now, signatureRequirement)
}

func (sp *ServiceProvider) decryptElement(encryptedEl *etree.Element) (*etree.Element, error) {
	keys := make([]namedDecryptionKey, 0, 1+len(sp.DecryptionKeys))
	if sp.EncryptionKey != nil {
		keys = append(keys, namedDecryptionKey{"EncryptionKey", sp.EncryptionKey})
	} else if !sp.KeyOnlySigns {
		keys = append(keys, namedDecryptionKey{"Key", sp.Key})
	}
	for i, k := range sp.DecryptionKeys {
		keys = append(keys, namedDecryptionKey{fmt.Sprintf("DecryptionKeys[%d]", i), k})
	}
	return decryptWithKeys(encryptedEl, keys, sp.entityID())
}

// parsePlaintext parses the plaintext of a decrypted element and returns its
// root element.
func parsePlaintext(plaintextEl []byte) (*etree.Element, error) {
	// Whether a modified ciphertext decrypts to well-formed XML is what the
	// attacks on XML Encryption in CBC mode (Jager and Somorovsky, 2011)
	// learn from, so plaintext that is not a well-formed element gets the
	// same error as a ciphertext with bad padding, without detail.
	if err := xmlroundtrip.Validate(plaintextEl); err != nil {
		return nil, xmlenc.ErrDecryptionFailed
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plaintextEl); err != nil {
		return nil, xmlenc.ErrDecryptionFailed
	}
	if doc.Root() == nil {
		return nil, xmlenc.ErrDecryptionFailed
	}
	return doc.Root(), nil
}

// decryptWithKey decrypts encryptedDataEl, the EncryptedData child of
// encryptedEl, with decryptionKey. If encryptedKeyEl is not nil, it is an
// EncryptedKey, beside the EncryptedData or inside its KeyInfo, that holds
// the content key wrapped with decryptionKey.
func decryptWithKey(decryptionKey interface{}, encryptedEl, encryptedKeyEl, encryptedDataEl *etree.Element) ([]byte, error) {
	if encryptedKeyEl == nil {
		return xmlenc.Decrypt(decryptionKey, encryptedDataEl)
	}
	key, err := xmlenc.Decrypt(decryptionKey, encryptedKeyEl)
	if err != nil {
		if encryptedKeyEl.Parent() == encryptedEl {
			return nil, classify(fmt.Errorf("failed to decrypt key from response: %w", err), ErrDecryptionFailed)
		}
		return nil, err
	}
	// The block ciphers unwrap an EncryptedKey in KeyInfo themselves, so
	// hand them the EncryptedData without one, now that the key is known.
	if encryptedDataEl.FindElement("./KeyInfo/EncryptedKey") != nil {
		encryptedDataEl = encryptedDataEl.Copy()
		for _, el := range encryptedDataEl.FindElements("./KeyInfo/EncryptedKey") {
			el.Parent().RemoveChild(el)
		}
	}
	return xmlenc.Decrypt(key, encryptedDataEl)
}

func (sp *ServiceProvider) parseAssertion(assertionEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement) (*Assertion, error) {
	return sp.parseReceivedAssertion(assertionEl, assertionEl, possibleRequestIDs, now, signatureRequirement)
}

// parseReceivedAssertion is parseAssertion, where receivedEl is the
// assertion as received (see receivedChildren), on which its signature is
// checked.
func (sp *ServiceProvider) parseReceivedAssertion(assertionEl, receivedEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement) (*Assertion, error) {
	// A signature that is present must be valid even when the enclosing
	// Response is signed (saml-core §2.3.3, saml-profiles §4.1.4.3); only
	// its absence is allowed then.
	signed, sigErr := sp.validatedElement(receivedEl)
	switch {
	case sigErr == nil:
		// Read the assertion from what the signature covers.
		assertionEl = signed
	case sigErr == errSignatureElementNotPresent && signatureRequirement != signatureRequired:
	default:
		return nil, sigErr
	}

	// parse the assertion we just validated
	var assertion Assertion
	if err := unmarshalElement(assertionEl, &assertion); err != nil {
		return nil, err
	}
	if err := fillAttributeValuesXML(assertionEl, &assertion); err != nil {
		return nil, err
	}
	if err := sp.decryptEncryptedIDs(assertion.Subject); err != nil {
		return nil, err
	}
	if err := sp.decryptEncryptedAttributes(assertionEl, &assertion); err != nil {
		return nil, err
	}

	if err := sp.validateAssertion(&assertion, possibleRequestIDs, now); err != nil {
		return nil, err
	}

	return &assertion, nil
}

// decryptEncryptedIDs sets the NameID of subject, and of each of its
// SubjectConfirmations, that is given as an EncryptedID (saml-core §2.2.4)
// to the NameID the EncryptedID holds, decrypted with the SP's decryption
// keys. If AcceptAssertionBaseID is set, the EncryptedID of subject may
// also hold a BaseID, which is then set as subject.BaseID; otherwise that
// is refused (ErrUnsupported). The EncryptedID is then cleared, since BaseID, NameID
// and EncryptedID are alternatives and an assertion that is marshalled
// again must hold only one. It is called after the assertion's signature,
// which covers the EncryptedID, has been checked.
func (sp *ServiceProvider) decryptEncryptedIDs(subject *Subject) error {
	if subject == nil {
		return nil
	}
	switch {
	case subject.BaseID != nil && (subject.NameID != nil || subject.EncryptedID != nil):
		return classify(errors.New("assertion Subject has a BaseID and a NameID or EncryptedID"), ErrMalformedMessage)
	case subject.NameID != nil && subject.EncryptedID != nil:
		return classify(errors.New("assertion Subject: has both a NameID and an EncryptedID"), ErrMalformedMessage)
	case subject.EncryptedID != nil:
		nameID, baseID, err := decryptIdentifier(subject.EncryptedID, sp.decryptElement, sp.AcceptAssertionBaseID)
		if err != nil {
			return fmt.Errorf("assertion Subject: %w", err)
		}
		subject.NameID, subject.BaseID = nameID, baseID
		subject.EncryptedID = nil
	}
	for i := range subject.SubjectConfirmations {
		subjectConfirmation := &subject.SubjectConfirmations[i]
		nameID, err := sp.decryptEncryptedID(subjectConfirmation.NameID, subjectConfirmation.EncryptedID)
		if err != nil {
			return fmt.Errorf("assertion SubjectConfirmation: %w", err)
		}
		subjectConfirmation.NameID = nameID
		subjectConfirmation.EncryptedID = nil
	}
	return nil
}

// decryptEncryptedID returns the NameID held by encryptedID, or nameID if
// encryptedID is nil. The two are alternatives, so an element with both is
// rejected. The EncryptedID is decrypted with the SP's decryption keys and
// must hold a saml:NameID (see decryptNameID).
func (sp *ServiceProvider) decryptEncryptedID(nameID *NameID, encryptedID *etree.Element) (*NameID, error) {
	if encryptedID == nil {
		return nameID, nil
	}
	if nameID != nil {
		return nil, classify(errors.New("has both a NameID and an EncryptedID"), ErrMalformedMessage)
	}
	return decryptNameID(encryptedID, sp.decryptElement)
}

// validateSubjectIdentifier makes sure subject identifies the principal.
// The Subject of a login assertion is the principal the SP establishes a
// session for (saml-core §2.4.1, saml-profiles §4.1.4.2), so one with no
// identifier is refused rather than accepted with a nil NameID. (A NameID
// with an empty value is still accepted: this package's own IdP issues one
// for a Session with no NameID.) A BaseID is accepted only if AcceptAssertionBaseID is
// set, since its content is defined by an extension this package does not
// interpret. It expects decryptEncryptedIDs to have replaced an EncryptedID
// by what it holds.
func (sp *ServiceProvider) validateSubjectIdentifier(subject *Subject) error {
	switch {
	case subject.BaseID != nil:
		if !sp.AcceptAssertionBaseID {
			return classify(errors.New("assertion Subject identifies the principal with a BaseID, which is not accepted"), ErrUnsupported)
		}
		return nil
	case subject.EncryptedID != nil:
		return classify(errors.New("assertion Subject EncryptedID has not been decrypted"), ErrMalformedMessage)
	case subject.NameID == nil:
		return classify(errors.New("assertion Subject has no BaseID, NameID or EncryptedID"), ErrMissingElement)
	}
	return nil
}

// decryptEncryptedAttributes decrypts each saml:EncryptedAttribute
// (saml-core §2.7.3.2) of the AttributeStatements of assertionEl with the
// SP's decryption keys and puts the saml:Attribute it holds into the
// matching AttributeStatement of assertion, in document order among the
// statement's plaintext Attributes. assertion is what assertionEl
// unmarshals to. An EncryptedAttribute that cannot be decrypted
// (ErrDecryptionFailed), or that does not hold a saml:Attribute, makes the
// assertion refused rather than silently ignored. It is called after the
// assertion's signature, which covers the EncryptedAttributes, has been
// checked.
func (sp *ServiceProvider) decryptEncryptedAttributes(assertionEl *etree.Element, assertion *Assertion) error {
	statementEls, err := findChildren(assertionEl, samlAssertionNamespace, "AttributeStatement")
	if err != nil {
		return err
	}
	if len(statementEls) != len(assertion.AttributeStatements) {
		return classify(errors.New("cannot match the AttributeStatement elements of the assertion"), ErrMalformedMessage)
	}
	for i, statementEl := range statementEls {
		encryptedEls, err := findChildren(statementEl, samlAssertionNamespace, "EncryptedAttribute")
		if err != nil {
			return err
		}
		if len(encryptedEls) == 0 {
			continue
		}
		attributeEls, err := findChildren(statementEl, samlAssertionNamespace, "Attribute")
		if err != nil {
			return err
		}
		statement := &assertion.AttributeStatements[i]
		if len(attributeEls) != len(statement.Attributes) {
			return classify(errors.New("cannot match the Attribute elements of an AttributeStatement"), ErrMalformedMessage)
		}
		isEncrypted := make(map[*etree.Element]bool, len(encryptedEls))
		for _, el := range encryptedEls {
			isEncrypted[el] = true
		}
		attributes := make([]Attribute, 0, len(attributeEls)+len(encryptedEls))
		next := 0 // the index of the next plaintext Attribute
		for _, childEl := range statementEl.ChildElements() {
			switch {
			case isEncrypted[childEl]:
				attribute, err := sp.decryptEncryptedAttribute(childEl)
				if err != nil {
					return err
				}
				attributes = append(attributes, *attribute)
			case next < len(attributeEls) && childEl == attributeEls[next]:
				attributes = append(attributes, statement.Attributes[next])
				next++
			}
		}
		statement.Attributes = attributes
	}
	return nil
}

// decryptEncryptedAttribute returns the saml:Attribute held by encryptedEl,
// a saml:EncryptedAttribute, decrypted with the SP's decryption keys.
func (sp *ServiceProvider) decryptEncryptedAttribute(encryptedEl *etree.Element) (*Attribute, error) {
	plaintext, err := sp.decryptElement(encryptedEl)
	if err != nil {
		return nil, classify(fmt.Errorf("cannot decrypt EncryptedAttribute: %w", err), ErrDecryptionFailed)
	}
	if plaintext.NamespaceURI() != samlAssertionNamespace || plaintext.Tag != "Attribute" {
		return nil, classify(fmt.Errorf("EncryptedAttribute holds a %s element, not a saml:Attribute", plaintext.FullTag()), ErrMalformedMessage)
	}
	var attribute Attribute
	if err := unmarshalElement(plaintext, &attribute); err != nil {
		return nil, err
	}
	if err := fillAttributeXML(plaintext, &attribute); err != nil {
		return nil, err
	}
	return &attribute, nil
}

// validateAssertion checks that the conditions specified in assertion match
// the requirements to accept. If validation fails, it returns an error describing
// the failure. (The digital signature on the assertion is not checked -- this
// should be done before calling this function).
// samlVersion is the only SAML version this package reads and writes.
const samlVersion = "2.0"

// checkVersion refuses a message or assertion whose Version is not 2.0
// (saml-core §4.1.2 and §4.1.3.1: a relying party MUST NOT process an
// assertion, and a responder MUST reject a request, with an unsupported
// major version). what names the element in the error.
func checkVersion(what, version string) error {
	if version != samlVersion {
		return classify(fmt.Errorf("%s Version %q is not %s", what, version, samlVersion), ErrUnsupported)
	}
	return nil
}

func (sp *ServiceProvider) validateAssertion(assertion *Assertion, possibleRequestIDs []string, now time.Time) error {
	if err := checkVersion("assertion", assertion.Version); err != nil {
		return err
	}
	if sp.limits().issueDeadline(assertion).Before(now) {
		return classify(fmt.Errorf("expired on %s", sp.limits().issueDeadline(assertion)), ErrExpired)
	}
	if assertion.IssueInstant.Add(-sp.maxClockSkew()).After(now) {
		return classify(fmt.Errorf("assertion IssueInstant %s is in the future", assertion.IssueInstant), ErrNotYetValid)
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer is not %q", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	if assertion.Subject == nil {
		return classify(fmt.Errorf("assertion has no Subject"), ErrMissingElement)
	}
	if err := sp.validateSubjectIdentifier(assertion.Subject); err != nil {
		return err
	}
	if assertion.Conditions == nil {
		return classify(fmt.Errorf("assertion has no Conditions"), ErrMissingElement)
	}
	if err := sp.validateBearerSubjectConfirmations(assertion.Subject, possibleRequestIDs, now); err != nil {
		return err
	}
	// The assertion establishes a login, so it must say how the principal
	// authenticated: "the set of one or more assertions MUST contain at
	// least one <AuthnStatement>", in an assertion with a bearer
	// SubjectConfirmation (saml-profiles §4.1.4.2). An attribute-only
	// assertion is not a login.
	if len(assertion.AuthnStatements) == 0 {
		return classify(fmt.Errorf("assertion has no AuthnStatement"), ErrMissingElement)
	}
	if assertion.Conditions.NotBefore.Add(-sp.maxClockSkew()).After(now) {
		return classify(fmt.Errorf("assertion Conditions is not yet valid"), ErrNotYetValid)
	}
	// An omitted Conditions NotOnOrAfter means no expiry (saml-core
	// §2.5.1.2); the assertion is still bounded by MaxIssueDelay and the
	// SubjectConfirmationData NotOnOrAfter.
	if !assertion.Conditions.NotOnOrAfter.IsZero() && sp.limits().pastDeadline(assertion.Conditions.NotOnOrAfter, now) {
		return classify(fmt.Errorf("assertion Conditions is expired"), ErrExpired)
	}
	if err := sp.validateUnknownConditions(assertion); err != nil {
		return err
	}

	if err := sp.validateAudienceRestriction(assertion); err != nil {
		return err
	}
	if err := sp.validateAuthnContextClassRef(assertion); err != nil {
		return err
	}
	return nil
}

// validateUnknownConditions decides an assertion whose Conditions has a
// child element this package does not understand. Its validity cannot be
// determined, and an Indeterminate assertion MUST be rejected (saml-core
// §2.5.1.1, lines 872-881), so with RejectUnknownConditions it is refused;
// otherwise the conditions are ignored. ValidateUnknownConditions, if set,
// decides instead.
func (sp *ServiceProvider) validateUnknownConditions(assertion *Assertion) error {
	unknown := assertion.Conditions.UnknownConditions
	if len(unknown) == 0 {
		return nil
	}
	if sp.ValidateUnknownConditions != nil {
		return sp.ValidateUnknownConditions(assertion)
	}
	if !sp.RejectUnknownConditions {
		return nil
	}
	names := make([]string, len(unknown))
	for i, name := range unknown {
		names[i] = "{" + name.Space + "}" + name.Local
	}
	return classify(fmt.Errorf("assertion Conditions has unrecognised conditions %q: the assertion is Indeterminate", names), ErrUnsupported)
}

// validateAuthnContextClassRef checks, if ValidateAuthnContextClassRef is
// set, that one of the assertion's AuthnStatements has an
// AuthnContextClassRef that satisfies RequestedAuthnContext: one listed in it
// for the "exact" Comparison, or one AuthnContextClassRefComparator accepts
// for any other.
func (sp *ServiceProvider) validateAuthnContextClassRef(assertion *Assertion) error {
	if !sp.ValidateAuthnContextClassRef || sp.RequestedAuthnContext == nil {
		return nil
	}
	requested := sp.RequestedAuthnContext.ClassRefs()
	if len(requested) == 0 {
		return nil
	}
	comparison := sp.RequestedAuthnContext.Comparison
	exact := comparison == "" || comparison == "exact"
	if !exact && sp.AuthnContextClassRefComparator == nil {
		return classify(fmt.Errorf("cannot validate AuthnContextClassRef for RequestedAuthnContext Comparison %q: only \"exact\" is supported", comparison), ErrUnsupported)
	}
	satisfies := func(got string) bool {
		if exact {
			return slices.Contains(requested, got)
		}
		return sp.AuthnContextClassRefComparator(comparison, requested, got)
	}
	var got []string
	for _, authnStatement := range assertion.AuthnStatements {
		classRef := authnStatement.AuthnContext.AuthnContextClassRef
		if classRef == nil {
			continue
		}
		if satisfies(classRef.Value) {
			return nil
		}
		got = append(got, classRef.Value)
	}
	if !exact {
		return classify(fmt.Errorf("assertion AuthnContextClassRef %q does not satisfy the requested %q with Comparison %q", got, requested, comparison), ErrAuthnContextMismatch)
	}
	return classify(fmt.Errorf("assertion AuthnContextClassRef %q is not one of the requested %q", got, requested), ErrAuthnContextMismatch)
}

// validateAssertionInResponseTo checks the InResponseTo of an assertion's
// SubjectConfirmationData against the IDs of the requests this SP made.
//
// With AllowIDPInitiated set, an empty InResponseTo is an unsolicited
// assertion and is accepted. A non-empty one names an SP-initiated request
// and must match one of possibleRequestIDs, so that an assertion issued for
// one login cannot be replayed as an IdP-initiated one. Some IdPs (e.g.
// Rippling) send a non-empty InResponseTo on IdP-initiated assertions; a
// ValidateRequestID hook decides those cases too.
func (sp *ServiceProvider) validateAssertionInResponseTo(inResponseTo string, possibleRequestIDs []string) error {
	if sp.AllowIDPInitiated {
		if inResponseTo == "" {
			return nil
		}
		if sp.ValidateRequestID != nil {
			return sp.ValidateRequestID(Response{InResponseTo: inResponseTo}, possibleRequestIDs)
		}
	}
	for _, possibleRequestID := range possibleRequestIDs {
		// As in validateRequestID, an empty entry never matches.
		if possibleRequestID != "" && inResponseTo == possibleRequestID {
			return nil
		}
	}
	return classify(fmt.Errorf("assertion SubjectConfirmation one of the possible request IDs (%v)", possibleRequestIDs), ErrRequestIDMismatch)
}

// issueDeadline is the last moment validateAssertion accepts assertion by its
// IssueInstant.
func (l timeLimits) issueDeadline(assertion *Assertion) time.Time {
	return l.issueInstantDeadline(assertion.IssueInstant)
}

// issueInstantDeadline is the last moment a message issued at issueInstant
// is accepted: MaxIssueDelay later. MaxIssueDelay already allows for some
// clock drift.
func (l timeLimits) issueInstantDeadline(issueInstant time.Time) time.Time {
	return issueInstant.Add(l.delay())
}

// checkIssueInstant refuses a message whose IssueInstant is more than
// MaxIssueDelay in the past, or more than MaxClockSkew in
// the future. A message dated in the future would otherwise stay acceptable
// by its IssueInstant for as long as the issuer liked. what names the
// message in the error.
func (l timeLimits) checkIssueInstant(what string, issueInstant, now time.Time) error {
	if deadline := l.issueInstantDeadline(issueInstant); deadline.Before(now) {
		return classify(fmt.Errorf("%s expired at %s", what, deadline), ErrExpired)
	}
	if issueInstant.Add(-l.skew()).After(now) {
		return classify(fmt.Errorf("%s %s is in the future", what, issueInstant), ErrNotYetValid)
	}
	return nil
}

// skewedDeadline is a NotOnOrAfter time moved later by the allowed clock
// skew: the moment from which validateAssertion refuses it.
func (l timeLimits) skewedDeadline(notOnOrAfter time.Time) time.Time {
	return notOnOrAfter.Add(l.skew())
}

// pastDeadline reports whether now is at or after notOnOrAfter, allowing for
// clock skew. NotOnOrAfter is exclusive: it is "the time instant at which the
// validity interval has ended" (saml-core §2.5.1.2), so a message is no
// longer valid at that instant itself.
func (l timeLimits) pastDeadline(notOnOrAfter, now time.Time) bool {
	return !now.Before(l.skewedDeadline(notOnOrAfter))
}

// acceptableUntil returns the moment after which validateAssertion refuses
// assertion: the earliest of the deadlines its expiry checks apply. A
// NotOnOrAfter deadline is exclusive (the assertion is already refused at
// it); the MaxIssueDelay deadline is inclusive. An omitted Conditions
// NotOnOrAfter sets no deadline.
func (l timeLimits) acceptableUntil(assertion *Assertion) time.Time {
	deadline := l.issueDeadline(assertion)
	if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() {
		deadline = earliest(deadline, l.skewedDeadline(assertion.Conditions.NotOnOrAfter))
	}
	// One valid bearer confirmation is enough, so the assertion stays
	// acceptable until the latest bearer NotOnOrAfter. Confirmations with
	// another Method are not checked and set no deadline.
	var confirmationDeadline time.Time
	if assertion.Subject != nil {
		for _, confirmation := range assertion.Subject.SubjectConfirmations {
			if confirmation.Method != bearerSubjectConfirmationMethod || confirmation.SubjectConfirmationData == nil {
				continue
			}
			if d := l.skewedDeadline(confirmation.SubjectConfirmationData.NotOnOrAfter); d.After(confirmationDeadline) {
				confirmationDeadline = d
			}
		}
	}
	if !confirmationDeadline.IsZero() {
		deadline = earliest(deadline, confirmationDeadline)
	}
	return deadline
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// consumeAssertion records assertion in the ReplayCache, if one is set,
// refusing it if it was recorded before.
func (sp *ServiceProvider) consumeAssertion(assertion *Assertion) error {
	if sp.ReplayCache == nil {
		return nil
	}
	if assertion.ID == "" {
		return classify(errors.New("assertion has no ID to check for replay"), ErrMissingElement)
	}
	if err := sp.ReplayCache.Consume(assertion.ID, sp.limits().acceptableUntil(assertion)); err != nil {
		return fmt.Errorf("assertion %q: %w", assertion.ID, err)
	}
	return nil
}

// logoutRequestReplayKeyPrefix is prepended to the ID of a LogoutRequest to
// form the key it is recorded under in an AssertionReplayCache. It keeps
// LogoutRequest IDs apart from assertion IDs, which are recorded as is and,
// being xs:ID values, cannot contain a colon.
const logoutRequestReplayKeyPrefix = "LogoutRequest:"

// logoutRequestAcceptableUntil returns the moment after which a LogoutRequest
// is refused: IssueInstant plus MaxIssueDelay or, if it is earlier, the
// NotOnOrAfter time allowing for clock skew.
func (l timeLimits) logoutRequestAcceptableUntil(req *LogoutRequest) time.Time {
	deadline := l.issueInstantDeadline(req.IssueInstant)
	if req.NotOnOrAfter != nil {
		deadline = earliest(deadline, l.skewedDeadline(*req.NotOnOrAfter))
	}
	return deadline
}

// consumeLogoutRequest records the ID of req in cache, if cache is not nil,
// refusing req if it was recorded before. req must already be validated.
func consumeLogoutRequest(cache AssertionReplayCache, req *LogoutRequest, l timeLimits) error {
	if cache == nil {
		return nil
	}
	if req.ID == "" {
		return classify(errors.New("logout request has no ID to check for replay"), ErrMissingElement)
	}
	if err := cache.Consume(logoutRequestReplayKeyPrefix+req.ID, l.logoutRequestAcceptableUntil(req)); err != nil {
		return fmt.Errorf("logout request %q: %w", req.ID, err)
	}
	return nil
}

// bearerSubjectConfirmationMethod is the SubjectConfirmation Method of the
// SAML web browser SSO profile.
const bearerSubjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // not a credential

// validateBearerSubjectConfirmations checks the bearer SubjectConfirmations
// of subject. The Web Browser SSO profile requires one (saml-profiles
// §4.1.4.2), and "satisfying any one of them is sufficient to confirm the
// subject" (saml-core §2.4.1), so the assertion is accepted if one bearer
// confirmation has SubjectConfirmationData that names this SP's ACS as
// Recipient, answers one of possibleRequestIDs (or none, if IdP-initiated
// responses are allowed), and is valid at now. Confirmations with another
// Method ("Other ... confirmation methods MAY be included", §4.1.4.2) are
// not checked. If none passes, the error of the first bearer confirmation is
// returned.
func (sp *ServiceProvider) validateBearerSubjectConfirmations(subject *Subject, possibleRequestIDs []string, now time.Time) error {
	var firstErr error
	for _, subjectConfirmation := range subject.SubjectConfirmations {
		if subjectConfirmation.Method != bearerSubjectConfirmationMethod {
			continue
		}
		err := sp.validateBearerSubjectConfirmationData(subjectConfirmation.SubjectConfirmationData, possibleRequestIDs, now)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		return classify(fmt.Errorf("assertion has no bearer SubjectConfirmation"), ErrMissingElement)
	}
	return firstErr
}

// validateBearerSubjectConfirmationData checks the SubjectConfirmationData of
// one bearer SubjectConfirmation (saml-profiles §4.1.4.3).
func (sp *ServiceProvider) validateBearerSubjectConfirmationData(data *SubjectConfirmationData, possibleRequestIDs []string, now time.Time) error {
	if data == nil {
		return classify(fmt.Errorf("assertion SubjectConfirmation has no SubjectConfirmationData"), ErrMissingElement)
	}
	if err := sp.validateAssertionInResponseTo(data.InResponseTo, possibleRequestIDs); err != nil {
		return err
	}
	if data.Recipient != sp.AcsURL.String() {
		return classify(fmt.Errorf("assertion SubjectConfirmation Recipient is not %s", sp.AcsURL.String()), ErrDestinationMismatch)
	}
	// saml-profiles §4.1.4.2 says a bearer SubjectConfirmationData MUST
	// NOT carry NotBefore, but some IdPs send one anyway; accept it as
	// long as it is not in the future (saml-core §2.4.1.2). An omitted
	// NotBefore is the zero time, which always passes.
	if data.NotBefore.Add(-sp.maxClockSkew()).After(now) {
		return classify(fmt.Errorf("assertion SubjectConfirmationData is not yet valid"), ErrNotYetValid)
	}
	// A bearer SubjectConfirmationData MUST carry NotOnOrAfter
	// (saml-profiles §4.1.4.2): an omitted one is the zero time, which
	// has always passed.
	if sp.limits().pastDeadline(data.NotOnOrAfter, now) {
		return classify(fmt.Errorf("assertion SubjectConfirmationData is expired"), ErrExpired)
	}
	return nil
}

func (sp *ServiceProvider) validateAudienceRestriction(assertion *Assertion) error {
	if sp.ValidateAudienceRestriction != nil {
		if err := sp.ValidateAudienceRestriction(assertion); err != nil {
			return classify(fmt.Errorf("audience restriction validation failed: %w", err), ErrAudienceMismatch)
		}
		return nil
	}

	audience := firstSet(sp.EntityID, sp.MetadataURL.String())
	// An assertion with no AudienceRestriction is valid at every service
	// provider trusting the IdP, so one naming this SP is required.
	if len(assertion.Conditions.AudienceRestrictions) == 0 {
		return classify(fmt.Errorf("assertion Conditions has no AudienceRestriction for %q", audience), ErrAudienceMismatch)
	}
	// Every AudienceRestriction must be satisfied, and one is satisfied when
	// any of its audiences is this SP (saml-core §2.5.1.4).
	for i := range assertion.Conditions.AudienceRestrictions {
		if !audienceRestrictionContains(&assertion.Conditions.AudienceRestrictions[i], audience) {
			return classify(fmt.Errorf("assertion Conditions AudienceRestriction does not contain %q", audience), ErrAudienceMismatch)
		}
	}
	return nil
}

// audienceRestrictionContains reports whether any audience of r is audience.
func audienceRestrictionContains(r *AudienceRestriction, audience string) bool {
	for _, v := range r.AllAudiences() {
		if v.Value == audience {
			return true
		}
	}
	return false
}

// withoutValidityPeriod returns copies of certs whose validity period covers
// all time, so that dsig accepts them regardless of the current time. Only
// the parsed NotBefore and NotAfter fields change; Raw and the public key are
// unchanged, so the copies still match the certificates they came from.
func withoutValidityPeriod(certs []*x509.Certificate) []*x509.Certificate {
	rv := make([]*x509.Certificate, len(certs))
	for i, cert := range certs {
		c := *cert
		c.NotBefore = time.Time{}
		c.NotAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		rv[i] = &c
	}
	return rv
}

var errSignatureElementNotPresent = errors.New("signature element not present")

// unboundedParentContext is etreeutils.NSBuildParentContext without the
// default context's 1000-node traversal budget (GHSA-qhrp-hfff-vphr). That
// budget is meant for SignedInfo canonicalization. Detaching a whole Response
// or Assertion counts every node in it, and a legitimate one can hold far more,
// such as a user's group memberships.
func unboundedParentContext(el *etree.Element) (etreeutils.NSContext, error) {
	parent := el.Parent()
	if parent == nil {
		return etreeutils.EmptyNSContext, nil
	}

	ctx, err := unboundedParentContext(parent)
	if err != nil {
		return ctx, err
	}

	return ctx.SubContext(parent)
}

// stripKeyInfoWithoutCertificate removes the KeyInfo from el's Signature
// when it carries no X509Certificate, so that dsig verifies against the
// trusted certificates instead, and reports whether it had none.
func stripKeyInfoWithoutCertificate(el *etree.Element) bool {
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") != nil {
		return false
	}
	if sigEl := el.FindElement("./Signature"); sigEl != nil {
		if keyInfo := sigEl.FindElement("KeyInfo"); keyInfo != nil {
			sigEl.RemoveChild(keyInfo)
		}
	}
	return true
}

// validatedWithEachCert validates the signature on el against each of certs
// in turn, with a copy of base that trusts only that certificate, and
// returns the signed element as dsig's Validate does for the first that
// succeeds, or the last error.
func validatedWithEachCert(base *dsig.ValidationContext, certs []*x509.Certificate, el *etree.Element) (*etree.Element, error) {
	var err error
	for _, cert := range certs {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{cert},
		})
		ctx.IdAttribute = base.IdAttribute
		ctx.Clock = base.Clock
		var signed *etree.Element
		if signed, err = ctx.Validate(el); err == nil {
			return signed, nil
		}
	}
	return nil, err
}

// validateSignature returns nil iff the Signature embedded in the element is valid
//
// Every error other than errSignatureElementNotPresent matches
// ErrInvalidSignature with errors.Is, and also ErrUntrustedCertificate or
// ErrCertificateNotValidNow when that is why validation failed.
func (sp *ServiceProvider) validateSignature(el *etree.Element) error {
	_, err := sp.verifySignedElement(el, sp.getIDPSigningCerts)
	return err
}

// validatedElement is validateSignature, returning on success the element
// to read the message from: what the signature covers, parsed from the
// canonical bytes that were digested, with el's Signature put back. Data
// el holds that the signature does not cover (such as a namespace
// declaration exclusive canonicalization leaves out) is not in it. If a
// SignatureVerifier that does not implement SignedElementVerifier checked
// the signature, it returns el.
func (sp *ServiceProvider) validatedElement(el *etree.Element) (*etree.Element, error) {
	return sp.verifySignedElement(el, sp.getIDPSigningCerts)
}

// verifySignedElement is validatedElement, trusting the certificates
// metadataCerts returns when the IdP's certificates come from its metadata
// (that is, when neither IDPCertificate nor IDPCertificateFingerprint is
// set). Its errors are classified as validateSignature's are.
func (sp *ServiceProvider) verifySignedElement(el *etree.Element, metadataCerts func() ([]*x509.Certificate, error)) (*etree.Element, error) {
	signed, err := sp.validateSignatureUnclassified(el, metadataCerts)
	if err == errSignatureElementNotPresent {
		return nil, err
	}
	if err == nil {
		// el still carries its Signature (and ID); signed may not.
		if err = checkSignatureReference(el); err == nil {
			return signed, nil
		}
		err = fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
	}
	return nil, classify(err, ErrInvalidSignature)
}

func (sp *ServiceProvider) validateSignatureUnclassified(el *etree.Element, metadataCerts func() ([]*x509.Certificate, error)) (*etree.Element, error) {
	original := el
	sigEl, err := findChild(el, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return nil, err
	}
	if sigEl == nil {
		return nil, errSignatureElementNotPresent
	}
	if err := checkXMLSignatureNotSHA1(sp.RejectSHA1Signatures, sigEl); err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
	}

	certs, err := sp.signatureVerificationCerts(el, metadataCerts)
	if err != nil {
		return nil, err
	}

	if sp.IgnoreCertificateExpiry {
		certs = withoutValidityPeriod(certs)
	}

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: certs,
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	if clock := sp.dsigClock(); clock != nil {
		validationContext.Clock = clock
	}

	// Some SAML responses contain a RSAKeyValue element. One of two things is happening here:
	//
	// (1) We're getting something signed by a key we already know about -- the public key
	//     of the signing cert provided in the metadata.
	// (2) We're getting something signed by a key we *don't* know about, and which we have
	//     no ability to verify.
	//
	// The best course of action is to just remove the KeyInfo so that dsig falls back to
	// verifying against the public key provided in the metadata.
	noCertInKeyInfo := stripKeyInfoWithoutCertificate(el)

	tag := el.Tag
	ctx, err := unboundedParentContext(el)
	if err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}
	// A copy of the Signature, carrying the declarations it needs, to put
	// back into the verified element (which does not include it).
	sigCtx, err := ctx.SubContext(sigEl)
	if err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}
	sigCopy, err := etreeutils.NSDetatch(sigCtx, sigEl)
	if err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}
	sigIndex := sigEl.Index()
	// NSDetatch returns a nil element with its error, so the tag is kept above.
	el, err = etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}

	if sp.SignatureVerifier != nil {
		if v, ok := sp.SignatureVerifier.(SignedElementVerifier); ok {
			signed, err := v.VerifySignedElement(validationContext, el)
			if err != nil {
				return nil, err
			}
			return withSignature(signed, sigCopy, sigIndex), nil
		}
		if err := sp.SignatureVerifier.VerifySignature(validationContext, el); err != nil {
			return nil, err
		}
		return original, nil
	}

	// Without a certificate in KeyInfo, dsig can only pick the signing
	// certificate itself when it trusts exactly one ("Missing x509 Element"
	// otherwise), so an IdP that lists several signing certificates in its
	// metadata, for example during key rollover, and signs without
	// X509Certificate would always be rejected. In that case validate
	// against each trusted certificate on its own. Each attempt is a full
	// dsig validation of the same element that trusts only that
	// certificate, so this accepts exactly what one of them would accept
	// had the IdP named it in KeyInfo.
	if noCertInKeyInfo && len(certs) > 1 {
		signed, err := validatedWithEachCert(validationContext, certs, el)
		if err != nil {
			return nil, fmt.Errorf("cannot validate signature on %s: %w", tag, err)
		}
		return withSignature(signed, sigCopy, sigIndex), nil
	}

	signed, err := validationContext.Validate(el)
	if err != nil {
		err = fmt.Errorf("cannot validate signature on %s: %w", tag, err)
		if kind := classifyCertificate(el, certs, validationContext.Clock.Now()); kind != nil {
			return nil, classify(err, kind)
		}
		return nil, err
	}

	return withSignature(signed, sigCopy, sigIndex), nil
}

// withSignature puts sig back into signed, the element a signature
// validation returned (which the enveloped-signature transform removed it
// from), at index or after the last child if signed has fewer, so that the
// message read from signed still has its Signature.
func withSignature(signed, sig *etree.Element, index int) *etree.Element {
	if index > len(signed.Child) {
		index = len(signed.Child)
	}
	signed.InsertChildAt(index, sig)
	return signed
}

// signatureVerificationCerts returns the IdP certificates that a signature on
// el may be made with: from the IdP metadata, the configured fingerprint or
// the configured certificate.
func (sp *ServiceProvider) signatureVerificationCerts(el *etree.Element, metadataCerts func() ([]*x509.Certificate, error)) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err error
	if sp.IDPMetadata != nil && sp.IDPCertificateFingerprint == nil && sp.IDPCertificateFingerprintAlgorithm == nil && sp.IDPCertificate == nil {
		certs, err = metadataCerts()
		if err != nil {
			return nil, fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
		}
	}
	if sp.IDPMetadata != nil && sp.IDPCertificateFingerprint != nil && sp.IDPCertificateFingerprintAlgorithm != nil && sp.IDPCertificate == nil {
		certs, err = sp.getCertBasedOnFingerprint(el)
		if err != nil {
			return nil, fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
		}
	}
	if sp.IDPMetadata != nil && sp.IDPCertificateFingerprint == nil && sp.IDPCertificateFingerprintAlgorithm == nil && sp.IDPCertificate != nil {
		cert, err := parseCert(*sp.IDPCertificate)
		if err != nil {
			return nil, fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("cannot validate signature on %s: saml config not set up properly, specify either idp metadata url, fingerprints or actual certificate", el.Tag)
	}
	return certs, nil
}

// SignLogoutRequest adds the `Signature` element to the `LogoutRequest`.
func (sp *ServiceProvider) SignLogoutRequest(req *LogoutRequest) error {
	signingContext, err := sp.signingContext(sp.logoutSignatureMethod())
	if err != nil {
		return err
	}

	assertionEl := req.Element()
	signedRequestEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return err
	}

	sigEl := signedRequestEl.Child[len(signedRequestEl.Child)-1]
	req.Signature = sigEl.(*etree.Element)
	return nil
}

// LogoutRequestOption customizes a LogoutRequest produced by
// MakeLogoutRequest, MakeRedirectLogoutRequest or MakePostLogoutRequest. The
// option is applied before the request is signed.
type LogoutRequestOption func(*LogoutRequest)

// WithSessionIndex sets the SessionIndex element of a LogoutRequest, which
// identifies the session at the IDP to terminate (saml-core-2.0-os section
// 3.7.1). The value is typically the SessionIndex attribute of the
// AuthnStatement in the assertion the IDP issued at login. Some IDPs require
// it to perform single logout. An empty value leaves SessionIndex unset.
func WithSessionIndex(sessionIndex string) LogoutRequestOption {
	return func(req *LogoutRequest) {
		if sessionIndex == "" {
			req.setSessionIndexes(nil)
			return
		}
		req.setSessionIndexes([]SessionIndex{{Value: sessionIndex}})
	}
}

// WithSessionIndexes sets the SessionIndex elements of a LogoutRequest, one
// for each non-empty value, in order (saml-core-2.0-os section 3.7.1). Use it
// instead of WithSessionIndex to end several sessions of the principal at the
// IDP with one request. Without any non-empty value, the request carries no
// SessionIndex.
func WithSessionIndexes(sessionIndexes ...string) LogoutRequestOption {
	return func(req *LogoutRequest) {
		indexes := make([]SessionIndex, 0, len(sessionIndexes))
		for _, sessionIndex := range sessionIndexes {
			if sessionIndex != "" {
				indexes = append(indexes, SessionIndex{Value: sessionIndex})
			}
		}
		req.setSessionIndexes(indexes)
	}
}

// MakeLogoutRequest produces a new LogoutRequest object for idpURL. If
// sp.SignatureMethod is set, the request carries an enveloped XML signature,
// which is what the HTTP-POST binding uses.
func (sp *ServiceProvider) MakeLogoutRequest(idpURL, nameID string, opts ...LogoutRequestOption) (*LogoutRequest, error) {
	req, err := sp.makeLogoutRequest(idpURL, nameID, opts...)
	if err != nil {
		return nil, err
	}
	if sp.logoutSignatureMethod() != "" {
		if err := sp.SignLogoutRequest(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (sp *ServiceProvider) makeUnsignedLogoutRequest(idpURL, nameID string, opts ...LogoutRequestOption) *LogoutRequest {
	req := &LogoutRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(sp.randReader(), 20)),
		IssueInstant: sp.now(),
		Version:      "2.0",
		Destination:  idpURL,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(sp.EntityID, sp.MetadataURL.String()),
		},
		NameID: &NameID{
			Format:          sp.nameIDFormat(),
			Value:           nameID,
			NameQualifier:   sp.IDPMetadata.EntityID,
			SPNameQualifier: sp.Metadata().EntityID,
		},
	}
	for _, opt := range opts {
		opt(req)
	}
	return req
}

// makeLogoutRequest returns an unsigned LogoutRequest, whose NameID is
// encrypted if sp.EncryptLogoutNameID is set.
func (sp *ServiceProvider) makeLogoutRequest(idpURL, nameID string, opts ...LogoutRequestOption) (*LogoutRequest, error) {
	req := sp.makeUnsignedLogoutRequest(idpURL, nameID, opts...)
	if sp.EncryptLogoutNameID {
		if err := sp.EncryptLogoutRequestNameID(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// EncryptLogoutRequestNameID replaces the NameID of req with a
// saml:EncryptedID holding it (saml-core-2.0-os §2.2.4), encrypted to the
// IDP's encryption certificate with LogoutNameIDEncrypter. The certificate
// is the first one in IDPMetadata whose KeyDescriptor has use="encryption",
// or else the first one with no use. Call it before signing req. Use it to
// encrypt the NameID of some requests only; EncryptLogoutNameID encrypts
// every request.
func (sp *ServiceProvider) EncryptLogoutRequestNameID(req *LogoutRequest) error {
	if req.NameID == nil {
		return classify(errors.New("cannot encrypt the NameID of a LogoutRequest that has none"), ErrMissingElement)
	}
	cert, methods, err := sp.getIDPEncryptionCert()
	if err != nil {
		return err
	}
	encryptedID, err := encryptIdentifier(req.NameID.Element(), cert, encrypterWithRand(identifierEncrypter(sp.LogoutNameIDEncrypter, methods), sp.Rand))
	if err != nil {
		return fmt.Errorf("cannot encrypt NameID: %w", err)
	}
	req.EncryptedID = encryptedID
	req.NameID = nil
	return nil
}

// getIDPEncryptionCert returns the IDP certificate to encrypt to, and the
// EncryptionMethods listed with it: the first one in the IDP SSO descriptors
// whose use is "encryption", or else the first one whose use is unspecified.
func (sp *ServiceProvider) getIDPEncryptionCert() (*x509.Certificate, []EncryptionMethod, error) {
	if sp.IDPMetadata == nil {
		return nil, nil, classify(errors.New("no IDP metadata"), ErrMissingElement)
	}
	var keyDescriptors []KeyDescriptor
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		keyDescriptors = append(keyDescriptors, idpSSODescriptor.KeyDescriptors...)
	}
	cert, methods, err := encryptionKey(keyDescriptors)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, classify(errors.New("cannot find an encryption certificate in the IDP SSO descriptor"), ErrMissingElement)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("IDP encryption certificate: %w", err)
	}
	return cert, methods, nil
}

// MakeRedirectLogoutRequest creates a SAML LogoutRequest using the
// HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the logout process.
//
// If sp.SignatureMethod is set, the request is signed with a query string
// signature (SigAlg and Signature parameters) as the binding requires
// (saml-bindings-2.0-os section 3.4.4.1), rather than with an enveloped XML
// signature.
func (sp *ServiceProvider) MakeRedirectLogoutRequest(nameID, relayState string, opts ...LogoutRequestOption) (*url.URL, error) {
	req, err := sp.makeLogoutRequest(sp.GetSLOBindingLocation(HTTPRedirectBinding), nameID, opts...)
	if err != nil {
		return nil, err
	}
	return sp.RedirectLogoutRequestURL(req, relayState)
}

// RedirectLogoutRequestURL returns the URL that sends req to its Destination
// with the HTTP-Redirect binding. Use it instead of MakeRedirectLogoutRequest
// when the request's ID is needed, for example to track the request and
// match it with the IDP's LogoutResponse; req is typically made by
// MakeLogoutRequest with the IDP's HTTP-Redirect SingleLogoutService location.
//
// Any enveloped XML signature on req is left out of the message. If
// sp.SignatureMethod is set, the URL carries a query string signature
// instead, as the binding requires (saml-bindings-2.0-os section 3.4.4.1).
func (sp *ServiceProvider) RedirectLogoutRequestURL(req *LogoutRequest, relayState string) (*url.URL, error) {
	if err := checkRelayState(sp.LimitRelayStateLength, relayState); err != nil {
		return nil, err
	}
	unsigned := *req
	unsigned.Signature = nil
	encoded, err := deflateAndEncode(unsigned.Element())
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(unsigned.Destination, redirectParamSAMLRequest, encoded, relayState, sp.logoutSignatureMethod())
}

// Redirect returns a URL suitable for using the redirect binding with the
// request. The URL carries no query string signature; use
// ServiceProvider.MakeRedirectLogoutRequest to produce a signed one. Any
// enveloped XML signature is omitted, as required by the HTTP-Redirect binding.
func (r *LogoutRequest) Redirect(relayState string) *url.URL {
	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	doc := etree.NewDocument()
	unsigned := *r
	unsigned.Signature = nil
	doc.SetRoot(unsigned.Element())
	if _, err := doc.WriteTo(w2); err != nil {
		panic(err)
	}
	if err := w2.Close(); err != nil {
		panic(err)
	}
	if err := w1.Close(); err != nil {
		panic(err)
	}

	rv, _ := url.Parse(r.Destination)

	query := rv.Query()
	query.Set("SAMLRequest", w.String())
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	rv.RawQuery = query.Encode()

	return rv
}

// MakePostLogoutRequest creates a SAML authentication request using
// the HTTP-POST binding. It returns HTML text representing an HTML form that
// can be sent presented to a browser to initiate the logout process.
func (sp *ServiceProvider) MakePostLogoutRequest(nameID, relayState string, opts ...LogoutRequestOption) ([]byte, error) {
	if err := checkRelayState(sp.LimitRelayStateLength, relayState); err != nil {
		return nil, err
	}
	req, err := sp.MakeLogoutRequest(sp.GetSLOBindingLocation(HTTPPostBinding), nameID, opts...)
	if err != nil {
		return nil, err
	}
	return req.Post(relayState), nil
}

// Post returns an HTML form suitable for using the HTTP-POST binding with the request
func (r *LogoutRequest) Post(relayState string) []byte {
	return r.PostWithNonce(relayState, "")
}

// PostWithNonce is like Post, but if nonce is not empty it is set as the
// nonce attribute of the form's auto-submit <script> element, so that the
// form can be served under a Content-Security-Policy that allows scripts by
// nonce.
func (r *LogoutRequest) PostWithNonce(relayState, nonce string) []byte {
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())
	reqBuf, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	encodedReqBuf := base64.StdEncoding.EncodeToString(reqBuf)

	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<form method="post" action="{{.URL}}" id="SAMLRequestForm">` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script{{with .Nonce}} nonce="{{.}}"{{end}}>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLRequestForm').submit();</script>`))
	data := struct {
		URL         string
		SAMLRequest string
		RelayState  string
		Nonce       string
	}{
		URL:         r.Destination,
		SAMLRequest: encodedReqBuf,
		RelayState:  relayState,
		Nonce:       nonce,
	}

	rv := bytes.Buffer{}
	if err := tmpl.Execute(&rv, data); err != nil {
		panic(err)
	}

	return rv.Bytes()
}

// MakeLogoutResponse produces a new LogoutResponse object for idpURL and
// logoutRequestID, with the status Success. If sp.SignatureMethod is set,
// the response carries an enveloped XML signature, which is what the
// HTTP-POST binding uses.
func (sp *ServiceProvider) MakeLogoutResponse(idpURL, logoutRequestID string) (*LogoutResponse, error) {
	return sp.MakeLogoutResponseWithStatus(idpURL, logoutRequestID, successStatus())
}

// MakeLogoutResponseWithStatus is like MakeLogoutResponse, but the response
// carries status instead of Success. For example, a service provider that
// ended the session the LogoutRequest came with but not every session it
// names answers with StatusSuccess and the second-level status
// StatusPartialLogout (saml-core-2.0-os §3.7.3.2). The signature, if any,
// covers the status.
func (sp *ServiceProvider) MakeLogoutResponseWithStatus(idpURL, logoutRequestID string, status Status) (*LogoutResponse, error) {
	response := sp.makeUnsignedLogoutResponse(idpURL, logoutRequestID)
	response.Status = status
	if sp.logoutSignatureMethod() != "" {
		if err := sp.SignLogoutResponse(response); err != nil {
			return nil, err
		}
	}
	return response, nil
}

func (sp *ServiceProvider) makeUnsignedLogoutResponse(idpURL, logoutRequestID string) *LogoutResponse {
	return &LogoutResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(sp.randReader(), 20)),
		InResponseTo: logoutRequestID,
		Version:      "2.0",
		IssueInstant: sp.now(),
		Destination:  idpURL,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(sp.EntityID, sp.MetadataURL.String()),
		},
		Status: successStatus(),
	}
}

// successStatus returns the Status of a request that succeeded.
func successStatus() Status {
	return Status{StatusCode: StatusCode{Value: StatusSuccess}}
}

// MakeRedirectLogoutResponse creates a SAML LogoutResponse using
// the HTTP-Redirect binding. It returns a URL that we will redirect the user to
// for LogoutResponse.
//
// If sp.SignatureMethod is set, the response is signed with a query string
// signature (SigAlg and Signature parameters) as the binding requires
// (saml-bindings-2.0-os section 3.4.4.1), rather than with an enveloped XML
// signature.
func (sp *ServiceProvider) MakeRedirectLogoutResponse(logoutRequestID, relayState string) (*url.URL, error) {
	return sp.MakeRedirectLogoutResponseWithStatus(logoutRequestID, relayState, successStatus())
}

// MakeRedirectLogoutResponseWithStatus is like MakeRedirectLogoutResponse,
// but the response carries status instead of Success (see
// MakeLogoutResponseWithStatus). The query string signature, if any, covers
// the status.
func (sp *ServiceProvider) MakeRedirectLogoutResponseWithStatus(logoutRequestID, relayState string, status Status) (*url.URL, error) {
	resp := sp.makeUnsignedLogoutResponse(sp.GetSLOBindingLocation(HTTPRedirectBinding), logoutRequestID)
	resp.Status = status
	return sp.RedirectLogoutResponseURL(resp, relayState)
}

// RedirectLogoutResponseURL returns the URL that sends resp to its
// Destination with the HTTP-Redirect binding, as RedirectLogoutRequestURL
// does for a LogoutRequest. Use it for a response made with
// MakeLogoutResponseWithStatus, whose ID the caller then knows.
//
// Any enveloped XML signature on resp is left out of the message. If
// LogoutSignatureMethod or SignatureMethod is set, the URL carries a query
// string signature instead (saml-bindings-2.0-os section 3.4.4.1). The
// RelayState is the one of the request being answered, so its length is
// not checked.
func (sp *ServiceProvider) RedirectLogoutResponseURL(resp *LogoutResponse, relayState string) (*url.URL, error) {
	unsigned := *resp
	unsigned.Signature = nil
	encoded, err := deflateAndEncode(unsigned.Element())
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(unsigned.Destination, redirectParamSAMLResponse, encoded, relayState, sp.logoutSignatureMethod())
}

// Redirect returns a URL suitable for using the redirect binding with the
// LogoutResponse. The URL carries no query string signature; use
// ServiceProvider.MakeRedirectLogoutResponse to produce a signed one. Any
// enveloped XML signature is omitted, as required by the HTTP-Redirect binding.
func (r *LogoutResponse) Redirect(relayState string) *url.URL {
	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	doc := etree.NewDocument()
	unsigned := *r
	unsigned.Signature = nil
	doc.SetRoot(unsigned.Element())
	if _, err := doc.WriteTo(w2); err != nil {
		panic(err)
	}
	if err := w2.Close(); err != nil {
		panic(err)
	}
	if err := w1.Close(); err != nil {
		panic(err)
	}

	rv, _ := url.Parse(r.Destination)

	query := rv.Query()
	query.Set("SAMLResponse", w.String())
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	rv.RawQuery = query.Encode()

	return rv
}

// MakePostLogoutResponse creates a SAML LogoutResponse using
// the HTTP-POST binding. It returns HTML text representing an HTML form that
// can be sent presented to a browser for LogoutResponse.
func (sp *ServiceProvider) MakePostLogoutResponse(logoutRequestID, relayState string) ([]byte, error) {
	return sp.MakePostLogoutResponseWithStatus(logoutRequestID, relayState, successStatus())
}

// MakePostLogoutResponseWithStatus is like MakePostLogoutResponse, but the
// response carries status instead of Success (see
// MakeLogoutResponseWithStatus).
func (sp *ServiceProvider) MakePostLogoutResponseWithStatus(logoutRequestID, relayState string, status Status) ([]byte, error) {
	resp, err := sp.MakeLogoutResponseWithStatus(sp.GetSLOBindingLocation(HTTPPostBinding), logoutRequestID, status)
	if err != nil {
		return nil, err
	}
	return resp.Post(relayState), nil
}

// Post returns an HTML form suitable for using the HTTP-POST binding with the LogoutResponse.
func (r *LogoutResponse) Post(relayState string) []byte {
	return r.PostWithNonce(relayState, "")
}

// PostWithNonce is like Post, but if nonce is not empty it is set as the
// nonce attribute of the form's auto-submit <script> element, so that the
// form can be served under a Content-Security-Policy that allows scripts by
// nonce.
func (r *LogoutResponse) PostWithNonce(relayState, nonce string) []byte {
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())
	reqBuf, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	encodedReqBuf := base64.StdEncoding.EncodeToString(reqBuf)

	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
		`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script{{with .Nonce}} nonce="{{.}}"{{end}}>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLResponseForm').submit();</script>`))
	data := struct {
		URL          string
		SAMLResponse string
		RelayState   string
		Nonce        string
	}{
		URL:          r.Destination,
		SAMLResponse: encodedReqBuf,
		RelayState:   relayState,
		Nonce:        nonce,
	}

	rv := bytes.Buffer{}
	if err := tmpl.Execute(&rv, data); err != nil {
		panic(err)
	}

	return rv.Bytes()
}

// SignLogoutResponse adds the `Signature` element to the `LogoutResponse`.
func (sp *ServiceProvider) SignLogoutResponse(resp *LogoutResponse) error {
	signingContext, err := sp.signingContext(sp.logoutSignatureMethod())
	if err != nil {
		return err
	}

	assertionEl := resp.Element()
	signedRequestEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return err
	}

	sigEl := signedRequestEl.Child[len(signedRequestEl.Child)-1]
	resp.Signature = sigEl.(*etree.Element)
	return nil
}

func (sp *ServiceProvider) nameIDFormat() string {
	var nameIDFormat string
	switch sp.AuthnNameIDFormat {
	case "":
		// To maintain library back-compat, use "transient" if unset.
		nameIDFormat = string(TransientNameIDFormat)
	case UnspecifiedNameIDFormat:
		// Spec defines an empty value as "unspecified" so don't set one,
		// unless the IdP needs it spelled out.
		if sp.SendUnspecifiedNameIDFormat {
			nameIDFormat = string(UnspecifiedNameIDFormat)
		}
	default:
		nameIDFormat = string(sp.AuthnNameIDFormat)
	}
	return nameIDFormat
}

// metadataNameIDFormat returns the NameIDFormat advertised in the SP metadata.
// Unlike the NameIDPolicy in an AuthnRequest, where an omitted Format means
// "unspecified", a metadata NameIDFormat element must contain a URI, so the
// effective format is always emitted.
func (sp *ServiceProvider) metadataNameIDFormat() NameIDFormat {
	if sp.AuthnNameIDFormat == "" {
		// Matches the default used by nameIDFormat() for requests.
		return TransientNameIDFormat
	}
	return sp.AuthnNameIDFormat
}

// ValidateLogoutResponseRequest validates the LogoutResponse content from the
// request, which may use the HTTP-Redirect, HTTP-POST or HTTP-POST-SimpleSign
// binding.
//
// With the HTTP-Redirect binding the response must be signed, either with a
// query string signature (SigAlg and Signature parameters) or with an
// enveloped XML signature. A posted form that carries a SigAlg or Signature
// field is an HTTP-POST-SimpleSign message and must have a valid SimpleSign
// signature; an enveloped XML signature it also carries must be valid too.
//
// It does not check the response's InResponseTo against the LogoutRequest
// this service provider sent; use ParseLogoutResponse for that.
//
// Deprecated: use ParseLogoutResponse, which also checks that the response
// answers a LogoutRequest this service provider sent, so that a
// LogoutResponse cannot be replayed or delivered unsolicited.
func (sp *ServiceProvider) ValidateLogoutResponseRequest(req *http.Request) error {
	_, err := sp.parseLogoutResponseRequest(req)
	return err
}

// ParseLogoutResponse validates the LogoutResponse content from the request,
// which may use the HTTP-Redirect, HTTP-POST or HTTP-POST-SimpleSign binding, as
// ValidateLogoutResponseRequest does, and returns it. In addition, the
// response's InResponseTo must be one of possibleRequestIDs, the IDs of the
// LogoutRequests this service provider sent and still expects an answer to,
// so that a LogoutResponse cannot be replayed or delivered unsolicited.
//
// A response that is valid and answers one of possibleRequestIDs, but
// whose status is not Success, is returned together with an error that
// matches ErrBadStatus, so that the caller can still record its ID.
func (sp *ServiceProvider) ParseLogoutResponse(req *http.Request, possibleRequestIDs []string) (*LogoutResponse, error) {
	// resp is nil unless the response is valid but for its status, which
	// is reported only once InResponseTo matches.
	resp, err := sp.parseLogoutResponseRequest(req)
	if resp == nil {
		return nil, err
	}
	for _, possibleRequestID := range possibleRequestIDs {
		if possibleRequestID != "" && resp.InResponseTo == possibleRequestID {
			return resp, err
		}
	}
	return nil, &InvalidResponseError{
		Now:        sp.now(),
		PrivateErr: classify(fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs), ErrRequestIDMismatch),
	}
}

func (sp *ServiceProvider) parseLogoutResponseRequest(req *http.Request) (*LogoutResponse, error) {
	if data := req.URL.Query().Get("SAMLResponse"); data != "" {
		return sp.validateLogoutResponseRedirectQuery(req.URL.RawQuery)
	}

	err := req.ParseForm()
	if err != nil {
		return nil, &InvalidResponseError{
			Now:        sp.now(),
			PrivateErr: classify(fmt.Errorf("unable to parse form: %w", err), ErrMalformedMessage),
		}
	}

	if isSimpleSignRequest(req) {
		return sp.parseLogoutResponseSimpleSign(req)
	}
	return sp.parseLogoutResponseForm(req.PostForm.Get("SAMLResponse"))
}

// parseLogoutResponseSimpleSign validates a LogoutResponse received via
// the HTTP-POST-SimpleSign binding. Its SimpleSign signature must be valid.
func (sp *ServiceProvider) parseLogoutResponseSimpleSign(req *http.Request) (*LogoutResponse, error) {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	m, err := parseSimpleSignRequest(req, redirectParamSAMLResponse)
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	root, err := sp.readSimpleSignMessage(m, retErr)
	if err != nil {
		return nil, err
	}

	var resp LogoutResponse
	if err := unmarshalElement(root, &resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := sp.validateLogoutResponse(&resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := logoutResponseStatusError(&resp); err != nil {
		retErr.PrivateErr = err
		return &resp, retErr
	}
	return &resp, nil
}

// ValidateLogoutResponseForm returns a nil error if the logout response is valid.
//
// It does not check the response's InResponseTo; see ParseLogoutResponse.
//
// Deprecated: use ParseLogoutResponse, which reads the form from the request
// and also checks the response's InResponseTo.
func (sp *ServiceProvider) ValidateLogoutResponseForm(postFormData string) error {
	_, err := sp.parseLogoutResponseForm(postFormData)
	return err
}

func (sp *ServiceProvider) parseLogoutResponseForm(postFormData string) (*LogoutResponse, error) {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	rawResponseBuf, err := base64.StdEncoding.DecodeString(postFormData)
	if err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("unable to parse base64: %w", err), ErrMalformedMessage)
		return nil, retErr
	}
	retErr.Response = string(rawResponseBuf)

	if err := xmlroundtrip.Validate(rawResponseBuf); err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("response contains invalid XML: %w", err), ErrMalformedMessage)
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawResponseBuf); err != nil {
		retErr.PrivateErr = classify(err, ErrMalformedMessage)
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = classify(errors.New("invalid xml: no root"), ErrMalformedMessage)
		return nil, retErr
	}

	signed, err := sp.validatedElement(doc.Root())
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	var resp LogoutResponse
	if err := unmarshalElement(signed, &resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := sp.validateLogoutResponse(&resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := logoutResponseStatusError(&resp); err != nil {
		retErr.PrivateErr = err
		return &resp, retErr
	}
	return &resp, nil
}

// ValidateLogoutResponseRedirect returns a nil error if the logout response is valid.
// queryParameterData is the URL-decoded value of the SAMLResponse query
// parameter.
//
// Because it only receives the SAMLResponse value, this method cannot check a
// query string signature and therefore requires the response to carry an
// enveloped XML signature. Most IDPs sign HTTP-Redirect binding messages with
// a query string signature instead (as saml-bindings-2.0-os section 3.4.4.1
// requires); use ValidateLogoutResponseRequest to accept those.
//
// It does not check the response's InResponseTo; see ParseLogoutResponse.
//
// Deprecated: use ParseLogoutResponse, which also accepts query string
// signatures and checks the response's InResponseTo.
//
// URL Binding appears to be gzip / flate encoded
// See https://www.oasis-open.org/committees/download.php/20645/sstc-saml-tech-overview-2%200-draft-10.pdf  6.6
func (sp *ServiceProvider) ValidateLogoutResponseRedirect(queryParameterData string) error {
	_, err := sp.validateLogoutResponseRedirectQuery(redirectParamSAMLResponse + "=" + url.QueryEscape(queryParameterData))
	return err
}

// validateLogoutResponseRedirectQuery validates a LogoutResponse received
// via the HTTP-Redirect binding. rawQuery is the URL's raw query string.
func (sp *ServiceProvider) validateLogoutResponseRedirectQuery(rawQuery string) (*LogoutResponse, error) {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	root, err := sp.readRedirectBindingMessage(rawQuery, redirectParamSAMLResponse, retErr)
	if err != nil {
		return nil, err
	}

	var resp LogoutResponse
	if err := unmarshalElement(root, &resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := sp.validateLogoutResponse(&resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := logoutResponseStatusError(&resp); err != nil {
		retErr.PrivateErr = err
		return &resp, retErr
	}
	return &resp, nil
}

// validateLogoutResponse validates the LogoutResponse fields. Returns a nil error if the LogoutResponse is valid.
func (sp *ServiceProvider) validateLogoutResponse(resp *LogoutResponse) error {
	if err := checkVersion("LogoutResponse", resp.Version); err != nil {
		return err
	}
	if resp.Destination != sp.SloURL.String() {
		return classify(fmt.Errorf("`Destination` does not match SloURL (expected %q)", sp.SloURL.String()), ErrDestinationMismatch)
	}

	now := sp.now()
	if err := sp.limits().checkIssueInstant("issueInstant", resp.IssueInstant, now); err != nil {
		return err
	}
	if resp.Issuer == nil || resp.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	return nil
}

// logoutResponseStatusError returns an error that matches ErrBadStatus if
// the status of resp, an otherwise valid LogoutResponse, is not Success.
func logoutResponseStatusError(resp *LogoutResponse) error {
	if resp.Status.StatusCode.Value != StatusSuccess {
		return classify(fmt.Errorf("status code was not %s", StatusSuccess), newErrBadStatus(resp.Status))
	}
	return nil
}

// ValidateLogoutRequest validates a LogoutRequest sent by the IDP (IDP
// initiated single logout), using the HTTP-Redirect, HTTP-POST or
// HTTP-POST-SimpleSign binding. It returns the request only if it is valid.
// If the request identifies the principal with an EncryptedID rather than a
// NameID, it is decrypted with the service provider's decryption keys (as
// for encrypted assertions) and NameID is set to the result. A request whose
// principal is a BaseID is refused unless AcceptLogoutRequestBaseID is set;
// its NameID is then nil. All the
// request's SessionIndexes are returned by its AllSessionIndexes method.
//
// The request must be signed by the IDP. With the HTTP-Redirect binding that
// is either a query string signature (SigAlg and Signature parameters) or an
// enveloped XML signature; with the HTTP-POST binding it is an enveloped XML
// signature. A posted form that carries a SigAlg or Signature field is an
// HTTP-POST-SimpleSign message and must have a valid SimpleSign signature
// (an enveloped XML signature it also carries must be valid too).
//
// If ReplayCache is set, the request's ID is recorded in it once the request
// is otherwise valid, and a request whose ID is already recorded is refused.
//
// The caller should end the session identified by the returned request's
// NameID (and SessionIndex, if present) and then answer the IDP, for example
// with MakeRedirectLogoutResponse(req.ID, relayState).
func (sp *ServiceProvider) ValidateLogoutRequest(req *http.Request) (*LogoutRequest, error) {
	if data := req.URL.Query().Get(redirectParamSAMLRequest); data != "" {
		return sp.validateLogoutRequestRedirectQuery(req.URL.RawQuery)
	}

	if err := req.ParseForm(); err != nil {
		return nil, &InvalidResponseError{
			Now:        sp.now(),
			PrivateErr: classify(fmt.Errorf("unable to parse form: %w", err), ErrMalformedMessage),
		}
	}

	if isSimpleSignRequest(req) {
		return sp.validateLogoutRequestSimpleSign(req)
	}
	return sp.ValidateLogoutRequestForm(req.PostForm.Get(redirectParamSAMLRequest))
}

// validateLogoutRequestSimpleSign validates a LogoutRequest received via the
// HTTP-POST-SimpleSign binding. Its SimpleSign signature must be valid.
func (sp *ServiceProvider) validateLogoutRequestSimpleSign(req *http.Request) (*LogoutRequest, error) {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	m, err := parseSimpleSignRequest(req, redirectParamSAMLRequest)
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	root, err := sp.readSimpleSignMessage(m, retErr)
	if err != nil {
		return nil, err
	}
	return sp.unmarshalAndValidateLogoutRequest(root, retErr)
}

// ValidateLogoutRequestForm validates a LogoutRequest received via the
// HTTP-POST binding. postFormData is the value of the SAMLRequest form field.
// It returns the request only if it is valid.
func (sp *ServiceProvider) ValidateLogoutRequestForm(postFormData string) (*LogoutRequest, error) {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	rawRequestBuf, err := base64.StdEncoding.DecodeString(postFormData)
	if err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("unable to parse base64: %w", err), ErrMalformedMessage)
		return nil, retErr
	}
	retErr.Response = string(rawRequestBuf)

	if err := xmlroundtrip.Validate(rawRequestBuf); err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("request contains invalid XML: %w", err), ErrMalformedMessage)
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawRequestBuf); err != nil {
		retErr.PrivateErr = classify(err, ErrMalformedMessage)
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = classify(errors.New("invalid xml: no root"), ErrMalformedMessage)
		return nil, retErr
	}

	signed, err := sp.validatedElement(doc.Root())
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	return sp.unmarshalAndValidateLogoutRequest(signed, retErr)
}

// validateLogoutRequestRedirectQuery validates a LogoutRequest received via
// the HTTP-Redirect binding. rawQuery is the URL's raw query string.
func (sp *ServiceProvider) validateLogoutRequestRedirectQuery(rawQuery string) (*LogoutRequest, error) {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	root, err := sp.readRedirectBindingMessage(rawQuery, redirectParamSAMLRequest, retErr)
	if err != nil {
		return nil, err
	}

	return sp.unmarshalAndValidateLogoutRequest(root, retErr)
}

func (sp *ServiceProvider) unmarshalAndValidateLogoutRequest(root *etree.Element, retErr *InvalidResponseError) (*LogoutRequest, error) {
	var req LogoutRequest
	if err := unmarshalElement(root, &req); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := sp.validateLogoutRequest(&req); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := consumeLogoutRequest(sp.ReplayCache, &req, sp.limits()); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	return &req, nil
}

// validateLogoutRequest validates the LogoutRequest fields. Returns a nil error if the LogoutRequest is valid.
func (sp *ServiceProvider) validateLogoutRequest(req *LogoutRequest) error {
	if err := checkVersion("LogoutRequest", req.Version); err != nil {
		return err
	}
	// The LogoutResponse answers the request by its ID (saml-core §3.2.1:
	// ID is required, and InResponseTo must match it).
	if req.ID == "" {
		return classify(errors.New("LogoutRequest has no ID"), ErrMissingElement)
	}
	if req.Destination != sp.SloURL.String() {
		return classify(fmt.Errorf("`Destination` does not match SloURL (expected %q)", sp.SloURL.String()), ErrDestinationMismatch)
	}
	return sp.validateLogoutRequestFields(req)
}

// validateLogoutRequestFields validates the LogoutRequest fields other than
// Destination.
func (sp *ServiceProvider) validateLogoutRequestFields(req *LogoutRequest) error {
	now := sp.now()
	if err := sp.limits().checkIssueInstant("issueInstant", req.IssueInstant, now); err != nil {
		return err
	}
	if req.NotOnOrAfter != nil && !now.Before(req.NotOnOrAfter.Add(sp.maxClockSkew())) {
		return classify(fmt.Errorf("request expired at %s", req.NotOnOrAfter), ErrExpired)
	}
	if req.Issuer == nil || req.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	return resolveLogoutRequestNameID(req, sp.decryptElement, sp.AcceptLogoutRequestBaseID)
}

func firstSet(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

// findChildren returns all the elements matching childNS/childTag that are direct children of parentEl.
//
// The namespace context of parentEl is built once. Building it for every
// child (NSBuildParentContext and SubContext both copy every declaration in
// scope) made the cost the number of children times the number of
// declarations, so a small unsigned message with many declarations and many
// matching children took seconds and gigabytes to read.
func findChildren(parentEl *etree.Element, childNS string, childTag string) ([]*etree.Element, error) {
	//nolint:prealloc // We don't know how many child elements we'll actually put into this array.
	var rv []*etree.Element
	var parentCtx *etreeutils.NSContext
	for _, childEl := range parentEl.ChildElements() {
		if childEl.Tag != childTag {
			continue
		}

		if parentCtx == nil {
			ctx, err := etreeutils.NSBuildParentContext(childEl)
			if err != nil {
				return nil, err
			}
			parentCtx = &ctx
		}

		if err := checkNamespaceDeclarations(childEl); err != nil {
			return nil, err
		}
		ns, err := lookupElementNamespace(*parentCtx, childEl)
		if err != nil {
			return nil, classify(fmt.Errorf("[%s]:%s cannot find prefix %s: %w", childNS, childTag, childEl.Space, err), ErrMalformedMessage)
		}
		if ns != childNS {
			continue
		}

		rv = append(rv, childEl)
	}

	return rv, nil
}

// checkNamespaceDeclarations makes the checks NSContext.SubContext makes of
// el's namespace declarations.
func checkNamespaceDeclarations(el *etree.Element) error {
	for _, attr := range el.Attr {
		switch {
		case attr.Space == "xmlns" && attr.Key == "xml" && attr.Value != etreeutils.XMLNamespace:
			return etreeutils.ErrReservedNamespace
		case attr.Space == "xmlns" && attr.Key == "xmlns":
			return etreeutils.ErrReservedNamespace
		case attr.Space == "" && attr.Key == "xmlns" && attr.Value == etreeutils.XMLNSNamespace:
			return etreeutils.ErrInvalidDefaultNamespace
		}
	}
	return nil
}

// lookupElementNamespace returns the namespace of el's prefix, given
// parentCtx, the namespace context of el's parent: what
// parentCtx.SubContext(el) followed by LookupPrefix(el.Space) returns,
// without copying parentCtx. Check el's declarations with
// checkNamespaceDeclarations first.
func lookupElementNamespace(parentCtx etreeutils.NSContext, el *etree.Element) (string, error) {
	ns, declared := "", false
	for _, attr := range el.Attr {
		switch {
		case attr.Space == "xmlns" && attr.Key == el.Space:
			ns, declared = attr.Value, true
		case attr.Space == "" && attr.Key == "xmlns" && el.Space == "":
			ns, declared = attr.Value, true
		}
	}
	if declared {
		return ns, nil
	}
	return parentCtx.LookupPrefix(el.Space)
}

// findOneChild finds the specified child element. Returns an error if the element doesn't exist.
func findOneChild(parentEl *etree.Element, childNS string, childTag string) (*etree.Element, error) {
	children, err := findChildren(parentEl, childNS, childTag)
	if err != nil {
		return nil, err
	}
	switch len(children) {
	case 0:
		return nil, classify(fmt.Errorf("cannot find %s:%s element", childNS, childTag), ErrMissingElement)
	case 1:
		return children[0], nil
	default:
		return nil, classify(fmt.Errorf("expected exactly one %s:%s element", childNS, childTag), ErrMalformedMessage)
	}
}

// receivedChildren returns the childNS/childTag children of read, and the
// children of received they correspond to, one for one. read is received
// itself, or received as rebuilt from what a signature on it covers (see
// validatedElement), which can lack namespace declarations received has,
// so that a signature on a child must be checked on its counterpart in
// received. Children are matched by position and must carry the same ID;
// if they cannot be matched, it is an error.
func receivedChildren(read, received *etree.Element, childNS, childTag string) ([]*etree.Element, []*etree.Element, error) {
	readEls, err := findChildren(read, childNS, childTag)
	if err != nil || read == received {
		return readEls, readEls, err
	}
	receivedEls, err := findChildren(received, childNS, childTag)
	if err != nil {
		return nil, nil, err
	}
	if len(readEls) != len(receivedEls) {
		return nil, nil, classify(fmt.Errorf("the signed %s has %d %s:%s elements, but %d were received", read.Tag, len(readEls), childNS, childTag, len(receivedEls)), ErrMalformedMessage)
	}
	for i := range readEls {
		if readEls[i].SelectAttrValue("ID", "") != receivedEls[i].SelectAttrValue("ID", "") {
			return nil, nil, classify(fmt.Errorf("the signed %s does not match the %s as received", childTag, childTag), ErrMalformedMessage)
		}
	}
	return readEls, receivedEls, nil
}

// findChild finds the specified child element. Returns (nil, nil) of the element doesn't exist.
func findChild(parentEl *etree.Element, childNS string, childTag string) (*etree.Element, error) {
	children, err := findChildren(parentEl, childNS, childTag)
	if err != nil {
		return nil, err
	}
	switch len(children) {
	case 0:
		return nil, nil
	case 1:
		return children[0], nil
	default:
		return nil, classify(fmt.Errorf("expected at most one %s:%s element", childNS, childTag), ErrMalformedMessage)
	}
}

// elementToBytes serializes el as a standalone document. Namespace
// declarations that el inherits from its ancestors are copied onto the
// serialized root, so prefixes (and the default namespace) used anywhere in
// el resolve to the same URIs they had in the original document.
func elementToBytes(el *etree.Element) ([]byte, error) {
	return elementCopyToBytes(elementWithNamespaces(el))
}

// elementWithNamespaces returns a copy of el that declares every namespace
// prefix it inherits from its ancestors.
func elementWithNamespaces(el *etree.Element) *etree.Element {
	root := el.Copy()

	declared := map[string]bool{}
	for _, attr := range root.Attr {
		if prefix, ok := namespaceDeclPrefix(attr); ok {
			declared[prefix] = true
		}
	}

	// Walk outward so the nearest declaration of each prefix wins.
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, attr := range p.Attr {
			prefix, ok := namespaceDeclPrefix(attr)
			if !ok || declared[prefix] {
				continue
			}
			declared[prefix] = true
			root.CreateAttr(attr.FullKey(), attr.Value)
		}
	}
	return root
}

func elementCopyToBytes(root *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(root)
	return doc.WriteToBytes()
}

// namespaceDeclPrefix reports whether attr is a namespace declaration and,
// if so, the prefix it declares ("" for the default namespace).
func namespaceDeclPrefix(attr etree.Attr) (string, bool) {
	switch {
	case attr.Space == "" && attr.Key == "xmlns":
		return "", true
	case attr.Space == "xmlns":
		return attr.Key, true
	default:
		return "", false
	}
}

// unmarshalElement serializes el into v by serializing el and then parsing it with xml.Unmarshal.
//
// el is untrusted: attribute fields are read only from unqualified
// attributes, never from namespace declarations or attributes in another
// namespace (see sanitizeAttributesForUnmarshal).
func unmarshalElement(el *etree.Element, v interface{}) error {
	root := elementWithNamespaces(el)
	sanitizeAttributesForUnmarshal(root)
	buf, err := elementCopyToBytes(root)
	if err != nil {
		return classify(err, ErrMalformedMessage)
	}
	return classify(xml.Unmarshal(buf, v), ErrMalformedMessage)
}

func elementToString(el *etree.Element) string {
	buf, err := elementToBytes(el)
	if err != nil {
		return ""
	}
	return string(buf)
}
