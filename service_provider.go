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
	"regexp"
	"strconv"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

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

	// HTTPClient to use during SAML artifact resolution
	HTTPClient *http.Client

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
	// Only the "exact" Comparison (or an empty one, which means "exact") is
	// supported. The ordering that "minimum", "better" and "maximum" refer
	// to is defined by each deployment, not by the SAML specification
	// (saml-core §3.3.2.2.1), so with any other Comparison every assertion
	// is rejected rather than accepted unchecked.
	ValidateAuthnContextClassRef bool

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
	// If nil, the package-level TimeNow and Clock are used. Setting this
	// field instead of replacing those globals allows ServiceProviders with
	// different clocks to be used concurrently, for example in parallel
	// tests.
	Clock *dsig.Clock

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

	// ReplayCache, if set, records the ID of the assertion each accepted
	// response is accepted for, and refuses a response whose assertion it
	// has already recorded. Without it, a captured assertion is accepted
	// again until it expires, and an IdP-initiated one has no request ID to
	// tie it to a single use. If nil, assertions are not checked for replay.
	ReplayCache AssertionReplayCache
}

// AssertionReplayCache records the IDs of accepted assertions, so that each
// is accepted only once. Implementations must be safe for concurrent use, and
// should be shared by every server that accepts assertions for the same
// service provider.
type AssertionReplayCache interface {
	// Consume atomically records assertionID as used until expiresAt, the
	// last moment the ServiceProvider would accept the assertion; after
	// that the record may be dropped. It returns ErrAssertionReplayed if
	// assertionID is already recorded, and any other error if it cannot
	// record it. Any error refuses the assertion.
	Consume(assertionID string, expiresAt time.Time) error
}

// ErrAssertionReplayed is returned by an AssertionReplayCache for an
// assertion ID it has already recorded.
var ErrAssertionReplayed = errors.New("assertion has already been used")

// now returns the current time as seen by this ServiceProvider.
func (sp *ServiceProvider) now() time.Time {
	if sp.Clock != nil {
		return sp.Clock.Now().UTC()
	}
	return TimeNow()
}

// dsigClock returns the clock to use for signature validation. It may be
// nil, in which case dsig uses the real clock.
func (sp *ServiceProvider) dsigClock() *dsig.Clock {
	if sp.Clock != nil {
		return sp.Clock
	}
	return Clock
}

// MaxIssueDelay is the longest allowed time between when a SAML assertion is
// issued by the IDP and the time it is received by ParseResponse. This is used
// to prevent old responses from being replayed (while allowing for some clock
// drift between the SP and IDP).
var MaxIssueDelay = time.Second * 90

// MaxClockSkew allows for leeway for clock skew between the IDP and SP when
// validating assertions. It defaults to 180 seconds (matches shibboleth).
var MaxClockSkew = time.Second * 180

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
	} else if sp.Certificate != nil {
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
			EncryptionMethods: []EncryptionMethod{
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
				{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
				{Algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep"},
			},
		})
	}

	if sp.Certificate != nil {
		if len(sp.SignatureMethod) > 0 {
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
// saml-bindings-2.0-os section 3.4.4.1.
func (r *AuthnRequest) Redirect(relayState string, sp *ServiceProvider) (*url.URL, error) {
	encoded, err := deflateAndEncode(r.Element())
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(r.Destination, redirectParamSAMLRequest, encoded, relayState)
}

// GetSSOBindingLocation returns URL for the IDP's Single Sign On Service binding
// of the specified type (HTTPRedirectBinding, HTTPPostBinding or
// HTTPPostSimpleSignBinding)
func (sp *ServiceProvider) GetSSOBindingLocation(binding string) string {
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
// specified type
func (sp *ServiceProvider) GetArtifactBindingLocation(binding string) string {
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, artifactResolutionService := range idpSSODescriptor.ArtifactResolutionServices {
			if artifactResolutionService.Binding == binding {
				return artifactResolutionService.Location
			}
		}
	}
	return ""
}

// GetSLOBindingLocation returns URL for the IDP's Single Log Out Service binding
// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
func (sp *ServiceProvider) GetSLOBindingLocation(binding string) string {
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
	var certStrs []string

	// We need to include non-empty certs where the "use" attribute is
	// either set to "signing" or is missing
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, keyDescriptor := range idpSSODescriptor.KeyDescriptors {
			if len(keyDescriptor.KeyInfo.X509Data.X509Certificates) != 0 {
				switch keyDescriptor.Use {
				case "", "signing":
					for _, certificate := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
						certStrs = append(certStrs, certificate.Data)
					}
				}
			}
		}
	}

	if len(certStrs) == 0 {
		return nil, errors.New("cannot find any signing certificate in the IDP SSO descriptor")
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
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
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
		ID:                          fmt.Sprintf("id-%x", randomBytes(20)),
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
	signatureMethod := sp.SignatureMethod
	if signatureMethod == "" && !signerutil.IsNil(sp.Key) {
		signatureMethod = defaultSignatureMethod(sp.Key.Public())
	}
	signingContext, err := sp.signingContext(signatureMethod)
	if err != nil {
		return nil, err
	}
	return signMetadata(sp.Metadata(), signingContext)
}

// GetSigningContext returns a dsig.SigningContext initialized based on the Service Provider's configuration
func GetSigningContext(sp *ServiceProvider) (*dsig.SigningContext, error) {
	return sp.signingContext(sp.SignatureMethod)
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
	Status string
}

func (e ErrBadStatus) Error() string {
	return e.Status
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

	req, err := http.NewRequestWithContext(ctx, "POST", sp.GetArtifactBindingLocation(SOAPBinding),
		bytes.NewReader(requestBody))
	if err != nil {
		retErr.PrivateErr = classify(err, ErrArtifactResolution)
		return nil, retErr
	}
	req.Header.Set("Content-Type", "text/xml")

	httpClient := sp.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(req)
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
	assertion, err := sp.ParseXMLArtifactResponse(responseBody, possibleRequestIDs, artifactResolveRequest.ID, *req.URL)
	if err != nil {
		return nil, err
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
	if err := xrv.Validate(bytes.NewReader(soapResponseXML)); err != nil {
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
		if artifactResponse.InResponseTo != artifactRequestID {
			retErr.PrivateErr = classify(fmt.Errorf("`InResponseTo` does not match the artifact request ID (expected %s)", artifactRequestID), ErrRequestIDMismatch)
			return nil, retErr
		}
		if artifactResponse.IssueInstant.Add(MaxIssueDelay).Before(now) {
			retErr.PrivateErr = classify(fmt.Errorf("response IssueInstant expired at %s", artifactResponse.IssueInstant.Add(MaxIssueDelay)), ErrExpired)
			return nil, retErr
		}
		if artifactResponse.Issuer != nil && artifactResponse.Issuer.Value != sp.IDPMetadata.EntityID {
			retErr.PrivateErr = classify(fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
			return nil, retErr
		}
		if artifactResponse.Status.StatusCode.Value != StatusSuccess {
			retErr.PrivateErr = ErrBadStatus{Status: artifactResponse.Status.StatusCode.Value}
			return nil, retErr
		}
	}

	var signatureRequirement signatureRequirement
	sigErr := sp.validateSignature(artifactResponseEl)
	switch sigErr {
	case nil:
		signatureRequirement = signatureNotRequired
	case errSignatureElementNotPresent:
		signatureRequirement = signatureRequired
	default:
		retErr.PrivateErr = sigErr
		return nil, retErr
	}

	responseEl, err := findOneChild(artifactResponseEl, "urn:oasis:names:tc:SAML:2.0:protocol", "Response")
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	assertion, err := sp.parseResponse(responseEl, possibleRequestIDs, now, signatureRequirement, currentURL)
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
// and properties are met.
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
	if err := xrv.Validate(bytes.NewReader(decodedResponseXML)); err != nil {
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
	var responseSignatureErr error
	var responseHasSignature bool
	switch signatureRequirement {
	case signatureRequired:
		responseSignatureErr = sp.validateSignature(responseEl)
		switch responseSignatureErr {
		case nil:
			responseHasSignature = true
		case errSignatureElementNotPresent:
			// the Response is not signed, so each Assertion must be (checked below)
		default:
			// A Signature is present but invalid: reject the Response before
			// looking at any of its other contents.
			return nil, responseSignatureErr
		}
	case signatureVerifiedByBinding:
		responseHasSignature = true
		if err := sp.validateSignature(responseEl); err != nil && err != errSignatureElementNotPresent {
			return nil, err
		}
		signatureRequirement = signatureNotRequired
	}

	// validate request attributes
	{
		var response Response
		if err := unmarshalElement(responseEl, &response); err != nil {
			return nil, classify(fmt.Errorf("cannot unmarshal response: %w", err), ErrMalformedMessage)
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

		if response.IssueInstant.Add(MaxIssueDelay).Before(now) {
			return nil, classify(fmt.Errorf("response IssueInstant expired at %s", response.IssueInstant.Add(MaxIssueDelay)), ErrExpired)
		}
		if response.Issuer != nil && response.Issuer.Value != sp.IDPMetadata.EntityID {
			return nil, classify(fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
		}
		if response.Status.StatusCode.Value != StatusSuccess {
			return nil, ErrBadStatus{Status: response.Status.StatusCode.Value}
		}
	}

	if responseHasSignature {
		// since the Response has a valid signature, none of the Assertions need one
		signatureRequirement = signatureNotRequired
	}

	var errs []error
	var assertions []Assertion

	// look for encrypted assertions
	{
		encryptedAssertionEls, err := findChildren(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion")
		if err != nil {
			return nil, err
		}
		for _, encryptedAssertionEl := range encryptedAssertionEls {
			assertion, err := sp.parseEncryptedAssertion(encryptedAssertionEl, possibleRequestIDs, now, signatureRequirement)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			assertions = append(assertions, *assertion)
		}
	}

	// look for plaintext assertions
	{
		assertionEls, err := findChildren(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
		if err != nil {
			return nil, err
		}
		for _, assertionEl := range assertionEls {
			assertion, err := sp.parseAssertion(assertionEl, possibleRequestIDs, now, signatureRequirement)
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
		for _, possibleRequestID := range possibleRequestIDs {
			if response.InResponseTo == possibleRequestID {
				requestIDvalid = true
			}
		}
	}
	if !requestIDvalid {
		return classify(fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs), ErrRequestIDMismatch)
	}
	return nil
}

func (sp *ServiceProvider) parseEncryptedAssertion(encryptedAssertionEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement) (*Assertion, error) {
	assertionEl, err := sp.decryptElement(encryptedAssertionEl)
	if err != nil {
		return nil, classify(fmt.Errorf("failed to decrypt EncryptedAssertion: %w", err), ErrDecryptionFailed)
	}
	return sp.parseAssertion(assertionEl, possibleRequestIDs, now, signatureRequirement)
}

func (sp *ServiceProvider) decryptElement(encryptedEl *etree.Element) (*etree.Element, error) {
	encryptedDataEl, err := findOneChild(encryptedEl, "http://www.w3.org/2001/04/xmlenc#", "EncryptedData")
	if err != nil {
		return nil, err
	}

	var decryptionKey interface{} = sp.Key
	decryptionKeyName := "Key"
	if sp.EncryptionKey != nil {
		decryptionKey = sp.EncryptionKey
		decryptionKeyName = "EncryptionKey"
	}

	plaintextEl, err := decryptWithKey(decryptionKey, encryptedEl, encryptedDataEl)
	if err != nil && len(sp.DecryptionKeys) > 0 {
		// Key transport is RSA-OAEP only, which fails the same way for every
		// wrong key, so trying several keys reveals no more than trying one.
		errs := []error{fmt.Errorf("%s: %w", decryptionKeyName, err)}
		for i, k := range sp.DecryptionKeys {
			var keyErr error
			if plaintextEl, keyErr = decryptWithKey(k, encryptedEl, encryptedDataEl); keyErr == nil {
				err = nil
				break
			}
			errs = append(errs, fmt.Errorf("DecryptionKeys[%d]: %w", i, keyErr))
		}
		if err != nil {
			err = fmt.Errorf("no decryption key could decrypt it: %w", errors.Join(errs...))
		}
	}
	if err != nil {
		return nil, err
	}

	if err := xrv.Validate(bytes.NewReader(plaintextEl)); err != nil {
		return nil, classify(fmt.Errorf("plaintext response contains invalid XML: %w", err), ErrMalformedMessage)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plaintextEl); err != nil {
		return nil, classify(fmt.Errorf("cannot parse plaintext response %w", err), ErrMalformedMessage)
	}
	if doc.Root() == nil {
		return nil, classify(errors.New("plaintext response contains no root element"), ErrMalformedMessage)
	}
	return doc.Root(), nil
}

// decryptWithKey decrypts encryptedDataEl, the EncryptedData child of
// encryptedEl, with decryptionKey. The content key is wrapped in an
// EncryptedKey either beside the EncryptedData or inside its KeyInfo.
func decryptWithKey(decryptionKey interface{}, encryptedEl, encryptedDataEl *etree.Element) ([]byte, error) {
	key := decryptionKey
	keyEl := encryptedEl.FindElement("./EncryptedKey")
	if keyEl != nil {
		var err error
		key, err = xmlenc.Decrypt(decryptionKey, keyEl)
		if err != nil {
			return nil, classify(fmt.Errorf("failed to decrypt key from response: %w", err), ErrDecryptionFailed)
		}
	}
	return xmlenc.Decrypt(key, encryptedDataEl)
}

func (sp *ServiceProvider) parseAssertion(assertionEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement) (*Assertion, error) {
	if signatureRequirement == signatureRequired {
		sigErr := sp.validateSignature(assertionEl)
		if sigErr != nil {
			return nil, sigErr
		}
	}

	// parse the assertion we just validated
	var assertion Assertion
	if err := unmarshalElement(assertionEl, &assertion); err != nil {
		return nil, err
	}

	if err := sp.validateAssertion(&assertion, possibleRequestIDs, now); err != nil {
		return nil, err
	}

	return &assertion, nil
}

// validateAssertion checks that the conditions specified in assertion match
// the requirements to accept. If validation fails, it returns an error describing
// the failure. (The digital signature on the assertion is not checked -- this
// should be done before calling this function).
func (sp *ServiceProvider) validateAssertion(assertion *Assertion, possibleRequestIDs []string, now time.Time) error {
	if issueDeadline(assertion).Before(now) {
		return classify(fmt.Errorf("expired on %s", issueDeadline(assertion)), ErrExpired)
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer is not %q", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	if assertion.Subject == nil {
		return classify(fmt.Errorf("assertion has no Subject"), ErrMissingElement)
	}
	if assertion.Conditions == nil {
		return classify(fmt.Errorf("assertion has no Conditions"), ErrMissingElement)
	}
	for _, subjectConfirmation := range assertion.Subject.SubjectConfirmations {
		if subjectConfirmation.SubjectConfirmationData == nil {
			return classify(fmt.Errorf("assertion SubjectConfirmation has no SubjectConfirmationData"), ErrMissingElement)
		}
		if err := sp.validateAssertionInResponseTo(subjectConfirmation.SubjectConfirmationData.InResponseTo, possibleRequestIDs); err != nil {
			return err
		}
		if subjectConfirmation.SubjectConfirmationData.Recipient != sp.AcsURL.String() {
			return classify(fmt.Errorf("assertion SubjectConfirmation Recipient is not %s", sp.AcsURL.String()), ErrDestinationMismatch)
		}
		// saml-profiles §4.1.4.2 says a bearer SubjectConfirmationData MUST
		// NOT carry NotBefore, but some IdPs send one anyway; accept it as
		// long as it is not in the future (saml-core §2.4.1.2). An omitted
		// NotBefore is the zero time, which always passes.
		if subjectConfirmation.SubjectConfirmationData.NotBefore.Add(-MaxClockSkew).After(now) {
			return classify(fmt.Errorf("assertion SubjectConfirmationData is not yet valid"), ErrNotYetValid)
		}
		if skewedDeadline(subjectConfirmation.SubjectConfirmationData.NotOnOrAfter).Before(now) {
			return classify(fmt.Errorf("assertion SubjectConfirmationData is expired"), ErrExpired)
		}
	}
	if !hasBearerSubjectConfirmation(assertion.Subject) {
		return classify(fmt.Errorf("assertion has no bearer SubjectConfirmation"), ErrMissingElement)
	}
	if assertion.Conditions.NotBefore.Add(-MaxClockSkew).After(now) {
		return classify(fmt.Errorf("assertion Conditions is not yet valid"), ErrNotYetValid)
	}
	if skewedDeadline(assertion.Conditions.NotOnOrAfter).Before(now) {
		return classify(fmt.Errorf("assertion Conditions is expired"), ErrExpired)
	}

	if err := sp.validateAudienceRestriction(assertion); err != nil {
		return err
	}
	if err := sp.validateAuthnContextClassRef(assertion); err != nil {
		return err
	}
	return nil
}

// validateAuthnContextClassRef checks, if ValidateAuthnContextClassRef is
// set, that one of the assertion's AuthnStatements has an
// AuthnContextClassRef listed in RequestedAuthnContext.
func (sp *ServiceProvider) validateAuthnContextClassRef(assertion *Assertion) error {
	if !sp.ValidateAuthnContextClassRef || sp.RequestedAuthnContext == nil {
		return nil
	}
	requested := sp.RequestedAuthnContext.ClassRefs()
	if len(requested) == 0 {
		return nil
	}
	if comparison := sp.RequestedAuthnContext.Comparison; comparison != "" && comparison != "exact" {
		return classify(fmt.Errorf("cannot validate AuthnContextClassRef for RequestedAuthnContext Comparison %q: only \"exact\" is supported", comparison), ErrUnsupported)
	}
	var got []string
	for _, authnStatement := range assertion.AuthnStatements {
		classRef := authnStatement.AuthnContext.AuthnContextClassRef
		if classRef == nil {
			continue
		}
		for _, want := range requested {
			if classRef.Value == want {
				return nil
			}
		}
		got = append(got, classRef.Value)
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
		if inResponseTo == possibleRequestID {
			return nil
		}
	}
	return classify(fmt.Errorf("assertion SubjectConfirmation one of the possible request IDs (%v)", possibleRequestIDs), ErrRequestIDMismatch)
}

// issueDeadline is the last moment validateAssertion accepts assertion by its
// IssueInstant.
func issueDeadline(assertion *Assertion) time.Time {
	return assertion.IssueInstant.Add(MaxIssueDelay)
}

// skewedDeadline is the last moment validateAssertion accepts a NotOnOrAfter
// time, allowing for clock skew.
func skewedDeadline(notOnOrAfter time.Time) time.Time {
	return notOnOrAfter.Add(MaxClockSkew)
}

// acceptableUntil returns the last moment validateAssertion accepts
// assertion: the earliest of the deadlines its expiry checks apply.
func acceptableUntil(assertion *Assertion) time.Time {
	deadline := issueDeadline(assertion)
	if assertion.Conditions != nil {
		deadline = earliest(deadline, skewedDeadline(assertion.Conditions.NotOnOrAfter))
	}
	if assertion.Subject != nil {
		for _, confirmation := range assertion.Subject.SubjectConfirmations {
			if confirmation.SubjectConfirmationData != nil {
				deadline = earliest(deadline, skewedDeadline(confirmation.SubjectConfirmationData.NotOnOrAfter))
			}
		}
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
	if err := sp.ReplayCache.Consume(assertion.ID, acceptableUntil(assertion)); err != nil {
		return fmt.Errorf("assertion %q: %w", assertion.ID, err)
	}
	return nil
}

// bearerSubjectConfirmationMethod is the SubjectConfirmation Method of the
// SAML web browser SSO profile.
const bearerSubjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // not a credential

// hasBearerSubjectConfirmation reports whether subject has the bearer
// SubjectConfirmation the web browser SSO profile requires (saml-profiles
// §4.1.4.2). Without one, the Recipient, InResponseTo and expiry checks on
// SubjectConfirmationData never run.
func hasBearerSubjectConfirmation(subject *Subject) bool {
	if subject == nil {
		return false
	}
	for _, subjectConfirmation := range subject.SubjectConfirmations {
		if subjectConfirmation.Method == bearerSubjectConfirmationMethod {
			return true
		}
	}
	return false
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

// validateWithEachCert validates the signature on el against each of certs
// in turn, with a copy of base that trusts only that certificate, and
// returns nil as soon as one of them verifies it. Otherwise it returns the
// error from the last certificate tried.
func validateWithEachCert(base *dsig.ValidationContext, certs []*x509.Certificate, el *etree.Element) error {
	var err error
	for _, cert := range certs {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{cert},
		})
		ctx.IdAttribute = base.IdAttribute
		ctx.Clock = base.Clock
		if _, err = ctx.Validate(el); err == nil {
			return nil
		}
	}
	return err
}

// validateSignature returns nil iff the Signature embedded in the element is valid
//
// Every error other than errSignatureElementNotPresent matches
// ErrInvalidSignature with errors.Is, and also ErrUntrustedCertificate or
// ErrCertificateNotValidNow when that is why validation failed.
func (sp *ServiceProvider) validateSignature(el *etree.Element) error {
	err := sp.validateSignatureUnclassified(el)
	if err == nil || err == errSignatureElementNotPresent {
		return err
	}
	return classify(err, ErrInvalidSignature)
}

func (sp *ServiceProvider) validateSignatureUnclassified(el *etree.Element) error {
	sigEl, err := findChild(el, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return err
	}
	if sigEl == nil {
		return errSignatureElementNotPresent
	}

	var certs []*x509.Certificate
	if sp.IDPMetadata != nil && sp.IDPCertificateFingerprint == nil && sp.IDPCertificateFingerprintAlgorithm == nil && sp.IDPCertificate == nil {
		certs, err = sp.getIDPSigningCerts()
		if err != nil {
			return fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
		}
	}
	if sp.IDPMetadata != nil && sp.IDPCertificateFingerprint != nil && sp.IDPCertificateFingerprintAlgorithm != nil && sp.IDPCertificate == nil {
		certs, err = sp.getCertBasedOnFingerprint(el)
		if err != nil {
			return fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
		}
	}
	if sp.IDPMetadata != nil && sp.IDPCertificateFingerprint == nil && sp.IDPCertificateFingerprintAlgorithm == nil && sp.IDPCertificate != nil {
		cert, err := parseCert(*sp.IDPCertificate)
		if err != nil {
			return fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return fmt.Errorf("cannot validate signature on %s: saml config not set up properly, specify either idp metadata url, fingerprints or actual certificate", el.Tag)
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
		return fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}
	// NSDetatch returns a nil element with its error, so the tag is kept above.
	el, err = etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %w", tag, err)
	}

	if sp.SignatureVerifier != nil {
		return sp.SignatureVerifier.VerifySignature(validationContext, el)
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
		if err := validateWithEachCert(validationContext, certs, el); err != nil {
			return fmt.Errorf("cannot validate signature on %s: %w", tag, err)
		}
		return nil
	}

	if _, err := validationContext.Validate(el); err != nil {
		err = fmt.Errorf("cannot validate signature on %s: %w", tag, err)
		if kind := classifyCertificate(el, certs, validationContext.Clock.Now()); kind != nil {
			return classify(err, kind)
		}
		return err
	}

	return nil
}

// SignLogoutRequest adds the `Signature` element to the `LogoutRequest`.
func (sp *ServiceProvider) SignLogoutRequest(req *LogoutRequest) error {
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
			req.SessionIndex = nil
			return
		}
		req.SessionIndex = &SessionIndex{Value: sessionIndex}
	}
}

// MakeLogoutRequest produces a new LogoutRequest object for idpURL. If
// sp.SignatureMethod is set, the request carries an enveloped XML signature,
// which is what the HTTP-POST binding uses.
func (sp *ServiceProvider) MakeLogoutRequest(idpURL, nameID string, opts ...LogoutRequestOption) (*LogoutRequest, error) {
	req := sp.makeUnsignedLogoutRequest(idpURL, nameID, opts...)
	if sp.SignatureMethod != "" {
		if err := sp.SignLogoutRequest(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (sp *ServiceProvider) makeUnsignedLogoutRequest(idpURL, nameID string, opts ...LogoutRequestOption) *LogoutRequest {
	req := &LogoutRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
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

// MakeRedirectLogoutRequest creates a SAML LogoutRequest using the
// HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the logout process.
//
// If sp.SignatureMethod is set, the request is signed with a query string
// signature (SigAlg and Signature parameters) as the binding requires
// (saml-bindings-2.0-os section 3.4.4.1), rather than with an enveloped XML
// signature.
func (sp *ServiceProvider) MakeRedirectLogoutRequest(nameID, relayState string, opts ...LogoutRequestOption) (*url.URL, error) {
	req := sp.makeUnsignedLogoutRequest(sp.GetSLOBindingLocation(HTTPRedirectBinding), nameID, opts...)
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
	unsigned := *req
	unsigned.Signature = nil
	encoded, err := deflateAndEncode(unsigned.Element())
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(unsigned.Destination, redirectParamSAMLRequest, encoded, relayState)
}

// Redirect returns a URL suitable for using the redirect binding with the
// request. The URL carries no query string signature; use
// ServiceProvider.MakeRedirectLogoutRequest to produce a signed one.
func (r *LogoutRequest) Redirect(relayState string) *url.URL {
	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())
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
// logoutRequestID. If sp.SignatureMethod is set, the response carries an
// enveloped XML signature, which is what the HTTP-POST binding uses.
func (sp *ServiceProvider) MakeLogoutResponse(idpURL, logoutRequestID string) (*LogoutResponse, error) {
	response := sp.makeUnsignedLogoutResponse(idpURL, logoutRequestID)
	if sp.SignatureMethod != "" {
		if err := sp.SignLogoutResponse(response); err != nil {
			return nil, err
		}
	}
	return response, nil
}

func (sp *ServiceProvider) makeUnsignedLogoutResponse(idpURL, logoutRequestID string) *LogoutResponse {
	return &LogoutResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: logoutRequestID,
		Version:      "2.0",
		IssueInstant: sp.now(),
		Destination:  idpURL,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(sp.EntityID, sp.MetadataURL.String()),
		},
		Status: Status{
			StatusCode: StatusCode{
				Value: StatusSuccess,
			},
		},
	}
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
	resp := sp.makeUnsignedLogoutResponse(sp.GetSLOBindingLocation(HTTPRedirectBinding), logoutRequestID)
	encoded, err := deflateAndEncode(resp.Element())
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(resp.Destination, redirectParamSAMLResponse, encoded, relayState)
}

// Redirect returns a URL suitable for using the redirect binding with the
// LogoutResponse. The URL carries no query string signature; use
// ServiceProvider.MakeRedirectLogoutResponse to produce a signed one.
func (r *LogoutResponse) Redirect(relayState string) *url.URL {
	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())
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
	resp, err := sp.MakeLogoutResponse(sp.GetSLOBindingLocation(HTTPPostBinding), logoutRequestID)
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
	signingContext, err := GetSigningContext(sp)
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
		// Spec defines an empty value as "unspecified" so don't set one.
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
func (sp *ServiceProvider) ParseLogoutResponse(req *http.Request, possibleRequestIDs []string) (*LogoutResponse, error) {
	resp, err := sp.parseLogoutResponseRequest(req)
	if err != nil {
		return nil, err
	}
	for _, possibleRequestID := range possibleRequestIDs {
		if possibleRequestID != "" && resp.InResponseTo == possibleRequestID {
			return resp, nil
		}
	}
	return nil, classify(fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs), ErrRequestIDMismatch)
}

func (sp *ServiceProvider) parseLogoutResponseRequest(req *http.Request) (*LogoutResponse, error) {
	if data := req.URL.Query().Get("SAMLResponse"); data != "" {
		return sp.validateLogoutResponseRedirectQuery(req.URL.RawQuery)
	}

	err := req.ParseForm()
	if err != nil {
		return nil, classify(fmt.Errorf("unable to parse form: %w", err), ErrMalformedMessage)
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
		return nil, err
	}
	return &resp, nil
}

// ValidateLogoutResponseForm returns a nil error if the logout response is valid.
//
// It does not check the response's InResponseTo; see ParseLogoutResponse.
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

	// TODO(ross): add test case for this (SLO does not have tests right now)
	if err := xrv.Validate(bytes.NewReader(rawResponseBuf)); err != nil {
		return nil, classify(fmt.Errorf("response contains invalid XML: %w", err), ErrMalformedMessage)
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

	if err := sp.validateSignature(doc.Root()); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	var resp LogoutResponse
	if err := unmarshalElement(doc.Root(), &resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if err := sp.validateLogoutResponse(&resp); err != nil {
		return nil, err
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
		return nil, err
	}
	return &resp, nil
}

// validateLogoutResponse validates the LogoutResponse fields. Returns a nil error if the LogoutResponse is valid.
func (sp *ServiceProvider) validateLogoutResponse(resp *LogoutResponse) error {
	if resp.Destination != sp.SloURL.String() {
		return classify(fmt.Errorf("`Destination` does not match SloURL (expected %q)", sp.SloURL.String()), ErrDestinationMismatch)
	}

	now := sp.now()
	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return classify(fmt.Errorf("issueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay)), ErrExpired)
	}
	if resp.Issuer == nil || resp.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		return classify(fmt.Errorf("status code was not %s", StatusSuccess), ErrBadStatus{Status: resp.Status.StatusCode.Value})
	}

	return nil
}

// ValidateLogoutRequest validates a LogoutRequest sent by the IDP (IDP
// initiated single logout), using the HTTP-Redirect, HTTP-POST or
// HTTP-POST-SimpleSign binding. It returns the request only if it is valid.
//
// The request must be signed by the IDP. With the HTTP-Redirect binding that
// is either a query string signature (SigAlg and Signature parameters) or an
// enveloped XML signature; with the HTTP-POST binding it is an enveloped XML
// signature. A posted form that carries a SigAlg or Signature field is an
// HTTP-POST-SimpleSign message and must have a valid SimpleSign signature
// (an enveloped XML signature it also carries must be valid too).
//
// The caller should end the session identified by the returned request's
// NameID (and SessionIndex, if present) and then answer the IDP, for example
// with MakeRedirectLogoutResponse(req.ID, relayState).
func (sp *ServiceProvider) ValidateLogoutRequest(req *http.Request) (*LogoutRequest, error) {
	if data := req.URL.Query().Get(redirectParamSAMLRequest); data != "" {
		return sp.validateLogoutRequestRedirectQuery(req.URL.RawQuery)
	}

	if err := req.ParseForm(); err != nil {
		return nil, classify(fmt.Errorf("unable to parse form: %w", err), ErrMalformedMessage)
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

	if err := xrv.Validate(bytes.NewReader(rawRequestBuf)); err != nil {
		return nil, classify(fmt.Errorf("request contains invalid XML: %w", err), ErrMalformedMessage)
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

	if err := sp.validateSignature(doc.Root()); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	return sp.unmarshalAndValidateLogoutRequest(doc.Root(), retErr)
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
	return &req, nil
}

// validateLogoutRequest validates the LogoutRequest fields. Returns a nil error if the LogoutRequest is valid.
func (sp *ServiceProvider) validateLogoutRequest(req *LogoutRequest) error {
	if req.Destination != sp.SloURL.String() {
		return classify(fmt.Errorf("`Destination` does not match SloURL (expected %q)", sp.SloURL.String()), ErrDestinationMismatch)
	}

	now := sp.now()
	if req.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return classify(fmt.Errorf("issueInstant expired at %s", req.IssueInstant.Add(MaxIssueDelay)), ErrExpired)
	}
	if req.IssueInstant.Add(-MaxClockSkew).After(now) {
		return classify(fmt.Errorf("issueInstant %s is in the future", req.IssueInstant), ErrNotYetValid)
	}
	if req.NotOnOrAfter != nil && !now.Before(req.NotOnOrAfter.Add(MaxClockSkew)) {
		return classify(fmt.Errorf("request expired at %s", req.NotOnOrAfter), ErrExpired)
	}
	if req.Issuer == nil || req.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return classify(errors.New("request does not contain a NameID"), ErrMissingElement)
	}

	return nil
}

func firstSet(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

// findChildren returns all the elements matching childNS/childTag that are direct children of parentEl.
func findChildren(parentEl *etree.Element, childNS string, childTag string) ([]*etree.Element, error) {
	//nolint:prealloc // We don't know how many child elements we'll actually put into this array.
	var rv []*etree.Element
	for _, childEl := range parentEl.ChildElements() {
		if childEl.Tag != childTag {
			continue
		}

		ctx, err := etreeutils.NSBuildParentContext(childEl)
		if err != nil {
			return nil, err
		}
		ctx, err = ctx.SubContext(childEl)
		if err != nil {
			return nil, err
		}

		ns, err := ctx.LookupPrefix(childEl.Space)
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
func unmarshalElement(el *etree.Element, v interface{}) error {
	buf, err := elementToBytes(el)
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
