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
	"net/http"
	"net/url"
	"regexp"
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
	// signing, including keys held in a KMS or HSM. Decrypting encrypted
	// assertions still needs the private key in memory as an *rsa.PrivateKey.
	Key crypto.Signer

	// Certificate is the public part of Key.
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate

	// HTTPClient to use during SAML artifact resolution
	HTTPClient *http.Client

	// MetadataURL is the full URL to the metadata endpoint on this host,
	// i.e. https://example.com/saml/metadata
	MetadataURL url.URL

	// AcsURL is the full URL to the SAML Assertion Customer Service endpoint
	// on this host, i.e. https://example.com/saml/acs
	AcsURL url.URL

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

	// MetadataValidDuration is a duration used to calculate validUntil
	// attribute in the metadata endpoint
	MetadataValidDuration time.Duration

	// ForceAuthn allows you to force re-authentication of users even if the user
	// has a SSO session at the IdP.
	ForceAuthn *bool

	// RequestedAuthnContext allow you to specify the requested authentication
	// context in authentication requests
	RequestedAuthnContext *RequestedAuthnContext

	// AllowIdpInitiated
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

	// LogoutBindings specify the bindings available for SLO endpoint. If empty,
	// HTTP-POST binding is used.
	LogoutBindings []string

	// AssertionConsumerServiceBindings specify the bindings advertised for the
	// AssertionConsumerService endpoint in the SP metadata, in order of
	// preference. If empty, both HTTP-POST and HTTP-Artifact bindings are
	// advertised. Set this to []string{HTTPPostBinding} to stop advertising
	// the HTTP-Artifact binding, for example when the IDP does not publish an
	// ArtifactResolutionService or the SP cannot reach it.
	AssertionConsumerServiceBindings []string

	// ValidateAudienceRestriction allows you to override the default audience validation
	// for an assertion. If nil, the default audience validation is used.
	ValidateAudienceRestriction func(assertion *Assertion) error

	// ValidateRequestID allows you to override the default request ID validation.
	// If nil, the default request ID validation is used.
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
}

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

	var keyDescriptors []KeyDescriptor
	if sp.Certificate != nil {
		certBytes := sp.Certificate.Raw
		for _, intermediate := range sp.Intermediates {
			certBytes = append(certBytes, intermediate.Raw...)
		}
		keyDescriptors = []KeyDescriptor{
			{
				Use: "encryption",
				KeyInfo: KeyInfo{
					X509Data: X509Data{
						X509Certificates: []X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(certBytes)},
						},
					},
				},
				EncryptionMethods: []EncryptionMethod{
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
				},
			},
		}
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
		EntityID:   firstSet(sp.EntityID, sp.MetadataURL.String()),
		ValidUntil: validUntil,

		SPSSODescriptors: []SPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
						ValidUntil:                 &validUntil,
					},
					SingleLogoutServices: sloEndpoints,
					NameIDFormats:        []NameIDFormat{sp.AuthnNameIDFormat},
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
// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
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
			return nil, fmt.Errorf("cannot parse certificate: %s", err)
		}

		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
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
		return nil, fmt.Errorf("cannot validate signature on %s: fingerprint mismatch", el.Tag)
	}

	return []*x509.Certificate{cert}, nil

}

func parseCert(x509Data string) (*x509.Certificate, error) {
	// cleanup whitespace
	regex := regexp.MustCompile(`\s+`)
	certStr := regex.ReplaceAllString(x509Data, "")
	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, fmt.Errorf("parse cert, cannot base64 decode cert string: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert, cannot parse certificate: %w", err)
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
	}
	// We don't need to sign the XML document if the IDP uses HTTP-Redirect binding
	if len(sp.SignatureMethod) > 0 && binding == HTTPPostBinding {
		if err := sp.SignAuthnRequest(&req); err != nil {
			return nil, err
		}
	}
	return &req, nil
}

// GetSigningContext returns a dsig.SigningContext initialized based on the Service Provider's configuration
func GetSigningContext(sp *ServiceProvider) (*dsig.SigningContext, error) {
	if signerutil.IsNil(sp.Key) {
		return nil, fmt.Errorf("signature method %s requires a non-nil private key", sp.SignatureMethod)
	}
	if sp.Certificate == nil {
		return nil, errors.New("cannot sign: ServiceProvider.Certificate is nil")
	}

	keyPair := tls.Certificate{
		Certificate: [][]byte{sp.Certificate.Raw},
		PrivateKey:  sp.Key,
		Leaf:        sp.Certificate,
	}
	// TODO: add intermediates for SP
	// for _, cert := range sp.Intermediates {
	// 	keyPair.Certificate = append(keyPair.Certificate, cert.Raw)
	// }

	// Validate that the key type matches the signature method.
	// We check the public key type to support crypto.Signer implementations
	// (like KMS/HSM signers) that aren't literal *rsa.PrivateKey or *ecdsa.PrivateKey.
	pubKey := sp.Key.Public()
	switch sp.SignatureMethod {
	case dsig.RSASHA1SignatureMethod,
		dsig.RSASHA256SignatureMethod,
		dsig.RSASHA384SignatureMethod,
		dsig.RSASHA512SignatureMethod:
		if _, ok := pubKey.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("signature method %s requires an RSA key, got %T", sp.SignatureMethod, pubKey)
		}

	case dsig.ECDSASHA1SignatureMethod,
		dsig.ECDSASHA256SignatureMethod,
		dsig.ECDSASHA384SignatureMethod,
		dsig.ECDSASHA512SignatureMethod:
		if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("signature method %s requires an ECDSA key, got %T", sp.SignatureMethod, pubKey)
		}
	default:
		return nil, fmt.Errorf("invalid signing method %s", sp.SignatureMethod)
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
	if err := signingContext.SetSignatureMethod(sp.SignatureMethod); err != nil {
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
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLRequestForm').submit();</script>`))
	data := struct {
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		URL:         r.Destination,
		SAMLRequest: encodedReqBuf,
		RelayState:  relayState,
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
		retErr.PrivateErr = fmt.Errorf("cannot generate artifact resolution request: %s", err)
		return nil, retErr
	}

	requestBody, err := elementToBytes(artifactResolveRequest.SoapRequest())
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	req, err := http.NewRequestWithContext(ctx, "POST", sp.GetArtifactBindingLocation(SOAPBinding),
		bytes.NewReader(requestBody))
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	req.Header.Set("Content-Type", "text/xml")

	httpClient := sp.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(req)
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot resolve artifact: %s", err)
		return nil, retErr
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			logger.DefaultLogger.Printf("Error while closing response body during artifact resolution: %v", err)
		}
	}()
	if response.StatusCode != 200 {
		retErr.PrivateErr = fmt.Errorf("Error during artifact resolution: HTTP status %d (%s)", response.StatusCode, response.Status)
		return nil, retErr
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("Error during artifact resolution: %s", err)
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

	rawResponseBuf, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot parse base64: %s", err)
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
		retErr.PrivateErr = fmt.Errorf("invalid xml: %s", err)
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(soapResponseXML); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal response: %s", err)
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = errors.New("invalid xml: no root")
		return nil, retErr
	}
	if doc.Root().NamespaceURI() != "http://schemas.xmlsoap.org/soap/envelope/" ||
		doc.Root().Tag != "Envelope" {
		retErr.PrivateErr = fmt.Errorf("expected a SOAP Envelope")
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
			retErr.PrivateErr = fmt.Errorf("`InResponseTo` does not match the artifact request ID (expected %s)", artifactRequestID)
			return nil, retErr
		}
		if artifactResponse.IssueInstant.Add(MaxIssueDelay).Before(now) {
			retErr.PrivateErr = fmt.Errorf("response IssueInstant expired at %s", artifactResponse.IssueInstant.Add(MaxIssueDelay))
			return nil, retErr
		}
		if artifactResponse.Issuer != nil && artifactResponse.Issuer.Value != sp.IDPMetadata.EntityID {
			retErr.PrivateErr = fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
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
	now := sp.now()
	var err error
	retErr := &InvalidResponseError{
		Now:      now,
		Response: string(decodedResponseXML),
	}

	// ensure that the response XML is well-formed before we parse it
	if err := xrv.Validate(bytes.NewReader(decodedResponseXML)); err != nil {
		retErr.PrivateErr = fmt.Errorf("invalid xml: %s", err)
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(decodedResponseXML); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = errors.New("invalid xml: no root")
		return nil, retErr
	}

	assertion, err := sp.parseResponse(doc.Root(), possibleRequestIDs, now, signatureRequired, currentURL)
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
	if signatureRequirement == signatureRequired {
		responseSignatureErr = sp.validateSignature(responseEl)
		if responseSignatureErr != errSignatureElementNotPresent {
			responseHasSignature = true
		}

		// Note: we're deferring taking action on the signature validation until after we've
		// processed the request attributes, because certain test cases seem to require this mis-feature.
		// TODO(ross): adjust the test cases so that we can abort here if the Response signature is invalid.
	}

	// validate request attributes
	{
		var response Response
		if err := unmarshalElement(responseEl, &response); err != nil {
			return nil, fmt.Errorf("cannot unmarshal response: %v", err)
		}

		// If the response is *not* signed, the Destination may be omitted.
		if responseHasSignature || response.Destination != "" {
			// Per section 3.4.5.2 of the SAML spec, Destination must match the location at which the response was received, i.e. currentURL.
			// Historically, we checked against the SP's ACS URL instead of currentURL, which is usually the same but may differ in query params.
			// To mitigate the risk of switching to comparing against currentURL, we still allow it if the ACS URL matches, even if the current URL doesn't.
			if response.Destination != currentURL.String() && response.Destination != sp.AcsURL.String() {
				return nil, fmt.Errorf("`Destination` does not match requested URL or AcsURL (destination %q, requested %q, acs %q)", response.Destination, currentURL.String(), sp.AcsURL.String())
			}
		}

		if err := sp.validateRequestID(response, possibleRequestIDs); err != nil {
			return nil, err
		}

		if response.IssueInstant.Add(MaxIssueDelay).Before(now) {
			return nil, fmt.Errorf("response IssueInstant expired at %s", response.IssueInstant.Add(MaxIssueDelay))
		}
		if response.Issuer != nil && response.Issuer.Value != sp.IDPMetadata.EntityID {
			return nil, fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
		}
		if response.Status.StatusCode.Value != StatusSuccess {
			return nil, ErrBadStatus{Status: response.Status.StatusCode.Value}
		}
	}

	if signatureRequirement == signatureRequired {
		switch responseSignatureErr {
		case nil:
			// since the request has a signature, none of the Assertions need one
			signatureRequirement = signatureNotRequired
		case errSignatureElementNotPresent:
			// the request has no signature, so assertions must be signed
			signatureRequirement = signatureRequired // nop
		default:
			return nil, responseSignatureErr
		}
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
		return nil, fmt.Errorf("expected at least one valid Assertion, none found")
	}

	// if we have at least one assertion, return the first one. It is almost universally true that valid responses
	// contain only one assertion. This is less that fully correct, but we didn't realize that there could be more
	// than one assertion at the time of establishing the public interface of ParseXMLResponse(), so for compatibility
	// we return the first one.
	return &assertions[0], nil
}

func (sp *ServiceProvider) validateRequestID(response Response, possibleRequestIDs []string) error {
	if sp.ValidateRequestID != nil {
		return sp.ValidateRequestID(response, possibleRequestIDs)
	}

	requestIDvalid := false
	if sp.AllowIDPInitiated {
		requestIDvalid = true
	} else {
		for _, possibleRequestID := range possibleRequestIDs {
			if response.InResponseTo == possibleRequestID {
				requestIDvalid = true
			}
		}
	}
	if !requestIDvalid {
		return fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs)
	}
	return nil
}

func (sp *ServiceProvider) parseEncryptedAssertion(encryptedAssertionEl *etree.Element, possibleRequestIDs []string, now time.Time, signatureRequirement signatureRequirement) (*Assertion, error) {
	assertionEl, err := sp.decryptElement(encryptedAssertionEl)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt EncryptedAssertion: %v", err)
	}
	return sp.parseAssertion(assertionEl, possibleRequestIDs, now, signatureRequirement)
}

func (sp *ServiceProvider) decryptElement(encryptedEl *etree.Element) (*etree.Element, error) {
	encryptedDataEl, err := findOneChild(encryptedEl, "http://www.w3.org/2001/04/xmlenc#", "EncryptedData")
	if err != nil {
		return nil, err
	}

	var key interface{} = sp.Key
	keyEl := encryptedEl.FindElement("./EncryptedKey")
	if keyEl != nil {
		var err error
		key, err = xmlenc.Decrypt(sp.Key, keyEl)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key from response: %s", err)
		}
	}

	plaintextEl, err := xmlenc.Decrypt(key, encryptedDataEl)
	if err != nil {
		return nil, err
	}

	if err := xrv.Validate(bytes.NewReader(plaintextEl)); err != nil {
		return nil, fmt.Errorf("plaintext response contains invalid XML: %s", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plaintextEl); err != nil {
		return nil, fmt.Errorf("cannot parse plaintext response %v", err)
	}
	if doc.Root() == nil {
		return nil, errors.New("plaintext response contains no root element")
	}
	return doc.Root(), nil
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
	if assertion.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return fmt.Errorf("expired on %s", assertion.IssueInstant.Add(MaxIssueDelay))
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		return fmt.Errorf("issuer is not %q", sp.IDPMetadata.EntityID)
	}
	if assertion.Subject == nil {
		return fmt.Errorf("assertion has no Subject")
	}
	if assertion.Conditions == nil {
		return fmt.Errorf("assertion has no Conditions")
	}
	for _, subjectConfirmation := range assertion.Subject.SubjectConfirmations {
		if subjectConfirmation.SubjectConfirmationData == nil {
			return fmt.Errorf("assertion SubjectConfirmation has no SubjectConfirmationData")
		}
		requestIDvalid := false

		// We *DO NOT* validate InResponseTo when AllowIDPInitiated is set. Here's why:
		//
		// The SAML specification does not provide clear guidance for handling InResponseTo for IDP-initiated
		// requests where there is no request to be in response to. The specification says:
		//
		//   InResponseTo [Optional]
		//       The ID of a SAML protocol message in response to which an attesting entity can present the
		//       assertion. For example, this attribute might be used to correlate the assertion to a SAML
		//       request that resulted in its presentation.
		//
		// The initial thought was that we should specify a single empty string in possibleRequestIDs for IDP-initiated
		// requests so that we would ensure that an InResponseTo was *not* provided in those cases where it wasn't
		// expected. Even that turns out to be frustrating for users. And in practice some IDPs (e.g. Rippling)
		// set a specific non-empty value for InResponseTo in IDP-initiated requests.
		//
		// Finally, it is unclear that there is significant security value in checking InResponseTo when we allow
		// IDP initiated assertions.
		if !sp.AllowIDPInitiated {
			for _, possibleRequestID := range possibleRequestIDs {
				if subjectConfirmation.SubjectConfirmationData.InResponseTo == possibleRequestID {
					requestIDvalid = true
					break
				}
			}
			if !requestIDvalid {
				return fmt.Errorf("assertion SubjectConfirmation one of the possible request IDs (%v)", possibleRequestIDs)
			}
		}
		if subjectConfirmation.SubjectConfirmationData.Recipient != sp.AcsURL.String() {
			return fmt.Errorf("assertion SubjectConfirmation Recipient is not %s", sp.AcsURL.String())
		}
		if subjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Add(MaxClockSkew).Before(now) {
			return fmt.Errorf("assertion SubjectConfirmationData is expired")
		}
	}
	if !hasBearerSubjectConfirmation(assertion.Subject) {
		return fmt.Errorf("assertion has no bearer SubjectConfirmation")
	}
	if assertion.Conditions.NotBefore.Add(-MaxClockSkew).After(now) {
		return fmt.Errorf("assertion Conditions is not yet valid")
	}
	if assertion.Conditions.NotOnOrAfter.Add(MaxClockSkew).Before(now) {
		return fmt.Errorf("assertion Conditions is expired")
	}

	if err := sp.validateAudienceRestriction(assertion); err != nil {
		return err
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
			return fmt.Errorf("audience restriction validation failed: %w", err)
		}
		return nil
	}

	audience := firstSet(sp.EntityID, sp.MetadataURL.String())
	// An assertion with no AudienceRestriction is valid at every service
	// provider trusting the IdP, so one naming this SP is required.
	if len(assertion.Conditions.AudienceRestrictions) == 0 {
		return fmt.Errorf("assertion Conditions has no AudienceRestriction for %q", audience)
	}
	audienceRestrictionsValid := false
	for _, audienceRestriction := range assertion.Conditions.AudienceRestrictions {
		if audienceRestriction.Audience.Value == audience {
			audienceRestrictionsValid = true
		}
	}
	if !audienceRestrictionsValid {
		return fmt.Errorf("assertion Conditions AudienceRestriction does not contain %q", audience)
	}
	return nil
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

// validateSignature returns nil iff the Signature embedded in the element is valid
func (sp *ServiceProvider) validateSignature(el *etree.Element) error {
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
			return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
		}
	}
	if sp.IDPMetadata != nil && sp.IDPCertificateFingerprint != nil && sp.IDPCertificateFingerprintAlgorithm != nil && sp.IDPCertificate == nil {
		certs, err = sp.getCertBasedOnFingerprint(el)
		if err != nil {
			return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
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
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		if sigEl := el.FindElement("./Signature"); sigEl != nil {
			if keyInfo := sigEl.FindElement("KeyInfo"); keyInfo != nil {
				sigEl.RemoveChild(keyInfo)
			}
		}
	}

	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
	}
	el, err = etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
	}

	if sp.SignatureVerifier != nil {
		return sp.SignatureVerifier.VerifySignature(validationContext, el)
	}

	if _, err := validationContext.Validate(el); err != nil {
		return fmt.Errorf("cannot validate signature on %s: %v", el.Tag, err)
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

// MakeLogoutRequest produces a new LogoutRequest object for idpURL. If
// sp.SignatureMethod is set, the request carries an enveloped XML signature,
// which is what the HTTP-POST binding uses.
func (sp *ServiceProvider) MakeLogoutRequest(idpURL, nameID string) (*LogoutRequest, error) {
	req := sp.makeUnsignedLogoutRequest(idpURL, nameID)
	if sp.SignatureMethod != "" {
		if err := sp.SignLogoutRequest(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (sp *ServiceProvider) makeUnsignedLogoutRequest(idpURL, nameID string) *LogoutRequest {
	return &LogoutRequest{
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
}

// MakeRedirectLogoutRequest creates a SAML LogoutRequest using the
// HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the logout process.
//
// If sp.SignatureMethod is set, the request is signed with a query string
// signature (SigAlg and Signature parameters) as the binding requires
// (saml-bindings-2.0-os section 3.4.4.1), rather than with an enveloped XML
// signature.
func (sp *ServiceProvider) MakeRedirectLogoutRequest(nameID, relayState string) (*url.URL, error) {
	req := sp.makeUnsignedLogoutRequest(sp.GetSLOBindingLocation(HTTPRedirectBinding), nameID)
	encoded, err := deflateAndEncode(req.Element())
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(req.Destination, redirectParamSAMLRequest, encoded, relayState)
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
func (sp *ServiceProvider) MakePostLogoutRequest(nameID, relayState string) ([]byte, error) {
	req, err := sp.MakeLogoutRequest(sp.GetSLOBindingLocation(HTTPPostBinding), nameID)
	if err != nil {
		return nil, err
	}
	return req.Post(relayState), nil
}

// Post returns an HTML form suitable for using the HTTP-POST binding with the request
func (r *LogoutRequest) Post(relayState string) []byte {
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
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLRequestForm').submit();</script>`))
	data := struct {
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		URL:         r.Destination,
		SAMLRequest: encodedReqBuf,
		RelayState:  relayState,
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
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLResponseForm').submit();</script>`))
	data := struct {
		URL          string
		SAMLResponse string
		RelayState   string
	}{
		URL:          r.Destination,
		SAMLResponse: encodedReqBuf,
		RelayState:   relayState,
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

// ValidateLogoutResponseRequest validates the LogoutResponse content from the
// request, which may use either the HTTP-Redirect or the HTTP-POST binding.
//
// With the HTTP-Redirect binding the response must be signed, either with a
// query string signature (SigAlg and Signature parameters) or with an
// enveloped XML signature.
func (sp *ServiceProvider) ValidateLogoutResponseRequest(req *http.Request) error {
	if data := req.URL.Query().Get("SAMLResponse"); data != "" {
		return sp.validateLogoutResponseRedirectQuery(req.URL.RawQuery)
	}

	err := req.ParseForm()
	if err != nil {
		return fmt.Errorf("unable to parse form: %v", err)
	}

	return sp.ValidateLogoutResponseForm(req.PostForm.Get("SAMLResponse"))
}

// ValidateLogoutResponseForm returns a nil error if the logout response is valid.
func (sp *ServiceProvider) ValidateLogoutResponseForm(postFormData string) error {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	rawResponseBuf, err := base64.StdEncoding.DecodeString(postFormData)
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("unable to parse base64: %s", err)
		return retErr
	}
	retErr.Response = string(rawResponseBuf)

	// TODO(ross): add test case for this (SLO does not have tests right now)
	if err := xrv.Validate(bytes.NewReader(rawResponseBuf)); err != nil {
		return fmt.Errorf("response contains invalid XML: %s", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawResponseBuf); err != nil {
		retErr.PrivateErr = err
		return retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = errors.New("invalid xml: no root")
		return retErr
	}

	if err := sp.validateSignature(doc.Root()); err != nil {
		retErr.PrivateErr = err
		return retErr
	}

	var resp LogoutResponse
	if err := unmarshalElement(doc.Root(), &resp); err != nil {
		retErr.PrivateErr = err
		return retErr
	}
	return sp.validateLogoutResponse(&resp)
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
// URL Binding appears to be gzip / flate encoded
// See https://www.oasis-open.org/committees/download.php/20645/sstc-saml-tech-overview-2%200-draft-10.pdf  6.6
func (sp *ServiceProvider) ValidateLogoutResponseRedirect(queryParameterData string) error {
	return sp.validateLogoutResponseRedirectQuery(redirectParamSAMLResponse + "=" + url.QueryEscape(queryParameterData))
}

// validateLogoutResponseRedirectQuery validates a LogoutResponse received
// via the HTTP-Redirect binding. rawQuery is the URL's raw query string.
func (sp *ServiceProvider) validateLogoutResponseRedirectQuery(rawQuery string) error {
	retErr := &InvalidResponseError{
		Now: sp.now(),
	}

	root, err := sp.readRedirectBindingMessage(rawQuery, redirectParamSAMLResponse, retErr)
	if err != nil {
		return err
	}

	var resp LogoutResponse
	if err := unmarshalElement(root, &resp); err != nil {
		retErr.PrivateErr = err
		return retErr
	}
	return sp.validateLogoutResponse(&resp)
}

// validateLogoutResponse validates the LogoutResponse fields. Returns a nil error if the LogoutResponse is valid.
func (sp *ServiceProvider) validateLogoutResponse(resp *LogoutResponse) error {
	if resp.Destination != sp.SloURL.String() {
		return fmt.Errorf("`Destination` does not match SloURL (expected %q)", sp.SloURL.String())
	}

	now := sp.now()
	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return fmt.Errorf("issueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay))
	}
	if resp.Issuer == nil || resp.Issuer.Value != sp.IDPMetadata.EntityID {
		return fmt.Errorf("issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		return fmt.Errorf("status code was not %s", StatusSuccess)
	}

	return nil
}

// ValidateLogoutRequest validates a LogoutRequest sent by the IDP (IDP
// initiated single logout), using either the HTTP-Redirect or the HTTP-POST
// binding. It returns the request only if it is valid.
//
// The request must be signed by the IDP. With the HTTP-Redirect binding that
// is either a query string signature (SigAlg and Signature parameters) or an
// enveloped XML signature; with the HTTP-POST binding it is an enveloped XML
// signature.
//
// The caller should end the session identified by the returned request's
// NameID (and SessionIndex, if present) and then answer the IDP, for example
// with MakeRedirectLogoutResponse(req.ID, relayState).
func (sp *ServiceProvider) ValidateLogoutRequest(req *http.Request) (*LogoutRequest, error) {
	if data := req.URL.Query().Get(redirectParamSAMLRequest); data != "" {
		return sp.validateLogoutRequestRedirectQuery(req.URL.RawQuery)
	}

	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("unable to parse form: %v", err)
	}

	return sp.ValidateLogoutRequestForm(req.PostForm.Get(redirectParamSAMLRequest))
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
		retErr.PrivateErr = fmt.Errorf("unable to parse base64: %s", err)
		return nil, retErr
	}
	retErr.Response = string(rawRequestBuf)

	if err := xrv.Validate(bytes.NewReader(rawRequestBuf)); err != nil {
		return nil, fmt.Errorf("request contains invalid XML: %s", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawRequestBuf); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = errors.New("invalid xml: no root")
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
		return fmt.Errorf("`Destination` does not match SloURL (expected %q)", sp.SloURL.String())
	}

	now := sp.now()
	if req.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return fmt.Errorf("issueInstant expired at %s", req.IssueInstant.Add(MaxIssueDelay))
	}
	if req.IssueInstant.Add(-MaxClockSkew).After(now) {
		return fmt.Errorf("issueInstant %s is in the future", req.IssueInstant)
	}
	if req.NotOnOrAfter != nil && !now.Before(req.NotOnOrAfter.Add(MaxClockSkew)) {
		return fmt.Errorf("request expired at %s", req.NotOnOrAfter)
	}
	if req.Issuer == nil || req.Issuer.Value != sp.IDPMetadata.EntityID {
		return fmt.Errorf("issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return errors.New("request does not contain a NameID")
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
			return nil, fmt.Errorf("[%s]:%s cannot find prefix %s: %v", childNS, childTag, childEl.Space, err)
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
		return nil, fmt.Errorf("cannot find %s:%s element", childNS, childTag)
	case 1:
		return children[0], nil
	default:
		return nil, fmt.Errorf("expected exactly one %s:%s element", childNS, childTag)
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
		return nil, fmt.Errorf("expected at most one %s:%s element", childNS, childTag)
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
		return err
	}
	return xml.Unmarshal(buf, v)
}

func elementToString(el *etree.Element) string {
	buf, err := elementToBytes(el)
	if err != nil {
		return ""
	}
	return string(buf)
}
