package saml

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/attrname"
	"github.com/crewjam/saml/internal/xmlroundtrip"

	"github.com/crewjam/saml/internal/signerutil"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/xmlenc"
)

// Session represents a user session. It is returned by the
// SessionProvider implementation's GetSession method. Fields here
// are used to set fields in the SAML assertion.
type Session struct {
	ID         string
	CreateTime time.Time
	ExpireTime time.Time
	Index      string

	NameID       string
	NameIDFormat string
	SubjectID    string

	Groups                 []string
	UserName               string
	UserEmail              string
	UserCommonName         string
	UserSurname            string
	UserGivenName          string
	UserScopedAffiliation  string
	EduPersonPrincipalName string `json:",omitempty"`

	// AuthnContextClassRef is the authentication context class the user
	// was actually authenticated with, such as
	// "urn:oasis:names:tc:SAML:2.0:ac:classes:X509". DefaultAssertionMaker
	// asserts it in the AuthnStatement. When empty, PasswordProtectedTransport
	// is asserted, as before. See IdentityProvider.EnforceRequestedAuthnContext.
	AuthnContextClassRef string `json:",omitempty"`

	CustomAttributes []Attribute
}

// SessionProvider is an interface used by IdentityProvider to determine the
// Session associated with a request. For an example implementation, see
// GetSession in the samlidp package.
//
// IdentityProvider does not act on the ForceAuthn and IsPassive attributes
// of the AuthnRequest (req.Request.ForceAuthn and req.Request.IsPassive):
// implementations are responsible for honouring them (saml-core §3.4.1,
// saml-profiles §4.1.3.4).
//
//   - ForceAuthn="true": the user must be authenticated directly, so an
//     existing session must not be returned. Authenticate the user again
//     and return a session whose CreateTime, which becomes the assertion's
//     AuthnInstant, is the time of that new authentication.
//   - IsPassive="true": the identity provider must not visibly interact with
//     the user. If a usable session exists, return it as usual. Otherwise do
//     not prompt the user; answer with a SAML error Response with the status
//     StatusResponder and the second-level status StatusNoPassive, by calling
//     IdentityProvider.SendErrorResponse with a *StatusError, and return nil.
//     This also applies when ForceAuthn is "true" as well and the user cannot
//     be authenticated again without interaction.
type SessionProvider interface {
	// GetSession returns the remote user session associated with the http.Request.
	//
	// If (and only if) the request is not associated with a session then GetSession
	// must complete the HTTP request and return nil.
	// To answer the request with a SAML error Response instead, for example
	// an IsPassive request when it would have to prompt the user, it can
	// call IdentityProvider.SendErrorResponse and return nil.
	GetSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
}

// ServiceProviderProvider is an interface used by IdentityProvider to look up
// service provider metadata for a request.
type ServiceProviderProvider interface {
	// GetServiceProvider returns the Service Provider metadata for the
	// service provider ID, which is typically the service provider's
	// metadata URL. If an appropriate service provider cannot be found then
	// the returned error must be os.ErrNotExist.
	GetServiceProvider(r *http.Request, serviceProviderID string) (*EntityDescriptor, error)
}

// AssertionMaker is an interface used by IdentityProvider to construct the
// assertion for a request. The default implementation is DefaultAssertionMaker,
// which is used if not AssertionMaker is specified.
type AssertionMaker interface {
	// MakeAssertion constructs an assertion from session and the request and
	// assigns it to req.Assertion.
	MakeAssertion(req *IdpAuthnRequest, session *Session) error
}

// ResponseWriter is an interface used by IdentityProvider to send the SAML
// response for a request to the browser, once the assertion has been made.
// The default implementation is DefaultResponseWriter, which is used if
// IdentityProvider.ResponseWriter is not set.
//
// Implement it to control the whole HTTP response, for example to set
// headers, to render the response inside the embedding application's own
// pages, or to support a binding other than HTTP-POST. To only change the
// markup of the default auto-submitting HTML form, set
// IdentityProvider.ResponseFormTemplate instead.
type ResponseWriter interface {
	// WriteResponse writes the HTTP response carrying the SAML response for
	// req. req.ResponseEl is nil until req.MakeResponse (or req.PostBinding,
	// which calls it) has been called. For an error Response it has been
	// set by req.MakeErrorResponse, and req.Assertion is nil. If it returns
	// an error, the caller logs it and replies with an HTTP 500 error, so an
	// implementation should return errors before it starts writing to w.
	WriteResponse(w http.ResponseWriter, req *IdpAuthnRequest) error
}

// DefaultResponseWriter is the default ResponseWriter. It calls
// req.WriteResponse, which writes an auto-submitting HTML form (see
// IdentityProvider.ResponseFormTemplate) that posts the response to the
// service provider using the HTTP-POST binding, or, when the ACS endpoint
// uses the HTTP-POST-SimpleSign binding, using that binding (see
// IdentityProvider.SimpleSignResponseFormTemplate).
type DefaultResponseWriter struct{}

// WriteResponse implements ResponseWriter.
func (DefaultResponseWriter) WriteResponse(w http.ResponseWriter, req *IdpAuthnRequest) error {
	return req.WriteResponse(w)
}

// IdentityProvider implements the SAML Identity Provider role (IDP).
//
// An identity provider receives SAML assertion requests and responds
// with SAML Assertions.
//
// You must provide a keypair that is used to
// sign assertions.
//
// You must provide an implementation of ServiceProviderProvider which
// returns
//
// You must provide an implementation of the SessionProvider which
// handles the actual authentication (i.e. prompting for a username
// and password).
type IdentityProvider struct {
	Key                     crypto.PrivateKey
	Signer                  crypto.Signer
	Logger                  logger.Interface
	Certificate             *x509.Certificate
	Intermediates           []*x509.Certificate
	MetadataURL             url.URL
	SSOURL                  url.URL
	LoginURL                url.URL
	LogoutURL               url.URL
	ServiceProviderProvider ServiceProviderProvider
	SessionProvider         SessionProvider
	AssertionMaker          AssertionMaker
	SignatureMethod         string
	ValidDuration           *time.Duration
	ResponseFormTemplate    *template.Template

	// Clock, if non-nil, is the time source for everything this
	// IdentityProvider does that depends on the current time: timestamps
	// on the metadata, assertions, responses and logout messages it issues,
	// the time checks on the requests and logout messages it receives, the
	// expiry of its logout state, and certificate validity during signature
	// validation.
	//
	// If nil, the real clock is used (through the deprecated package-level
	// TimeNow and Clock). Setting this field instead of replacing those
	// globals allows IdentityProviders with different clocks to be used
	// concurrently, for example in parallel tests.
	Clock *dsig.Clock

	// MaxClockSkew, if not zero, replaces the package-level MaxClockSkew for
	// this IdentityProvider: the leeway allowed for a service provider's
	// clock when checking IssueInstant and NotOnOrAfter times, and how far
	// back an assertion's validity period starts.
	MaxClockSkew time.Duration

	// MaxIssueDelay, if not zero, replaces the package-level MaxIssueDelay
	// for this IdentityProvider: the longest allowed time between a
	// request's IssueInstant and its receipt, which also bounds how long
	// replay records are kept and how long issued assertions are valid.
	MaxIssueDelay time.Duration

	// SimpleSignResponseFormTemplate, if set, replaces the default
	// auto-submitting HTML form used to send responses to ACS endpoints with
	// the HTTP-POST-SimpleSign binding. It is executed with an
	// IdpAuthnRequestSimpleSignForm and must post its SAMLResponse, SigAlg
	// and Signature fields, and RelayState when it is not empty (an empty
	// RelayState field would be included in the signed content).
	SimpleSignResponseFormTemplate *template.Template

	// LogoutRequestFormTemplate, if set, replaces the default
	// auto-submitting HTML form that sends a LogoutRequest to a service
	// provider's HTTP-POST SingleLogoutService while the IdP propagates a
	// logout (see StartLogout and ServeSLO). It is executed with an
	// IdpLogoutRequestForm and must post its SAMLRequest field to its URL.
	// LogoutResponses to service providers use ResponseFormTemplate.
	LogoutRequestFormTemplate *template.Template

	// LogoutCompleteTemplate, if set, replaces the default page shown at
	// the end of an IdP-initiated logout that has no return URL (see
	// StartLogout). It is executed with an IdpLogoutComplete.
	LogoutCompleteTemplate *template.Template

	// AdvertiseSimpleSignSSO, if true, adds an HTTP-POST-SimpleSign
	// SingleSignOnService endpoint at SSOURL to the metadata. ServeSSO
	// accepts SimpleSign authentication requests whether or not this is set.
	AdvertiseSimpleSignSSO bool

	// ResponseWriter, if set, writes the HTTP response carrying the SAML
	// response in ServeSSO and ServeIDPInitiated. If nil,
	// DefaultResponseWriter is used, which posts the response with the
	// HTML form from ResponseFormTemplate.
	ResponseWriter ResponseWriter

	// OnError, if non-nil, is called when ServeSSO, ServeIDPInitiated or
	// ServeMetadata cannot complete a request, in place of DefaultOnError,
	// which logs err to Logger and responds with status. status is the HTTP
	// status the IdentityProvider would respond with: StatusBadRequest for a
	// request that cannot be parsed or is invalid, StatusNotFound for an
	// IdP-initiated request for an unknown service provider, and
	// StatusInternalServerError otherwise. err can be matched with errors.Is
	// against the error values of this package, such as
	// ErrUnknownServiceProvider or ErrInvalidCertificate.
	//
	// OnError must write the response. When writing the SAML response or
	// the metadata failed part way, some of it may already have been
	// written to w.
	OnError func(w http.ResponseWriter, r *http.Request, status int, err error)

	// ExtraCertificates are additional certificates published in the IdP
	// metadata as signing keys, after Certificate. They are never used to
	// sign anything. Use them to announce a new signing certificate before
	// switching Certificate (and Key or Signer) to it, so that service
	// providers that refresh their copy of the metadata already trust the
	// new key when the rollover happens, or to keep publishing the old
	// certificate for a while afterwards.
	ExtraCertificates []*x509.Certificate

	// NameIDFormats are the NameID formats advertised in the IdP metadata.
	// When empty it defaults to the transient format for backwards compatibility.
	NameIDFormats []NameIDFormat

	// MetadataScopes are published in the IdP metadata as Shibboleth
	// shibmd:Scope extension elements, which tell service providers the
	// scopes the IdP is authoritative for, i.e. the parts after the "@" in
	// scoped attribute values such as eduPersonScopedAffiliation. When
	// empty, no scopes are published.
	MetadataScopes []ShibbolethScope

	// AssertionEncrypter, if set, encrypts assertions for service providers
	// that publish an encryption certificate. It is passed the SP's
	// *x509.Certificate as the key. Use it to select the key transport,
	// digest and block cipher, for example:
	//
	//	enc := xmlenc.OAEP_SHA256() // XML Encryption 1.1 RSA-OAEP
	//	enc.BlockCipher = xmlenc.AES256GCM
	//	idp.AssertionEncrypter = enc
	//
	// The service provider must support the algorithms chosen; those it
	// supports are usually listed in its metadata.
	//
	// When nil, assertions are encrypted with RSA-OAEP-MGF1P using a SHA-1
	// digest and the strongest block cipher that the service provider's
	// metadata lists in the EncryptionMethods of its encryption key: AES-GCM
	// (256, 128 then 192 bit keys) before AES-CBC. If it lists none of
	// them, AES-128-CBC is used, for compatibility with existing service
	// providers. CBC has no integrity protection; set AssertionEncrypter to
	// use AES-GCM with service providers that support it but do not say so.
	//
	// It also encrypts the EncryptedID that MakeAssertionEl issues in place
	// of the Subject's NameID when the AuthnRequest asks for the encrypted
	// NameID format (saml-core §3.4.1.1, §8.3.9).
	AssertionEncrypter xmlenc.Encrypter

	// SignMetadata, if true, causes ServeMetadata to publish metadata that
	// carries an enveloped XML signature made with the IdP's key. See
	// SignedMetadata.
	SignMetadata bool

	// RejectSHA1Signatures, if true, refuses messages from service
	// providers that are signed with a SHA-1 based algorithm: an XML
	// signature whose SignatureMethod or any DigestMethod is SHA-1 based
	// (rsa-sha1, ecdsa-sha1, dsa-sha1, hmac-sha1 or sha1), and an
	// HTTP-Redirect or HTTP-POST-SimpleSign signature whose SigAlg is. It
	// applies to the signatures the IdP verifies: those of LogoutRequests
	// and of LogoutResponses to the IdP's own LogoutRequests (ServeSLO),
	// and of AuthnRequests. The error matches ErrUnsupported. If false,
	// SHA-1 is accepted.
	RejectSHA1Signatures bool

	// WantAuthnRequestsSigned, if true, makes the IdP refuse AuthnRequests
	// that are not signed, with an error matching ErrInvalidSignature, and
	// publishes WantAuthnRequestsSigned="true" in its metadata
	// (saml-metadata-2.0-os §2.4.3). Whether or not it is set, a request
	// from a service provider whose metadata says AuthnRequestsSigned="true"
	// must be signed, and the signature of any signed request is verified
	// (see IdpAuthnRequest.Validate).
	WantAuthnRequestsSigned bool

	// LogoutBindings are the bindings advertised in the IdP metadata for the
	// SingleLogoutService at LogoutURL. When empty, only HTTP-Redirect is
	// advertised, as before. ServeSLO accepts LogoutRequests and
	// LogoutResponses with the HTTP-Redirect, HTTP-POST and
	// HTTP-POST-SimpleSign bindings, so set it to
	// []string{HTTPRedirectBinding, HTTPPostBinding} when LogoutURL is served
	// by ServeSLO.
	//
	// Include SOAPBinding to advertise a SOAP SingleLogoutService as well,
	// and have ServeSLO accept LogoutRequests sent server to server with the
	// SOAP binding. ServeSLO accepts them only then. Do so only if the
	// SessionProvider's SessionInvalidator can end sessions without the
	// browser's cookies (see SessionInvalidator), since such a request
	// carries none.
	LogoutBindings []string

	// EncryptionCertificate, if set, is published in the IdP metadata as the
	// IdP's encryption key in place of Certificate. Service providers encrypt
	// to it, for example the EncryptedID of a LogoutRequest. Its private key
	// must be Key or one of DecryptionKeys. Set it when Key cannot decrypt,
	// such as when the IdP signs with a Signer held in an HSM or KMS, or to
	// encrypt with a key other than the signing key.
	EncryptionCertificate *x509.Certificate

	// DecryptionKeys are further private keys that decrypt what service
	// providers encrypt to the IdP, such as the EncryptedID of a
	// LogoutRequest. They are tried in order after Key, if Key is an
	// *rsa.PrivateKey. Set them while rotating the IdP encryption key, so
	// that messages encrypted to the previous certificate by service
	// providers that have not yet refreshed the IdP metadata can still be
	// decrypted, or when Key cannot decrypt (see EncryptionCertificate).
	DecryptionKeys []*rsa.PrivateKey

	// LimitRelayStateLength, if true, makes NewIdpInitiatedRequest refuse a
	// RelayState longer than MaxRelayStateLength (80 bytes), as the SAML
	// bindings require of senders (saml-bindings-2.0-os §3.5.3), with an
	// error matching ErrRelayStateTooLong; ServeIDPInitiated then answers
	// HTTP 400. It is off by default. A RelayState the IdP echoes in a
	// Response or LogoutResponse is never checked.
	LimitRelayStateLength bool

	// AcceptLogoutRequestBaseID, if true, lets ServeSLO and
	// IdpLogoutRequest.Validate accept a LogoutRequest whose principal is a
	// saml:BaseID (in the clear, or in an EncryptedID) rather than a NameID.
	// Request.BaseID then holds the element and Request.NameID is nil, so
	// MatchesSession matches no session; the SessionInvalidator must
	// interpret the BaseID itself. If false, such a request is refused with
	// an error matching ErrUnsupported.
	AcceptLogoutRequestBaseID bool

	// EncryptLogoutNameID, if true, makes the LogoutRequests the IdP sends
	// to service providers (see StartLogout and SessionParticipantTracker)
	// identify the principal with a saml:EncryptedID instead of a NameID,
	// encrypted to the service provider's encryption certificate. As with
	// assertions, a service provider whose metadata publishes no encryption
	// certificate cannot decrypt, so it is sent the NameID in the clear.
	EncryptLogoutNameID bool

	// LogoutNameIDEncrypter, if set, encrypts the NameID of the
	// LogoutRequests the IdP sends (see EncryptLogoutNameID). It is passed
	// the service provider's *x509.Certificate as the key. When nil,
	// RSA-OAEP-MGF1P with a SHA-1 digest is used with the strongest block
	// cipher that the service provider's metadata lists in the
	// EncryptionMethods of its encryption key: AES-GCM (256, 128 then 192
	// bit keys) before AES-CBC, or AES-256-GCM if it lists none of them.
	LogoutNameIDEncrypter xmlenc.Encrypter

	// ReplayCache, if set, records the ID of each LogoutRequest that
	// IdpLogoutRequest.Validate (and so ServeSLO) accepts, and refuses a
	// LogoutRequest whose ID it has already recorded, so that a captured
	// request cannot be replayed while it is still current. IDs are recorded
	// under the key "LogoutRequest:" followed by the ID, until the last
	// moment the request would be accepted. If nil, LogoutRequests are not
	// checked for replay.
	//
	// It also records the ID of each signed AuthnRequest that ServeSSO
	// answers with an assertion, under the key "AuthnRequest:" followed by
	// the service provider's entity ID, a space and the ID, and refuses a
	// signed AuthnRequest it has already answered. The ID is recorded once
	// the SessionProvider has returned a session, so a request that is sent
	// again after a login form is still accepted. Unsigned AuthnRequests are
	// not recorded: anyone can make a new one, so refusing a repeated one
	// would protect nothing.
	ReplayCache AssertionReplayCache

	// HTTPClient is the client the IdP sends back-channel messages with:
	// the LogoutRequests it sends over the SOAP binding to the session
	// participants whose metadata lists a SOAP SingleLogoutService (see
	// StartLogout and ServeSLO). If nil, a client that gives up after 10
	// seconds and does not follow redirects is used. Whatever the client,
	// a redirect to a location that is not https (or http, with
	// AllowInsecureSOAPEndpoints) is not followed.
	HTTPClient *http.Client

	// AllowInsecureSOAPEndpoints lets the IdP send SOAP messages to http
	// endpoints. By default a SOAP SingleLogoutService whose Location is not
	// https is ignored, as if the service provider metadata did not list it
	// (see ErrInsecureSOAPEndpoint), so that a LogoutRequest carrying the
	// user's NameID never crosses the network in the clear; the participant
	// is then logged out through the browser if it can be. Set it only for
	// tests and development setups.
	AllowInsecureSOAPEndpoints bool

	// ReportPartialLogoutWithoutTracker, if true, makes ServeSLO answer a
	// LogoutRequest with the second-level status StatusPartialLogout under
	// StatusSuccess when the SessionProvider does not implement
	// SessionParticipantTracker. The IdP then cannot know which other
	// service providers the session was used for, nor contact them, and
	// saml-core-2.0-os §3.7.3.2 requires a session authority that cannot
	// contact all the session participants to say so with PartialLogout. If
	// false, such a logout is answered with a plain StatusSuccess, as
	// before. It has no effect when the SessionProvider tracks session
	// participants: the second-level status then reports whether they were
	// all logged out.
	ReportPartialLogoutWithoutTracker bool

	// SendErrorResponses makes ServeSSO answer an AuthnRequest that is
	// expired (ErrExpired) or not SAML 2.0 with a SAML error <Response> sent
	// to the service provider's assertion consumer service, as saml-core
	// §3.4.1.4 and saml-bindings §3.4.6 and §3.5.6 ask, instead of an HTTP
	// 400 error. The Response is only sent when the request otherwise
	// identifies a known service provider and an assertion consumer service
	// in its metadata, so it never goes to a location the request alone
	// names; other invalid requests still get HTTP 400. An expired request
	// gets a Requester status, a request with another version a
	// VersionMismatch status (saml-core §4.1.3.2).
	//
	// Whether or not it is set, an AssertionMaker that returns a
	// *StatusError gets an error Response, in ServeSSO and
	// ServeIDPInitiated.
	SendErrorResponses bool

	// EnforceNameIDPolicy, if true, makes DefaultAssertionMaker enforce the
	// NameIDPolicy of the AuthnRequest, as saml-core §3.4.1.1 requires.
	// A request whose NameIDPolicy Format is neither unspecified nor
	// encrypted, and is not the format the IdP issues (Session.NameIDFormat,
	// or transient if that is empty), is answered with an error Response
	// with the status Requester and InvalidNameIDPolicy, and no assertion.
	// A NameIDPolicy SPNameQualifier is put in the NameID instead of the
	// service provider's entity ID (it is left out of an entity format
	// NameID). Whether the service provider may ask for that qualifier, and
	// what identifier to give under it, is up to the SessionProvider, which
	// can read the policy from IdpAuthnRequest.Request.
	//
	// If false, the NameIDPolicy is ignored, as before, except that a
	// request for the encrypted format gets an EncryptedID whether or not
	// it is set (see MakeAssertionEl).
	//
	// Service providers built with this package, including samlsp, ask for
	// the transient format by default (ServiceProvider.AuthnNameIDFormat
	// empty). An IdP that issues another format, such as samlidp, which
	// issues emailAddress NameIDs to users with an email address, refuses
	// those requests when EnforceNameIDPolicy is set. Such a service
	// provider should set ServiceProvider.AuthnNameIDFormat to the format
	// the IdP issues, for example the first NameIDFormat of the IdP
	// metadata, or to UnspecifiedNameIDFormat to accept whatever the IdP
	// issues.
	EnforceNameIDPolicy bool

	// StrictACSBinding makes the IdP match the ProtocolBinding of an
	// AuthnRequest, as well as its AssertionConsumerServiceURL, against the
	// service provider's assertion consumer services (saml-core §3.4.1:
	// ProtocolBinding "identifies a SAML protocol binding to be used when
	// returning the <Response> message"). If no endpoint at that URL has
	// that binding, or the matching endpoint has a binding the IdP cannot
	// send a Response with, ServeSSO answers with a Requester error Response
	// with the second-level status UnsupportedBinding, sent to the service
	// provider's default assertion consumer service from its metadata (or
	// with HTTP 400 if it has none the IdP can send to).
	//
	// When false, an endpoint is matched on its Location as before, so a
	// request that names, say, HTTP-Artifact or HTTP-Redirect at the URL of
	// an HTTP-POST endpoint still gets an HTTP-POST Response. Set it only if
	// the service providers send a correct ProtocolBinding.
	//
	// Whether or not it is set, when ResponseWriter is not set (or is
	// DefaultResponseWriter) and the endpoint a request names (by URL or
	// index) has a binding other than HTTP-POST and HTTP-POST-SimpleSign,
	// ServeSSO answers with that UnsupportedBinding error Response before
	// asking the SessionProvider for a session, instead of failing with
	// HTTP 500 once the user has logged in. A custom ResponseWriter is
	// given such an endpoint, since it may support other bindings.
	StrictACSBinding bool

	// EnforceRequestedAuthnContext, if true, makes DefaultAssertionMaker
	// check the AuthnContextClassRef it asserts (Session.AuthnContextClassRef,
	// or PasswordProtectedTransport when that is empty) against the
	// RequestedAuthnContext of the AuthnRequest, with the "exact" (or
	// omitted), "minimum", "maximum" and "better" Comparisons of saml-core
	// §3.3.2.2.1 as amended by errata E65. When it does not satisfy any of
	// the requested classes, MakeAssertion returns a *StatusError, and
	// ServeSSO answers with a Response with the status Responder and the
	// second-level status NoAuthnContext and no assertion. An unknown
	// Comparison is answered with Requester. Only AuthnContextClassRefs are
	// evaluated; a request that names none is always satisfied.
	//
	// If false, the default, the RequestedAuthnContext is ignored and the
	// assertion is made whatever the service provider asked for, as before.
	EnforceRequestedAuthnContext bool

	// AuthnContextClassStrengths ranks authentication context classes for
	// the "minimum", "maximum" and "better" Comparisons, when
	// EnforceRequestedAuthnContext is set: a higher number is stronger, and
	// classes with the same number are equally strong. A class that is not
	// in the map is not ranked, and only satisfies a request that names it.
	// If nil, DefaultAuthnContextClassStrengths is used.
	AuthnContextClassStrengths map[string]int
}

// limits returns the clock skew and issue delay this IdentityProvider
// allows. idp may be nil, in which case the package-level values are used.
func (idp *IdentityProvider) limits() timeLimits {
	if idp == nil {
		return timeLimits{}
	}
	return timeLimits{clockSkew: idp.MaxClockSkew, issueDelay: idp.MaxIssueDelay}
}

// maxClockSkew returns MaxClockSkew, or the package-level MaxClockSkew if it
// is zero.
func (idp *IdentityProvider) maxClockSkew() time.Duration { return idp.limits().skew() }

// maxIssueDelay returns MaxIssueDelay, or the package-level MaxIssueDelay if
// it is zero.
func (idp *IdentityProvider) maxIssueDelay() time.Duration { return idp.limits().delay() }

// now returns the current time as seen by this IdentityProvider. idp may be
// nil, in which case the default clock is used.
func (idp *IdentityProvider) now() time.Time {
	if idp == nil {
		return clockNow(nil)
	}
	return clockNow(idp.Clock)
}

// dsigClock returns the clock to use for signature validation. It may be
// nil, in which case dsig uses the real clock.
func (idp *IdentityProvider) dsigClock() *dsig.Clock {
	if idp == nil {
		return dsigClockOrDefault(nil)
	}
	return dsigClockOrDefault(idp.Clock)
}

// Metadata returns the metadata structure for this identity provider.
func (idp *IdentityProvider) Metadata() *EntityDescriptor {
	certStr := base64.StdEncoding.EncodeToString(idp.Certificate.Raw)
	encryptionCertStr := certStr
	if idp.EncryptionCertificate != nil {
		encryptionCertStr = base64.StdEncoding.EncodeToString(idp.EncryptionCertificate.Raw)
	}

	var validDuration time.Duration
	if idp.ValidDuration != nil {
		validDuration = *idp.ValidDuration
	} else {
		validDuration = DefaultValidDuration
	}

	nameIDFormats := idp.NameIDFormats
	if len(nameIDFormats) == 0 {
		nameIDFormats = []NameIDFormat{TransientNameIDFormat}
	}

	ed := &EntityDescriptor{
		EntityID:      idp.entityID(),
		ValidUntil:    idp.now().Add(validDuration),
		CacheDuration: validDuration,
		IDPSSODescriptors: []IDPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{Data: certStr},
										},
									},
								},
							},
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{Data: encryptionCertStr},
										},
									},
								},
								// In order of preference: AES-GCM first, as
								// for the SP metadata. The IdP decrypts all of
								// them (see DecryptionKeys).
								EncryptionMethods: []EncryptionMethod{
									{Algorithm: xmlenc.AES256GCM.Algorithm()},
									{Algorithm: xmlenc.AES128GCM.Algorithm()},
									{Algorithm: xmlenc.AES192GCM.Algorithm()},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
								},
							},
						},
					},
					NameIDFormats: nameIDFormats,
				},
				SingleSignOnServices: []Endpoint{
					{
						Binding:  HTTPRedirectBinding,
						Location: idp.SSOURL.String(),
					},
					{
						Binding:  HTTPPostBinding,
						Location: idp.SSOURL.String(),
					},
				},
			},
		},
	}

	if idp.WantAuthnRequestsSigned {
		want := true
		ed.IDPSSODescriptors[0].WantAuthnRequestsSigned = &want
	}

	if idp.AdvertiseSimpleSignSSO {
		ed.IDPSSODescriptors[0].SingleSignOnServices = append(ed.IDPSSODescriptors[0].SingleSignOnServices, Endpoint{
			Binding:  HTTPPostSimpleSignBinding,
			Location: idp.SSOURL.String(),
		})
	}

	for _, cert := range idp.ExtraCertificates {
		if cert == nil {
			continue
		}
		ed.IDPSSODescriptors[0].KeyDescriptors = append(ed.IDPSSODescriptors[0].KeyDescriptors, KeyDescriptor{
			Use: "signing",
			KeyInfo: KeyInfo{
				X509Data: X509Data{
					X509Certificates: []X509Certificate{
						{Data: base64.StdEncoding.EncodeToString(cert.Raw)},
					},
				},
			},
		})
	}

	if len(idp.MetadataScopes) > 0 {
		ed.IDPSSODescriptors[0].Extensions = &Extensions{
			ShibbolethScopes: append([]ShibbolethScope(nil), idp.MetadataScopes...),
		}
	}

	if idp.LogoutURL.String() != "" {
		logoutBindings := idp.LogoutBindings
		if len(logoutBindings) == 0 {
			logoutBindings = []string{HTTPRedirectBinding}
		}
		for _, binding := range logoutBindings {
			ed.IDPSSODescriptors[0].SingleLogoutServices = append(ed.IDPSSODescriptors[0].SingleLogoutServices, Endpoint{
				Binding:  binding,
				Location: idp.LogoutURL.String(),
			})
		}
	}

	return ed
}

// entityID returns the IdP's entity ID, the EntityID of its metadata,
// without building the whole metadata (which encodes every certificate).
func (idp *IdentityProvider) entityID() string {
	return idp.MetadataURL.String()
}

// Handler returns an http.Handler that serves the metadata and SSO
// URLs, and the single logout URL (see ServeSLO) if LogoutURL is set and its
// path differs from the others.
func (idp *IdentityProvider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(idp.MetadataURL.Path, idp.ServeMetadata)
	mux.HandleFunc(idp.SSOURL.Path, idp.ServeSSO)
	if p := idp.LogoutURL.Path; p != "" && p != idp.MetadataURL.Path && p != idp.SSOURL.Path {
		mux.HandleFunc(p, idp.ServeSLO)
	}
	return mux
}

// SignedMetadata returns the IdP metadata as an XML element carrying an
// enveloped signature made with the IdP's key (saml-metadata-2.0-os §3).
//
// The signature references the EntityDescriptor by its ID attribute; one is
// generated if the metadata does not have one. The returned element must be
// serialized as-is: re-indenting it changes the signed content.
func (idp *IdentityProvider) SignedMetadata() (*etree.Element, error) {
	signingContext, err := idp.signingContext()
	if err != nil {
		return nil, err
	}
	return signMetadata(idp.Metadata(), signingContext)
}

// ServeMetadata is an http.HandlerFunc that serves the IDP metadata. If
// SignMetadata is set, the metadata is signed.
//
// If the metadata cannot be signed, serialized or written, a
// StatusInternalServerError response is sent. Set OnError to handle these
// failures differently.
func (idp *IdentityProvider) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	var buf []byte
	if idp.SignMetadata {
		el, err := idp.SignedMetadata()
		if err != nil {
			idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to sign metadata: %w", err))
			return
		}
		doc := etree.NewDocument()
		doc.SetRoot(el)
		if buf, err = doc.WriteToBytes(); err != nil {
			idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to serialize metadata: %w", err))
			return
		}
	} else {
		var err error
		if buf, err = xml.MarshalIndent(idp.Metadata(), "", "  "); err != nil {
			idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to serialize metadata: %w", err))
			return
		}
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if _, err := w.Write(buf); err != nil {
		idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to write metadata: %w", err))
	}
}

// DefaultOnError is how ServeSSO, ServeIDPInitiated and ServeMetadata report
// an error when OnError is nil: it logs err to Logger and responds with
// status. An OnError can call it for the errors it does not handle itself.
func (idp *IdentityProvider) DefaultOnError(w http.ResponseWriter, _ *http.Request, status int, err error) {
	idp.Logger.Printf("%s", err)
	http.Error(w, http.StatusText(status), status)
}

func (idp *IdentityProvider) onError(w http.ResponseWriter, r *http.Request, status int, err error) {
	if idp.OnError != nil {
		idp.OnError(w, r, status, err)
		return
	}
	idp.DefaultOnError(w, r, status, err)
}

// ServeSSO handles SAML auth requests.
//
// When it gets a request for a user that does not have a valid session,
// then it prompts the user via XXX.
//
// If the session already exists, then it produces a SAML assertion and
// returns an HTTP response according to the specified binding. The
// only supported binding right now is the HTTP-POST binding which returns
// an HTML form in the appropriate format with Javascript to automatically
// submit that form the to service provider's Assertion Customer Service
// endpoint.
//
// If the SAML request is invalid or cannot be verified a simple StatusBadRequest
// response is sent, unless SendErrorResponses is set and the request can be
// answered with a SAML error Response (see SendErrorResponses).
//
// A request that names an assertion consumer service whose binding the
// default ResponseWriter cannot send a Response with (anything but HTTP-POST
// and HTTP-POST-SimpleSign), or, with StrictACSBinding, whose URL has no
// endpoint with the requested ProtocolBinding, gets an error Response with
// the status Requester and UnsupportedBinding, sent to the service
// provider's default assertion consumer service from its metadata, before
// the SessionProvider is asked for a session.
//
// If the AssertionMaker returns a *StatusError, a SAML Response with that
// status and no assertion is sent to the assertion consumer service instead
// (see SendErrorResponse). So is one when the request has a
// <saml:Subject> that the assertion's Subject does not strongly match, as
// saml-core §3.4.1.4 requires (see CheckRequestSubject). If the assertion cannot otherwise be created or
// returned, a StatusInternalServerError response is sent.
//
// Set OnError to handle these failures differently.
func (idp *IdentityProvider) ServeSSO(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpAuthnRequest(idp, r)
	if err != nil {
		idp.onError(w, r, http.StatusBadRequest, fmt.Errorf("failed to parse request: %w", err))
		return
	}

	err = req.Validate()
	if err == nil {
		err = req.checkSendableACS()
	}
	if err != nil {
		if statusErr := req.validationErrorResponse(err); statusErr != nil {
			idp.sendStatusError(w, r, req, statusErr)
			return
		}
		idp.onError(w, r, http.StatusBadRequest, fmt.Errorf("failed to validate request: %w", err))
		return
	}

	session := idp.SessionProvider.GetSession(w, r, req)
	if session == nil {
		return
	}

	// Only now is the request used up: GetSession may have shown a login
	// form that sends the same request again.
	if err := req.consume(); err != nil {
		idp.onError(w, r, http.StatusBadRequest, fmt.Errorf("failed to validate request: %w", err))
		return
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = DefaultAssertionMaker{}
	}
	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		var statusErr *StatusError
		if errors.As(err, &statusErr) {
			idp.sendStatusError(w, r, req, statusErr)
			return
		}
		idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to make assertion: %w", err))
		return
	}
	if statusErr := req.requestSubjectStatusError(); statusErr != nil {
		idp.sendStatusError(w, r, req, statusErr)
		return
	}
	if err := idp.recordSessionParticipant(r, req, session); err != nil {
		idp.onError(w, r, http.StatusInternalServerError, err)
		return
	}
	if err := idp.responseWriter().WriteResponse(w, req); err != nil {
		idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to write response: %w", err))
		return
	}
}

// ServeIDPInitiated handes an IDP-initiated authorization request. Requests of this
// type require us to know a registered service provider and (optionally) the RelayState
// that will be passed to the application.
//
// It responds with StatusNotFound if the service provider is unknown, and
// with StatusInternalServerError if the service provider cannot be looked up
// or has no usable assertion consumer service, or the assertion cannot be
// created or returned. If the AssertionMaker returns a *StatusError, an
// unsolicited SAML Response with that status and no assertion is sent to the
// assertion consumer service instead. Set OnError to handle these failures differently, or
// build a handler from NewIdpInitiatedRequest.
func (idp *IdentityProvider) ServeIDPInitiated(w http.ResponseWriter, r *http.Request, serviceProviderID string, relayState string) {
	req, err := idp.NewIdpInitiatedRequest(r, serviceProviderID, relayState)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrUnknownServiceProvider):
			status = http.StatusNotFound
		case errors.Is(err, ErrRelayStateTooLong):
			status = http.StatusBadRequest
		}
		idp.onError(w, r, status, err)
		return
	}

	session := idp.SessionProvider.GetSession(w, r, req)
	if session == nil {
		// If GetSession returns nil, it must have written an HTTP response, per the interface
		// (this is probably because it drew a login form or something)
		return
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = DefaultAssertionMaker{}
	}
	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		var statusErr *StatusError
		if errors.As(err, &statusErr) {
			idp.sendStatusError(w, r, req, statusErr)
			return
		}
		idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to make assertion: %w", err))
		return
	}
	if err := idp.recordSessionParticipant(r, req, session); err != nil {
		idp.onError(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := idp.responseWriter().WriteResponse(w, req); err != nil {
		idp.onError(w, r, http.StatusInternalServerError, fmt.Errorf("failed to write response: %w", err))
		return
	}
}

// NewIdpInitiatedRequest returns the IdpAuthnRequest for an IdP-initiated
// login to the service provider serviceProviderID, with its metadata and its
// default assertion consumer service resolved: the default endpoint, by the
// saml-metadata §2.2.3 rule, among those with the HTTP-POST or
// HTTP-POST-SimpleSign binding. It is the part of ServeIDPInitiated that
// runs before the SessionProvider is asked for a session.
//
// It returns an error matching ErrUnknownServiceProvider (and os.ErrNotExist)
// if the ServiceProviderProvider does not know serviceProviderID,
// ErrUnknownAssertionConsumerService if the service provider has no HTTP-POST
// or HTTP-POST-SimpleSign assertion consumer service, and otherwise the
// ServiceProviderProvider's error, wrapped.
func (idp *IdentityProvider) NewIdpInitiatedRequest(r *http.Request, serviceProviderID string, relayState string) (*IdpAuthnRequest, error) {
	if err := checkRelayState(idp.LimitRelayStateLength, relayState); err != nil {
		return nil, err
	}
	req := &IdpAuthnRequest{
		IDP:         idp,
		HTTPRequest: r,
		RelayState:  relayState,
		Now:         idp.now(),
	}

	// Resolve the service provider and its ACS endpoint before the
	// SessionProvider is asked for a session, as ServeSSO does via Validate.
	// Otherwise a request for an unknown service provider would prompt the
	// user to log in before failing, and the SessionProvider would see a
	// request without ServiceProviderMetadata.
	var err error
	req.ServiceProviderMetadata, err = idp.ServiceProviderProvider.GetServiceProvider(r, serviceProviderID)
	if errors.Is(err, os.ErrNotExist) {
		return nil, classify(fmt.Errorf("cannot find service provider: %s", serviceProviderID), ErrUnknownServiceProvider, os.ErrNotExist)
	} else if err != nil {
		return nil, fmt.Errorf("cannot find service provider %s: %w", serviceProviderID, err)
	}

	// An unsolicited Response "SHOULD be delivered to the
	// <md:AssertionConsumerService> endpoint of the service provider
	// designated as the default" (saml-profiles §4.1.5): the default among
	// the endpoints the IdP can send a Response to, by the saml-metadata
	// §2.2.3 rule.
	if !req.selectDefaultACSEndpoint() {
		return nil, classify(errors.New("saml metadata does not contain an Assertion Customer Service url"), ErrUnknownAssertionConsumerService)
	}

	return req, nil
}

// responseWriter returns idp.ResponseWriter, or DefaultResponseWriter if it
// is not set.
func (idp *IdentityProvider) responseWriter() ResponseWriter {
	if idp.ResponseWriter != nil {
		return idp.ResponseWriter
	}
	return DefaultResponseWriter{}
}

// IdpAuthnRequest is used by IdentityProvider to handle a single authentication request.
type IdpAuthnRequest struct {
	IDP                     *IdentityProvider
	HTTPRequest             *http.Request
	RelayState              string
	RequestBuffer           []byte
	Request                 AuthnRequest
	ServiceProviderMetadata *EntityDescriptor
	SPSSODescriptor         *SPSSODescriptor
	ACSEndpoint             *IndexedEndpoint
	Assertion               *Assertion
	AssertionEl             *etree.Element
	ResponseEl              *etree.Element
	Now                     time.Time

	// RequestSigned is set by Validate when it has verified a signature
	// of the request: the query string signature of the HTTP-Redirect
	// binding, the signature of the HTTP-POST-SimpleSign binding, or an
	// enveloped XML signature. It is false for an unsigned request.
	RequestSigned bool

	// simpleSign is the HTTP-POST-SimpleSign message the request arrived
	// in, or nil if it arrived with another binding. Validate checks its
	// signature once it knows the service provider.
	simpleSign *simpleSignMessage

	// redirectMessage is the parsed query of a request received with the
	// HTTP-Redirect binding, or nil. Validate checks its query string
	// signature, if it has one, once it knows the service provider.
	redirectMessage *redirectBindingMessage
}

// NewIdpAuthnRequest returns a new IdpAuthnRequest for the given HTTP request to the authorization
// service.
//
// A GET request carries the request with the HTTP-Redirect binding and a
// POST request with the HTTP-POST binding, or with the HTTP-POST-SimpleSign
// binding when the form has a SigAlg or Signature field. The SimpleSign form
// is checked for duplicated or missing fields here; its signature is checked
// by Validate, once the service provider is known.
func NewIdpAuthnRequest(idp *IdentityProvider, r *http.Request) (*IdpAuthnRequest, error) {
	req := &IdpAuthnRequest{
		IDP:         idp,
		HTTPRequest: r,
		Now:         idp.now(),
	}

	switch r.Method {
	case "GET":
		// The query is parsed once, so that the message, the relay state and
		// the content a query string signature covers all come from the same
		// parse (see parseRedirectBindingQuery).
		m, err := parseRedirectBindingQuery(r.URL.RawQuery, redirectParamSAMLRequest)
		if err != nil {
			return nil, classify(err, ErrMalformedMessage)
		}
		compressedRequest, err := base64.StdEncoding.DecodeString(m.Message)
		if err != nil {
			return nil, classify(fmt.Errorf("cannot decode request: %w", err), ErrMalformedMessage)
		}
		req.RequestBuffer, err = io.ReadAll(newSaferFlateReader(bytes.NewReader(compressedRequest)))
		if err != nil {
			return nil, classify(fmt.Errorf("cannot decompress request: %w", err), ErrMalformedMessage)
		}
		req.RelayState = m.RelayState
		req.redirectMessage = m
	case "POST":
		if err := r.ParseForm(); err != nil {
			return nil, classify(err, ErrMalformedMessage)
		}
		simpleSign, err := parseSimpleSignRequest(r, redirectParamSAMLRequest)
		if err != nil {
			return nil, err
		}
		if simpleSign != nil {
			req.simpleSign = simpleSign
			req.RequestBuffer = simpleSign.XML
			req.RelayState = simpleSign.RelayState
			break
		}
		req.RequestBuffer, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
		if err != nil {
			return nil, classify(err, ErrMalformedMessage)
		}
		req.RelayState = r.PostForm.Get("RelayState")
	default:
		return nil, classify(fmt.Errorf("method not allowed"), ErrUnsupported)
	}

	return req, nil
}

// authnRequestReplayKeyPrefix is the prefix of the ReplayCache keys under
// which the IDs of signed AuthnRequests are recorded.
const authnRequestReplayKeyPrefix = "AuthnRequest:"

// consume records the ID of the validated request in the IdP's ReplayCache,
// if it is set and the request is signed, and returns an error if it was
// already recorded.
func (req *IdpAuthnRequest) consume() error {
	if req.IDP.ReplayCache == nil || !req.isSigned() {
		return nil
	}
	issuer := ""
	if req.Request.Issuer != nil {
		issuer = req.Request.Issuer.Value
	}
	key := authnRequestReplayKeyPrefix + issuer + " " + req.Request.ID
	if err := req.IDP.ReplayCache.Consume(key, req.Request.IssueInstant.Add(req.IDP.maxIssueDelay())); err != nil {
		return fmt.Errorf("authn request %q: %w", req.Request.ID, err)
	}
	return nil
}

// isSigned reports whether the request carries a signature: an enveloped
// ds:Signature element, the SigAlg or Signature query parameter of the
// HTTP-Redirect binding, or the signature of the HTTP-POST-SimpleSign
// binding. The signature itself is not checked here.
func (req *IdpAuthnRequest) isSigned() bool {
	if req.simpleSign != nil || req.Request.Signature != nil {
		return true
	}
	if req.redirectMessage != nil {
		return req.redirectMessage.SignedContent != nil
	}
	if req.HTTPRequest != nil && req.HTTPRequest.Method == http.MethodGet && req.HTTPRequest.URL != nil {
		query := req.HTTPRequest.URL.Query()
		if query.Has("SigAlg") || query.Has("Signature") {
			return true
		}
	}
	return false
}

// Validate checks that the authentication request is valid and assigns
// the AuthnRequest and Metadata properties. Returns a non-nil error if the
// request is not valid.
//
// A signed request must carry a valid signature made with a signing
// certificate from the service provider's metadata (their validity periods
// are not checked, as is usual for keys distributed in metadata): a query
// string signature (SigAlg and Signature) or an enveloped XML signature with
// the HTTP-Redirect binding, an enveloped XML signature with the HTTP-POST
// binding, and the SimpleSign signature with the HTTP-POST-SimpleSign
// binding. A request whose signature cannot be verified is rejected with an
// error matching ErrInvalidSignature. When the request has an enveloped
// signature, it is read again from what the signature covers.
//
// An unsigned request is rejected, with an error matching
// ErrInvalidSignature, when the service provider's metadata says it signs
// its AuthnRequests (AuthnRequestsSigned="true") or the IdP's
// WantAuthnRequestsSigned is set. Otherwise it is accepted.
//
// RequestSigned is set if a signature was verified.
//
// A signed request, and any request when WantAuthnRequestsSigned is set,
// must have a Destination equal to SSOURL, as saml-bindings-2.0-os §3.4.5.2
// and §3.5.5.2 require of signed messages; so must any request that has a
// Destination.
func (req *IdpAuthnRequest) Validate() error {
	req.RequestSigned = false
	if err := xmlroundtrip.Validate(req.RequestBuffer); err != nil {
		return classify(err, ErrMalformedMessage)
	}

	if err := xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil { //nolint:gosec // parsing the untrusted request is the point; it was checked by xmlroundtrip.Validate above
		return classify(err, ErrMalformedMessage)
	}

	if err := req.validateFields(); err != nil {
		return err
	}

	return req.resolveServiceProvider()
}

// validateFields checks the Destination, IssueInstant, Version and ID of
// the request.
func (req *IdpAuthnRequest) validateFields() error {
	// In http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf §3.4.5.2
	// we get a description of the Destination attribute:
	//
	//   If the message is signed, the Destination XML attribute in the root SAML
	//   element of the protocol message MUST contain the URL to which the sender
	//   has instructed the user agent to deliver the message. The recipient MUST
	//   then verify that the value matches the location at which the message has
	//   been received.
	//
	// (and §3.5.5.2 for HTTP-POST). We require the destination be correct
	// (a) if the IdP wants signed requests, (b) if it was provided, or (c)
	// if the request is signed.
	//
	// A request sent with the HTTP-POST-SimpleSign binding is signed, so it
	// must carry a Destination (sstc-saml-binding-simplesign-cs-01 §2.4).
	mustHaveDestination := req.IDP.WantAuthnRequestsSigned || req.Request.Destination != "" || req.isSigned()
	if mustHaveDestination {
		if req.Request.Destination != req.IDP.SSOURL.String() {
			return classify(fmt.Errorf("expected destination to be %q, not %q", req.IDP.SSOURL.String(), req.Request.Destination), ErrDestinationMismatch)
		}
	}

	if req.Request.IssueInstant.Add(req.IDP.maxIssueDelay()).Before(req.Now) {
		return classify(fmt.Errorf("request expired at %s",
			req.Request.IssueInstant.Add(req.IDP.maxIssueDelay())), ErrExpired)
	}
	// As for LogoutRequests, an IssueInstant later than the clock skew
	// allows is refused rather than trusted.
	if req.Request.IssueInstant.Add(-req.IDP.maxClockSkew()).After(req.Now) {
		return classify(fmt.Errorf("request IssueInstant %s is in the future", req.Request.IssueInstant), ErrNotYetValid)
	}
	if req.Request.Version != "2.0" {
		return classify(fmt.Errorf("expected SAML request version 2.0 got %v", req.Request.Version), ErrUnsupported, errVersionMismatch)
	}
	// The Response answers the request by its ID (saml-core §3.2.1: ID is
	// required, and InResponseTo must match it). Without one the Response
	// would carry no InResponseTo and look unsolicited.
	if req.Request.ID == "" {
		return classify(errors.New("authn request is missing an ID"), ErrMissingElement)
	}
	return nil
}

// resolveServiceProvider is the part of Validate that looks up the service
// provider that issued the request, checks its signature (see
// verifySignature), and selects the assertion consumer service the
// Response goes to. It sets ServiceProviderMetadata, SPSSODescriptor and
// ACSEndpoint.
func (req *IdpAuthnRequest) resolveServiceProvider() error {
	// find the service provider
	if req.Request.Issuer == nil {
		return classify(fmt.Errorf("authn request is missing an issuer"), ErrMissingElement)
	}
	serviceProviderID := req.Request.Issuer.Value
	serviceProvider, err := req.IDP.ServiceProviderProvider.GetServiceProvider(req.HTTPRequest, serviceProviderID)
	if errors.Is(err, os.ErrNotExist) {
		return classify(fmt.Errorf("cannot handle request from unknown service provider %s", serviceProviderID), ErrUnknownServiceProvider, os.ErrNotExist)
	} else if err != nil {
		return fmt.Errorf("cannot find service provider %s: %w", serviceProviderID, err)
	}
	if serviceProvider == nil {
		return classify(fmt.Errorf("cannot find service provider %s", serviceProviderID), ErrUnknownServiceProvider)
	}
	req.ServiceProviderMetadata = serviceProvider

	if err := req.verifySignature(); err != nil {
		return err
	}

	// Check that the ACS URL matches an ACS endpoint in the SP metadata.
	if err := req.getACSEndpoint(); err != nil {
		if errors.Is(err, errUnsupportedACSBinding) {
			return fmt.Errorf("cannot find assertion consumer service: %w", err)
		}
		return classify(fmt.Errorf("cannot find assertion consumer service: %w", err), ErrUnknownAssertionConsumerService)
	}

	return nil
}

// getACSEndpoint finds the AssertionConsumerService endpoint the response is
// sent to and sets SPSSODescriptor and ACSEndpoint.
//
// An endpoint named by AssertionConsumerServiceIndex is used whatever its
// binding, and an endpoint named by AssertionConsumerServiceURL is chosen as
// selectACSEndpointByURL describes. Without either, the response goes to
// "the default location associated with the requester" (saml-core §3.4.1):
// the default endpoint among those the IdP can send a Response to, chosen
// by selectDefaultACSEndpoint.
//
// When StrictACSBinding is set and an endpoint has the requested URL but
// none there has the requested ProtocolBinding, it returns an error
// matching errUnsupportedACSBinding.
func (req *IdpAuthnRequest) getACSEndpoint() error {
	if index := req.Request.AssertionConsumerServiceIndex; index != "" {
		if req.selectACSEndpoint(func(ep *IndexedEndpoint) bool { return strconv.Itoa(ep.Index) == index }) {
			return nil
		}
	}

	if acsURL := req.Request.AssertionConsumerServiceURL; acsURL != "" {
		if req.selectACSEndpointByURL(acsURL) {
			return nil
		}
		if req.strictACSBinding() {
			if _, ep := req.findACSEndpoint(func(ep *IndexedEndpoint) bool { return ep.Location == acsURL }); ep != nil {
				return classify(fmt.Errorf("no assertion consumer service at %q has binding %q", acsURL, req.Request.ProtocolBinding),
					ErrUnsupported, errUnsupportedACSBinding)
			}
		}
	}

	// Some service providers, like the Microsoft Azure AD service provider, issue
	// assertion requests that don't specify an ACS url at all.
	if req.Request.AssertionConsumerServiceURL == "" && req.Request.AssertionConsumerServiceIndex == "" {
		if req.selectDefaultACSEndpoint() {
			return nil
		}
	}

	return os.ErrNotExist // no ACS url found or specified
}

// errUnsupportedACSBinding is attached, with ErrUnsupported, when the IdP
// cannot send a Response with the binding an AuthnRequest asks for, so that
// ServeSSO can answer it with the status Requester and the second-level
// status UnsupportedBinding.
var errUnsupportedACSBinding = errors.New("saml: unsupported assertion consumer service binding")

// strictACSBinding reports whether the request's ProtocolBinding must match
// the Binding of the endpoint at its AssertionConsumerServiceURL: when it
// has one and StrictACSBinding is set.
func (req *IdpAuthnRequest) strictACSBinding() bool {
	return req.Request.ProtocolBinding != "" && req.IDP != nil && req.IDP.StrictACSBinding
}

// selectACSEndpointByURL selects the ACS endpoint at acsURL, and reports
// whether there is one.
//
// When StrictACSBinding is set and the request has a ProtocolBinding, the
// endpoint must have both that Location and that Binding.
//
// Otherwise it is matched by Location; an HTTP-POST-SimpleSign endpoint
// there is preferred when ProtocolBinding asks for that binding, and is
// otherwise only used when no endpoint with another binding has that
// Location and ProtocolBinding is empty. So a service provider that lists
// both bindings at one URL keeps getting HTTP-POST unless it asks for
// SimpleSign. Among the other endpoints at that Location, an HTTP-POST one
// is preferred when ProtocolBinding is HTTP-POST or empty, so that one
// listed after, say, an HTTP-Artifact endpoint there is still used.
func (req *IdpAuthnRequest) selectACSEndpointByURL(acsURL string) bool {
	binding := req.Request.ProtocolBinding
	if req.strictACSBinding() {
		return req.selectACSEndpoint(func(ep *IndexedEndpoint) bool {
			return ep.Location == acsURL && ep.Binding == binding
		})
	}

	preferPost := binding == "" || binding == HTTPPostBinding
	atURL := func(simpleSign bool) bool {
		if !simpleSign && preferPost && req.selectACSEndpoint(func(ep *IndexedEndpoint) bool {
			return ep.Location == acsURL && ep.Binding == HTTPPostBinding
		}) {
			return true
		}
		return req.selectACSEndpoint(func(ep *IndexedEndpoint) bool {
			return ep.Location == acsURL && (ep.Binding == HTTPPostSimpleSignBinding) == simpleSign
		})
	}
	switch binding {
	case HTTPPostSimpleSignBinding:
		return atURL(true) || atURL(false)
	case "":
		return atURL(false) || atURL(true)
	default:
		return atURL(false)
	}
}

// selectDefaultACSEndpoint selects the service provider's default
// AssertionConsumerService endpoint among those the IdP can send a Response
// to (see isSendableBinding), and reports whether there is one.
// saml-metadata §2.2.3: "the default endpoint is the first such endpoint
// with the isDefault attribute set to true. If no such endpoints exist, the
// default endpoint is the first such endpoint without the isDefault
// attribute set to false. If no such endpoints exist, the default endpoint
// is the first element in the sequence."
func (req *IdpAuthnRequest) selectDefaultACSEndpoint() bool {
	return req.selectACSEndpoint(func(ep *IndexedEndpoint) bool {
		return isSendableBinding(ep.Binding) && ep.IsDefault != nil && *ep.IsDefault
	}) || req.selectACSEndpoint(func(ep *IndexedEndpoint) bool {
		return isSendableBinding(ep.Binding) && (ep.IsDefault == nil || *ep.IsDefault)
	}) || req.selectACSEndpoint(func(ep *IndexedEndpoint) bool {
		return isSendableBinding(ep.Binding)
	})
}

// selectACSEndpoint sets SPSSODescriptor and ACSEndpoint to the first
// AssertionConsumerService endpoint in the service provider metadata for
// which match returns true, and reports whether there is one.
func (req *IdpAuthnRequest) selectACSEndpoint(match func(*IndexedEndpoint) bool) bool {
	spssoDescriptor, endpoint := req.findACSEndpoint(match)
	if endpoint == nil {
		return false
	}
	req.SPSSODescriptor = spssoDescriptor
	req.ACSEndpoint = endpoint
	return true
}

// findACSEndpoint returns copies of the first AssertionConsumerService
// endpoint in the service provider metadata for which match returns true
// and of its SPSSODescriptor, or nils if there is none.
//
// An endpoint whose Location is not an http or https URL is skipped, as for
// SingleLogoutService endpoints: metadata built in Go, rather than parsed,
// has not had its locations checked, and the Location becomes the
// Response's Destination and the action of the form that posts it.
func (req *IdpAuthnRequest) findACSEndpoint(match func(*IndexedEndpoint) bool) (*SPSSODescriptor, *IndexedEndpoint) {
	for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
			if _, err := checkEndpointLocation(endpoint.Binding, endpoint.Location); err != nil {
				continue
			}
			if match(&endpoint) {
				// Copy, so that the pointers do not alias the metadata.
				spssoDescriptor, endpoint := spssoDescriptor, endpoint
				return &spssoDescriptor, &endpoint
			}
		}
	}
	return nil, nil
}

// isSendableBinding reports whether the IdP can send a Response to an
// assertion consumer service with binding: HTTP-POST or
// HTTP-POST-SimpleSign. HTTP-Redirect cannot carry a Response with an
// assertion (saml-profiles §4.1.2), and HTTP-Artifact is not supported.
func isSendableBinding(binding string) bool {
	return binding == HTTPPostBinding || binding == HTTPPostSimpleSignBinding
}

// hostFromRemoteAddr returns the host part of an http.Request RemoteAddr,
// which is normally "IP:port". SubjectConfirmationData/@Address and
// SubjectLocality/@Address hold a network address without a port
// (saml-core-2.0-os §2.4.1.2 and §2.7.2.1), and service providers that check
// the address (e.g. Shibboleth) reject "IP:port". If RemoteAddr has no port,
// it is returned unchanged.
func hostFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// nonAlphanumeric matches what DefaultAssertionMaker ignores when it
// matches the name of a requested attribute.
var nonAlphanumeric = regexp.MustCompile("[^A-Za-z0-9]+")

// DefaultAssertionMaker produces a SAML assertion for the
// given request and assigns it to req.Assertion.
type DefaultAssertionMaker struct {
}

// MakeAssertion implements AssertionMaker. It produces a SAML assertion from the
// given request and assigns it to req.Assertion.
func (DefaultAssertionMaker) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	authnContextClassRef, err := req.authnContextClassRef(session)
	if err != nil {
		return err
	}

	attributes := []Attribute{}

	attributeConsumingService := defaultAttributeConsumingService(req.SPSSODescriptor)

	for _, requestedAttribute := range attributeConsumingService.RequestedAttributes {
		// "If no NameFormat value is provided, the identifier
		// urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified ... is in
		// effect" (saml-core §2.7.3.1).
		switch requestedAttribute.NameFormat {
		case "", attrname.FormatBasic, attrname.FormatUnspecified:
			// The name is compared case-sensitively: string values "MUST be
			// compared using an exact binary comparison" and implementations
			// "MUST NOT depend on case-insensitive string comparisons"
			// (saml-core §1.3.1). Punctuation is removed before comparing,
			// as this code always has, so "email_address" matches
			// "emailaddress"; that is a convenience beyond the specification.
			attrName := nonAlphanumeric.ReplaceAllString(requestedAttribute.Name, "")
			switch attrName {
			case "email", "emailaddress":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserEmail,
					}},
				})
			case "name", "fullname", "cn", "commonname":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserCommonName,
					}},
				})
			case "givenname", "firstname":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserGivenName,
					}},
				})
			case "surname", "lastname", "familyname":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserSurname,
					}},
				})
			case "uid", "user", "userid":
				attributes = append(attributes, Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserName,
					}},
				})
			}
		}
	}

	if session.UserName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "uid",
			Name:         attrname.UID,
			NameFormat:   attrname.FormatURI,
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserName,
			}},
		})
	}

	if session.UserEmail != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "mail",
			Name:         attrname.Mail,
			NameFormat:   attrname.FormatURI,
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserEmail,
			}},
		})
	}
	if session.EduPersonPrincipalName != "" || session.UserEmail != "" {
		value := session.EduPersonPrincipalName
		if value == "" {
			// We used to set eduPersonPrincipalName (urn:oid:1.3.6.1.4.1.5923.1.1.1.6)
			// to the value of session.UserEmail. It is more correct to set
			// mail (urn:oid:0.9.2342.19200300.100.1.3). To avoid breaking things,
			// we preserve the former behavior.
			value = session.UserEmail
		}

		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonPrincipalName",
			Name:         attrname.EduPersonPrincipalName,
			NameFormat:   attrname.FormatURI,
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: value,
			}},
		})
	}
	if session.UserSurname != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "sn",
			Name:         attrname.Surname,
			NameFormat:   attrname.FormatURI,
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserSurname,
			}},
		})
	}
	if session.UserGivenName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "givenName",
			Name:         attrname.GivenName,
			NameFormat:   attrname.FormatURI,
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserGivenName,
			}},
		})
	}

	if session.UserCommonName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "cn",
			Name:         attrname.CommonName,
			NameFormat:   attrname.FormatURI,
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserCommonName,
			}},
		})
	}

	if session.UserScopedAffiliation != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonScopedAffiliation",
			Name:         attrname.EduPersonScopedAffiliation,
			NameFormat:   attrname.FormatURI,
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserScopedAffiliation,
			}},
		})
	}

	attributes = append(attributes, session.CustomAttributes...)

	if len(session.Groups) != 0 {
		groupMemberAttributeValues := make([]AttributeValue, 0, len(session.Groups))
		for _, group := range session.Groups {
			groupMemberAttributeValues = append(groupMemberAttributeValues, AttributeValue{
				Type:  "xs:string",
				Value: group,
			})
		}
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonAffiliation",
			Name:         attrname.EduPersonAffiliation,
			NameFormat:   attrname.FormatURI,
			Values:       groupMemberAttributeValues,
		})
	}

	if session.SubjectID != "" {
		attributes = append(attributes, Attribute{
			Name:       attrname.SubjectID,
			NameFormat: attrname.FormatURI,
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: session.SubjectID,
				},
			},
		})
	}

	// allow for some clock skew in the validity period using the
	// issuer's apparent clock, but never start the validity period after
	// now: the request's IssueInstant comes from the service provider, and
	// a later one would postdate the assertion.
	notBefore := req.Now.Add(-1 * req.IDP.maxClockSkew())
	notOnOrAfterAfter := req.Now.Add(req.IDP.maxIssueDelay())
	if notBefore.Before(req.Request.IssueInstant) {
		notBefore = req.Request.IssueInstant
		if notBefore.After(req.Now) {
			notBefore = req.Now
		}
		notOnOrAfterAfter = notBefore.Add(req.IDP.maxIssueDelay())
	}
	// The subject confirmation window SHOULD fall within the assertion's
	// (saml-core §2.4.1.2), so it ends no later than the Conditions.
	confirmationNotOnOrAfter := req.Now.Add(req.IDP.maxIssueDelay())
	if notOnOrAfterAfter.Before(confirmationNotOnOrAfter) {
		confirmationNotOnOrAfter = notOnOrAfterAfter
	}

	nameID, err := req.makeAssertionNameID(session)
	if err != nil {
		return err
	}

	remoteAddress := hostFromRemoteAddr(req.HTTPRequest.RemoteAddr)

	req.Assertion = &Assertion{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant: req.IDP.now(),
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.entityID(),
		},
		Subject: &Subject{
			NameID: nameID,
			SubjectConfirmations: []SubjectConfirmation{
				{
					Method: bearerSubjectConfirmationMethod,
					SubjectConfirmationData: &SubjectConfirmationData{
						Address:      remoteAddress,
						InResponseTo: req.Request.ID,
						NotOnOrAfter: confirmationNotOnOrAfter,
						Recipient:    req.ACSEndpoint.Location,
					},
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfterAfter,
			AudienceRestrictions: []AudienceRestriction{
				{
					Audience: Audience{Value: req.ServiceProviderMetadata.EntityID},
				},
			},
		},
		AuthnStatements: []AuthnStatement{
			{
				AuthnInstant: session.CreateTime,
				SessionIndex: session.Index,
				SubjectLocality: &SubjectLocality{
					Address: remoteAddress,
				},
				AuthnContext: AuthnContext{
					AuthnContextClassRef: &AuthnContextClassRef{
						Value: authnContextClassRef,
					},
				},
			},
		},
		AttributeStatements: []AttributeStatement{
			{
				Attributes: attributes,
			},
		},
	}

	return nil
}

// The Canonicalizer prefix list MUST be empty. Various implementations
// (maybe ours?) do not appear to support non-empty prefix lists in XML C14N.
const canonicalizerPrefixList = ""

// MakeAssertionEl sets `AssertionEl` to a signed, possibly encrypted, version of `Assertion`.
//
// When the request's NameIDPolicy Format is
// urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted and the service
// provider publishes an encryption certificate, the Subject's NameID is
// first replaced with a saml:EncryptedID that holds it, encrypted to that
// certificate with AssertionEncrypter (saml-core §2.2.4, §3.4.1.1,
// §8.3.9): Assertion.Subject.NameID is then nil and
// Assertion.Subject.EncryptedID is set. The NameID keeps the format it was
// issued with. Without a certificate, the NameID is issued as it is.
func (req *IdpAuthnRequest) MakeAssertionEl() error {
	if req.Assertion == nil {
		return errors.New("the request has no assertion: call MakeAssertion first")
	}
	signingContext, err := req.signingContext()
	if err != nil {
		return err
	}
	if err := req.encryptSubjectNameID(); err != nil {
		return err
	}

	assertionEl := req.Assertion.Element()

	signedAssertionEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return err
	}

	sigEl := signedAssertionEl.Child[len(signedAssertionEl.Child)-1]
	req.Assertion.Signature = sigEl.(*etree.Element)
	signedAssertionEl = req.Assertion.Element()

	certBuf, methods, err := encryptionKey(req.SPSSODescriptor.KeyDescriptors)
	if errors.Is(err, os.ErrNotExist) {
		req.AssertionEl = signedAssertionEl
		return nil
	} else if err != nil {
		return err
	}

	var signedAssertionBuf []byte
	{
		doc := etree.NewDocument()
		doc.SetRoot(signedAssertionEl)
		signedAssertionBuf, err = doc.WriteToBytes()
		if err != nil {
			return err
		}
	}

	var configured xmlenc.Encrypter
	if req.IDP != nil {
		configured = req.IDP.AssertionEncrypter
	}
	encryptor := assertionEncrypter(configured, methods)
	encryptedDataEl, err := encryptor.Encrypt(certBuf, signedAssertionBuf, nil)
	if err != nil {
		return err
	}
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")

	encryptedAssertionEl := etree.NewElement("saml:EncryptedAssertion")
	encryptedAssertionEl.AddChild(encryptedDataEl)
	req.AssertionEl = encryptedAssertionEl

	return nil
}

// requestsEncryptedNameID reports whether the request's NameIDPolicy asks
// for the encrypted NameID format (saml-core §3.4.1.1, §8.3.9).
func (req *IdpAuthnRequest) requestsEncryptedNameID() bool {
	policy := req.Request.NameIDPolicy
	return policy != nil && policy.Format != nil && *policy.Format == encryptedNameIDFormat
}

// encryptSubjectNameID replaces the NameID of the Subject of req.Assertion
// with an EncryptedID that holds it, if the request asks for the encrypted
// format and the service provider publishes an encryption certificate.
func (req *IdpAuthnRequest) encryptSubjectNameID() error {
	subject := req.Assertion.Subject
	if subject == nil || subject.NameID == nil || subject.EncryptedID != nil || req.SPSSODescriptor == nil || !req.requestsEncryptedNameID() {
		return nil
	}
	cert, methods, err := encryptionKey(req.SPSSODescriptor.KeyDescriptors)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var configured xmlenc.Encrypter
	if req.IDP != nil {
		configured = req.IDP.AssertionEncrypter
	}
	encryptedID, err := encryptIdentifier(subject.NameID.Element(), cert, assertionEncrypter(configured, methods))
	if err != nil {
		return fmt.Errorf("cannot encrypt NameID: %w", err)
	}
	subject.EncryptedID = encryptedID
	subject.NameID = nil
	return nil
}

// errNoACSEndpoint is returned when a response is to be made for an
// IdpAuthnRequest whose ACSEndpoint is not set, typically because Validate
// was not called or failed.
var errNoACSEndpoint = errors.New("the request has no assertion consumer service endpoint: call Validate first")

// assertionEncrypter returns the Encrypter for an assertion: configured, if
// it is set, and otherwise RSA-OAEP-MGF1P with a SHA-1 digest, which all
// implementations support, and a block cipher chosen from methods, the
// EncryptionMethods the service provider's metadata lists for its
// encryption key: the first of AES-256-GCM, AES-128-GCM, AES-192-GCM,
// AES-256-CBC, AES-128-CBC and AES-192-CBC that it lists. A service
// provider that lists none of them gets AES-128-CBC, as before, since
// many service providers that do not list their algorithms cannot decrypt
// AES-GCM.
func assertionEncrypter(configured xmlenc.Encrypter, methods []EncryptionMethod) xmlenc.Encrypter {
	if configured != nil {
		return configured
	}
	encrypter := xmlenc.OAEP()
	encrypter.DigestMethod = &xmlenc.SHA1
	encrypter.BlockCipher = xmlenc.AES128CBC
	listed := make(map[string]bool, len(methods))
	for _, method := range methods {
		listed[method.Algorithm] = true
	}
	for _, blockCipher := range identifierBlockCiphers {
		if listed[blockCipher.Algorithm()] {
			encrypter.BlockCipher = blockCipher
			break
		}
	}
	return encrypter
}

// IdpAuthnRequestForm contans HTML form information to be submitted to the
// SAML HTTP POST binding ACS.
type IdpAuthnRequestForm struct {
	URL          string
	SAMLResponse string
	RelayState   string
}

// PostBinding creates the HTTP POST form information for this
// `IdpAuthnRequest`. If `Response` is not already set, it calls MakeResponse
// to produce it.
func (req *IdpAuthnRequest) PostBinding() (IdpAuthnRequestForm, error) {
	var form IdpAuthnRequestForm

	// Check the endpoint before the response is signed (and perhaps
	// encrypted) for nothing.
	if req.ACSEndpoint == nil {
		return form, errNoACSEndpoint
	}
	if req.ACSEndpoint.Binding != HTTPPostBinding {
		entityID := ""
		if req.ServiceProviderMetadata != nil {
			entityID = req.ServiceProviderMetadata.EntityID
		}
		return form, classify(fmt.Errorf("%s: unsupported binding %s",
			entityID, req.ACSEndpoint.Binding), ErrUnsupported)
	}

	if req.ResponseEl == nil {
		if err := req.MakeResponse(); err != nil {
			return form, err
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	responseBuf, err := doc.WriteToBytes()
	if err != nil {
		return form, err
	}

	form.URL = req.ACSEndpoint.Location
	form.SAMLResponse = base64.StdEncoding.EncodeToString(responseBuf)
	form.RelayState = req.RelayState

	return form, nil
}

var defaultResponseFormTemplate = template.Must(template.New("saml-post-form").Parse(`` +
	`<html xmlns="http://www.w3.org/1999/xhtml">` +
	`<head><title>Continue</title></head>` +
	`<body>` +
	`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
	`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
	`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
	`<script>document.getElementById('SAMLResponseForm').submit();</script>` +
	`</body>` +
	`</html>`))

// WriteResponse writes the `Response` to the http.ResponseWriter. If
// `Response` is not already set, it calls MakeResponse to produce it.
//
// If the ACS endpoint uses the HTTP-POST-SimpleSign binding, the form is the
// one SimpleSignBinding describes, rendered with
// IdentityProvider.SimpleSignResponseFormTemplate. Otherwise it is the
// HTTP-POST form PostBinding describes, rendered with ResponseFormTemplate.
func (req *IdpAuthnRequest) WriteResponse(w http.ResponseWriter) error {
	setNoCacheHeaders(w.Header())
	if req.ACSEndpoint != nil && req.ACSEndpoint.Binding == HTTPPostSimpleSignBinding {
		return req.writeSimpleSignResponse(w)
	}

	form, err := req.PostBinding()
	if err != nil {
		return err
	}

	tmpl := req.IDP.ResponseFormTemplate
	if tmpl == nil {
		tmpl = defaultResponseFormTemplate
	}

	buf := bytes.NewBuffer(nil)
	if err := tmpl.Execute(buf, form); err != nil {
		return err
	}
	if _, err := io.Copy(w, buf); err != nil {
		return err
	}
	return nil
}

// getSPEncryptionCert returns the certificate which we can use to encrypt
// things to the SP, or os.ErrNotExist if no such certificate is found.
func (req *IdpAuthnRequest) getSPEncryptionCert() (*x509.Certificate, error) {
	cert, _, err := encryptionKey(req.SPSSODescriptor.KeyDescriptors)
	return cert, err
}

// unmarshalEtreeHack parses `el` and sets values in the structure `v`.
//
// This is a hack -- it first serializes the element, then uses xml.Unmarshal.
func unmarshalEtreeHack(el *etree.Element, v interface{}) error {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(buf, v)
}

// MakeResponse creates and assigns a new SAML response in ResponseEl. `Assertion` must
// be non-nil. If MakeAssertionEl() has not been called, this function calls it for
// you.
func (req *IdpAuthnRequest) MakeResponse() error {
	if req.ACSEndpoint == nil {
		return errNoACSEndpoint
	}
	if req.AssertionEl == nil {
		if err := req.MakeAssertionEl(); err != nil {
			return err
		}
	}

	response := &Response{
		Destination:  req.ACSEndpoint.Location,
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: req.Request.ID,
		IssueInstant: req.Now,
		Version:      "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.MetadataURL.String(),
		},
		Status: Status{
			StatusCode: StatusCode{
				Value: StatusSuccess,
			},
		},
	}

	responseEl := response.Element()
	responseEl.AddChild(req.AssertionEl) // AssertionEl either an EncryptedAssertion or Assertion element

	// Sign the response element (we've already signed the Assertion element)
	{
		signingContext, err := req.signingContext()
		if err != nil {
			return err
		}

		signedResponseEl, err := signingContext.SignEnveloped(responseEl)
		if err != nil {
			return err
		}

		sigEl := signedResponseEl.ChildElements()[len(signedResponseEl.ChildElements())-1]
		response.Signature = sigEl
		responseEl = response.Element()
		responseEl.AddChild(req.AssertionEl)
	}

	req.ResponseEl = responseEl
	return nil
}

// signingContext will create a signing context for the request.
func (req *IdpAuthnRequest) signingContext() (*dsig.SigningContext, error) {
	return req.IDP.signingContext()
}

// signingContext returns a signing context for the IdP's key and certificate.
func (idp *IdentityProvider) signingContext() (*dsig.SigningContext, error) {
	// A typed-nil key (for example the *rsa.PrivateKey returned by a failed
	// x509.ParsePKCS1PrivateKey call) is not == nil but panics when used to
	// sign, so check for that explicitly and return an error instead.
	useSigner := !signerutil.IsNil(idp.Signer)
	if !useSigner {
		if key, _ := idp.Key.(crypto.Signer); signerutil.IsNil(key) {
			return nil, errors.New("cannot sign: IdentityProvider.Key and IdentityProvider.Signer are both nil or invalid")
		}
	}
	if idp.Certificate == nil {
		return nil, errors.New("cannot sign: IdentityProvider.Certificate is nil")
	}

	// Create a cert chain based off of the IDP cert and its intermediates.
	certificates := make([][]byte, 0, 1+len(idp.Intermediates))
	certificates = append(certificates, idp.Certificate.Raw)
	for _, cert := range idp.Intermediates {
		certificates = append(certificates, cert.Raw)
	}

	var signingContext *dsig.SigningContext
	var err error
	// If signer is set, use it instead of the private key.
	if useSigner {
		signingContext, err = dsig.NewSigningContext(idp.Signer, certificates)
		if err != nil {
			return nil, err
		}
	} else {
		keyPair := tls.Certificate{
			Certificate: certificates,
			PrivateKey:  idp.Key,
			Leaf:        idp.Certificate,
		}
		keyStore := dsig.TLSCertKeyStore(keyPair)

		signingContext = dsig.NewDefaultSigningContext(keyStore)
	}

	// Default to SHA-256 if the signature method isn't set. SHA-1 based
	// methods are deprecated for XML signatures.
	signatureMethod := idp.SignatureMethod
	if signatureMethod == "" {
		publicKey := idp.Certificate.PublicKey
		if useSigner {
			publicKey = idp.Signer.Public()
		}
		signatureMethod = defaultSignatureMethod(publicKey)
	}

	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(canonicalizerPrefixList)
	if err := signingContext.SetSignatureMethod(signatureMethod); err != nil {
		return nil, err
	}

	return signingContext, nil
}

// defaultAttributeConsumingService returns the SP's AttributeConsumingService
// marked isDefault, else its first one, else an empty one.
func defaultAttributeConsumingService(spSSODescriptor *SPSSODescriptor) *AttributeConsumingService {
	if spSSODescriptor == nil || len(spSSODescriptor.AttributeConsumingServices) == 0 {
		return &AttributeConsumingService{}
	}
	for i := range spSSODescriptor.AttributeConsumingServices {
		acs := spSSODescriptor.AttributeConsumingServices[i]
		if acs.IsDefault != nil && *acs.IsDefault {
			return &acs
		}
	}
	acs := spSSODescriptor.AttributeConsumingServices[0]
	return &acs
}
