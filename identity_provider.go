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

	CustomAttributes []Attribute
}

// SessionProvider is an interface used by IdentityProvider to determine the
// Session associated with a request. For an example implementation, see
// GetSession in the samlidp package.
type SessionProvider interface {
	// GetSession returns the remote user session associated with the http.Request.
	//
	// If (and only if) the request is not associated with a session then GetSession
	// must complete the HTTP request and return nil.
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
	// which calls it) has been called. If it returns an error, the caller
	// logs it and replies with an HTTP 500 error, so an implementation
	// should return errors before it starts writing to w.
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

	// SimpleSignResponseFormTemplate, if set, replaces the default
	// auto-submitting HTML form used to send responses to ACS endpoints with
	// the HTTP-POST-SimpleSign binding. It is executed with an
	// IdpAuthnRequestSimpleSignForm and must post its SAMLResponse, SigAlg
	// and Signature fields, and RelayState when it is not empty (an empty
	// RelayState field would be included in the signed content).
	SimpleSignResponseFormTemplate *template.Template

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
	// digest and AES-128-CBC, for compatibility with existing service
	// providers.
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
	// and of AuthnRequests sent with the HTTP-POST-SimpleSign binding. The error matches ErrUnsupported. If false, SHA-1 is
	// accepted.
	RejectSHA1Signatures bool

	// LogoutBindings are the bindings advertised in the IdP metadata for the
	// SingleLogoutService at LogoutURL. When empty, only HTTP-Redirect is
	// advertised, as before. ServeSLO accepts LogoutRequests with both the
	// HTTP-Redirect and the HTTP-POST binding, so set it to
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
	ReplayCache AssertionReplayCache

	// HTTPClient is the client the IdP sends back-channel messages with:
	// the LogoutRequests it sends over the SOAP binding to the session
	// participants whose metadata lists a SOAP SingleLogoutService (see
	// StartLogout and ServeSLO). If nil, a client that gives up after 10
	// seconds and does not follow redirects is used.
	HTTPClient *http.Client
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
		EntityID:      idp.MetadataURL.String(),
		ValidUntil:    TimeNow().Add(validDuration),
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
		buf, _ = xml.MarshalIndent(idp.Metadata(), "", "  ")
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
// response is sent.
//
// If the assertion cannot be created or returned, a StatusInternalServerError
// response is sent.
//
// Set OnError to handle these failures differently.
func (idp *IdentityProvider) ServeSSO(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpAuthnRequest(idp, r)
	if err != nil {
		idp.onError(w, r, http.StatusBadRequest, fmt.Errorf("failed to parse request: %w", err))
		return
	}

	if err := req.Validate(); err != nil {
		idp.onError(w, r, http.StatusBadRequest, fmt.Errorf("failed to validate request: %w", err))
		return
	}

	// TODO(ross): we must check that the request ID has not been previously
	//   issued.

	session := idp.SessionProvider.GetSession(w, r, req)
	if session == nil {
		return
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = DefaultAssertionMaker{}
	}
	if err := assertionMaker.MakeAssertion(req, session); err != nil {
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

// ServeIDPInitiated handes an IDP-initiated authorization request. Requests of this
// type require us to know a registered service provider and (optionally) the RelayState
// that will be passed to the application.
//
// It responds with StatusNotFound if the service provider is unknown, and
// with StatusInternalServerError if the service provider cannot be looked up
// or has no usable assertion consumer service, or the assertion cannot be
// created or returned. Set OnError to handle these failures differently, or
// build a handler from NewIdpInitiatedRequest.
func (idp *IdentityProvider) ServeIDPInitiated(w http.ResponseWriter, r *http.Request, serviceProviderID string, relayState string) {
	req, err := idp.NewIdpInitiatedRequest(r, serviceProviderID, relayState)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrUnknownServiceProvider) {
			status = http.StatusNotFound
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
// login to the service provider serviceProviderID, with its metadata and the
// first HTTP-POST assertion consumer service in it resolved. It is the part
// of ServeIDPInitiated that runs before the SessionProvider is asked for a
// session.
//
// It returns an error matching ErrUnknownServiceProvider (and os.ErrNotExist)
// if the ServiceProviderProvider does not know serviceProviderID,
// ErrUnknownAssertionConsumerService if the service provider has no HTTP-POST
// assertion consumer service, and otherwise the ServiceProviderProvider's
// error, wrapped.
func (idp *IdentityProvider) NewIdpInitiatedRequest(r *http.Request, serviceProviderID string, relayState string) (*IdpAuthnRequest, error) {
	req := &IdpAuthnRequest{
		IDP:         idp,
		HTTPRequest: r,
		RelayState:  relayState,
		Now:         TimeNow(),
	}

	// Resolve the service provider and its ACS endpoint before the
	// SessionProvider is asked for a session, as ServeSSO does via Validate.
	// Otherwise a request for an unknown service provider would prompt the
	// user to log in before failing, and the SessionProvider would see a
	// request without ServiceProviderMetadata.
	var err error
	req.ServiceProviderMetadata, err = idp.ServiceProviderProvider.GetServiceProvider(r, serviceProviderID)
	if err == os.ErrNotExist {
		return nil, classify(fmt.Errorf("cannot find service provider: %s", serviceProviderID), ErrUnknownServiceProvider, os.ErrNotExist)
	} else if err != nil {
		return nil, fmt.Errorf("cannot find service provider %s: %w", serviceProviderID, err)
	}

	// find an ACS endpoint that we can use: the first HTTP-POST one, or,
	// if there is none, the first HTTP-POST-SimpleSign one.
	if !req.selectACSEndpoint(func(ep *IndexedEndpoint) bool { return ep.Binding == HTTPPostBinding }) {
		req.selectACSEndpoint(func(ep *IndexedEndpoint) bool { return ep.Binding == HTTPPostSimpleSignBinding })
	}
	if req.ACSEndpoint == nil {
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

	// simpleSign is the HTTP-POST-SimpleSign message the request arrived
	// in, or nil if it arrived with another binding. Validate checks its
	// signature once it knows the service provider.
	simpleSign *simpleSignMessage
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
		Now:         TimeNow(),
	}

	switch r.Method {
	case "GET":
		compressedRequest, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
		if err != nil {
			return nil, classify(fmt.Errorf("cannot decode request: %w", err), ErrMalformedMessage)
		}
		req.RequestBuffer, err = io.ReadAll(newSaferFlateReader(bytes.NewReader(compressedRequest)))
		if err != nil {
			return nil, classify(fmt.Errorf("cannot decompress request: %w", err), ErrMalformedMessage)
		}
		req.RelayState = r.URL.Query().Get("RelayState")
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

// Validate checks that the authentication request is valid and assigns
// the AuthnRequest and Metadata properties. Returns a non-nil error if the
// request is not valid.
//
// Signatures on requests sent with the HTTP-Redirect or HTTP-POST binding
// are not checked. A request sent with the HTTP-POST-SimpleSign binding must
// carry a valid SimpleSign signature made with a signing certificate from
// the service provider's metadata (its validity period is not checked), and
// a Destination equal to SSOURL; it is rejected otherwise.
func (req *IdpAuthnRequest) Validate() error {
	if err := xmlroundtrip.Validate(req.RequestBuffer); err != nil {
		return classify(err, ErrMalformedMessage)
	}

	if err := xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil { //nolint:gosec // parsing the untrusted request is the point; it was checked by xmlroundtrip.Validate above
		return classify(err, ErrMalformedMessage)
	}

	// We always have exactly one IDP SSO descriptor
	if len(req.IDP.Metadata().IDPSSODescriptors) != 1 {
		panic("expected exactly one IDP SSO descriptor in IDP metadata")
	}
	idpSsoDescriptor := req.IDP.Metadata().IDPSSODescriptors[0]

	// TODO(ross): support signed authn requests
	// For now we do the safe thing and fail in the case where we think
	// requests might be signed.
	if idpSsoDescriptor.WantAuthnRequestsSigned != nil && *idpSsoDescriptor.WantAuthnRequestsSigned {
		return classify(fmt.Errorf("authn request signature checking is not currently supported"), ErrUnsupported)
	}

	// In http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf §3.4.5.2
	// we get a description of the Destination attribute:
	//
	//   If the message is signed, the Destination XML attribute in the root SAML
	//   element of the protocol message MUST contain the URL to which the sender
	//   has instructed the user agent to deliver the message. The recipient MUST
	//   then verify that the value matches the location at which the message has
	//   been received.
	//
	// We require the destination be correct either (a) if signing is enabled or
	// (b) if it was provided.
	//
	// A request sent with the HTTP-POST-SimpleSign binding is signed, so it
	// must carry a Destination (sstc-saml-binding-simplesign-cs-01 §2.4).
	mustHaveDestination := idpSsoDescriptor.WantAuthnRequestsSigned != nil && *idpSsoDescriptor.WantAuthnRequestsSigned
	mustHaveDestination = mustHaveDestination || req.Request.Destination != "" || req.simpleSign != nil
	if mustHaveDestination {
		if req.Request.Destination != req.IDP.SSOURL.String() {
			return classify(fmt.Errorf("expected destination to be %q, not %q", req.IDP.SSOURL.String(), req.Request.Destination), ErrDestinationMismatch)
		}
	}

	if req.Request.IssueInstant.Add(MaxIssueDelay).Before(req.Now) {
		return classify(fmt.Errorf("request expired at %s",
			req.Request.IssueInstant.Add(MaxIssueDelay)), ErrExpired)
	}
	if req.Request.Version != "2.0" {
		return classify(fmt.Errorf("expected SAML request version 2.0 got %v", req.Request.Version), ErrUnsupported)
	}
	// The Response answers the request by its ID (saml-core §3.2.1: ID is
	// required, and InResponseTo must match it). Without one the Response
	// would carry no InResponseTo and look unsolicited.
	if req.Request.ID == "" {
		return classify(errors.New("authn request is missing an ID"), ErrMissingElement)
	}

	// find the service provider
	if req.Request.Issuer == nil {
		return classify(fmt.Errorf("authn request is missing an issuer"), ErrMissingElement)
	}
	serviceProviderID := req.Request.Issuer.Value
	serviceProvider, err := req.IDP.ServiceProviderProvider.GetServiceProvider(req.HTTPRequest, serviceProviderID)
	if err == os.ErrNotExist {
		return classify(fmt.Errorf("cannot handle request from unknown service provider %s", serviceProviderID), ErrUnknownServiceProvider, os.ErrNotExist)
	} else if err != nil {
		return fmt.Errorf("cannot find service provider %s: %w", serviceProviderID, err)
	}
	req.ServiceProviderMetadata = serviceProvider

	if req.simpleSign != nil {
		if err := req.verifySimpleSignSignature(); err != nil {
			return fmt.Errorf("cannot verify HTTP-POST-SimpleSign signature: %w", err)
		}
	}

	// Check that the ACS URL matches an ACS endpoint in the SP metadata.
	if err := req.getACSEndpoint(); err != nil {
		return classify(fmt.Errorf("cannot find assertion consumer service: %w", err), ErrUnknownAssertionConsumerService)
	}

	return nil
}

// getACSEndpoint finds the AssertionConsumerService endpoint the response is
// sent to and sets SPSSODescriptor and ACSEndpoint.
//
// An endpoint named by AssertionConsumerServiceIndex is used whatever its
// binding. An endpoint named by AssertionConsumerServiceURL is matched by
// Location; an HTTP-POST-SimpleSign endpoint there is preferred when
// ProtocolBinding asks for that binding, and is otherwise only used when no
// endpoint with another binding has that Location and ProtocolBinding is
// empty. So a service provider that lists both bindings at one URL keeps
// getting HTTP-POST unless it asks for SimpleSign. Without either, the
// default endpoint (HTTP-POST, HTTP-Redirect or HTTP-POST-SimpleSign) is
// used, then any HTTP-POST or HTTP-Redirect endpoint, then any
// HTTP-POST-SimpleSign endpoint.
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
	}

	// Some service providers, like the Microsoft Azure AD service provider, issue
	// assertion requests that don't specify an ACS url at all.
	if req.Request.AssertionConsumerServiceURL == "" && req.Request.AssertionConsumerServiceIndex == "" {
		// find a default ACS binding in the metadata that we can use
		if req.selectACSEndpoint(func(ep *IndexedEndpoint) bool {
			return ep.IsDefault != nil && *ep.IsDefault && (isPostOrRedirect(ep.Binding) || ep.Binding == HTTPPostSimpleSignBinding)
		}) {
			return nil
		}

		// if we can't find a default, use *any* ACS binding
		if req.selectACSEndpoint(func(ep *IndexedEndpoint) bool { return isPostOrRedirect(ep.Binding) }) {
			return nil
		}
		if req.selectACSEndpoint(func(ep *IndexedEndpoint) bool { return ep.Binding == HTTPPostSimpleSignBinding }) {
			return nil
		}
	}

	return os.ErrNotExist // no ACS url found or specified
}

// selectACSEndpointByURL selects the ACS endpoint at acsURL, as described for
// getACSEndpoint, and reports whether there is one.
func (req *IdpAuthnRequest) selectACSEndpointByURL(acsURL string) bool {
	atURL := func(simpleSign bool) func(*IndexedEndpoint) bool {
		return func(ep *IndexedEndpoint) bool {
			return ep.Location == acsURL && (ep.Binding == HTTPPostSimpleSignBinding) == simpleSign
		}
	}
	switch req.Request.ProtocolBinding {
	case HTTPPostSimpleSignBinding:
		return req.selectACSEndpoint(atURL(true)) || req.selectACSEndpoint(atURL(false))
	case "":
		return req.selectACSEndpoint(atURL(false)) || req.selectACSEndpoint(atURL(true))
	default:
		return req.selectACSEndpoint(atURL(false))
	}
}

// selectACSEndpoint sets SPSSODescriptor and ACSEndpoint to the first
// AssertionConsumerService endpoint in the service provider metadata for
// which match returns true, and reports whether there is one.
func (req *IdpAuthnRequest) selectACSEndpoint(match func(*IndexedEndpoint) bool) bool {
	for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
			if match(&endpoint) {
				// Copy, so that the pointers do not alias the metadata.
				spssoDescriptor, endpoint := spssoDescriptor, endpoint
				req.SPSSODescriptor = &spssoDescriptor
				req.ACSEndpoint = &endpoint
				return true
			}
		}
	}
	return false
}

func isPostOrRedirect(binding string) bool {
	return binding == HTTPPostBinding || binding == HTTPRedirectBinding
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

// DefaultAssertionMaker produces a SAML assertion for the
// given request and assigns it to req.Assertion.
type DefaultAssertionMaker struct {
}

// MakeAssertion implements AssertionMaker. It produces a SAML assertion from the
// given request and assigns it to req.Assertion.
func (DefaultAssertionMaker) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	attributes := []Attribute{}

	var attributeConsumingService *AttributeConsumingService
	for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
		if acs.IsDefault != nil && *acs.IsDefault {
			// explicitly copy loop iterator variables
			//
			// c.f. https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
			//
			// (note that I'm pretty sure this isn't strictly necessary because we break out of the loop immediately,
			// but it certainly doesn't hurt anything and may prevent bugs in the future.)
			acs := acs

			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
			// explicitly copy loop iterator variables
			//
			// c.f. https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
			//
			// (note that I'm pretty sure this isn't strictly necessary because we break out of the loop immediately,
			// but it certainly doesn't hurt anything and may prevent bugs in the future.)
			acs := acs

			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		attributeConsumingService = &AttributeConsumingService{}
	}

	for _, requestedAttribute := range attributeConsumingService.RequestedAttributes {
		if requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" || requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" {
			attrName := requestedAttribute.Name
			attrName = regexp.MustCompile("[^A-Za-z0-9]+").ReplaceAllString(attrName, "")
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
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserName,
			}},
		})
	}

	if session.UserEmail != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "mail",
			Name:         "urn:oid:0.9.2342.19200300.100.1.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
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
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: value,
			}},
		})
	}
	if session.UserSurname != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserSurname,
			}},
		})
	}
	if session.UserGivenName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserGivenName,
			}},
		})
	}

	if session.UserCommonName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserCommonName,
			}},
		})
	}

	if session.UserScopedAffiliation != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "scopedAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
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
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       groupMemberAttributeValues,
		})
	}

	if session.SubjectID != "" {
		attributes = append(attributes, Attribute{
			Name:       "urn:oasis:names:tc:SAML:attribute:subject-id",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: session.SubjectID,
				},
			},
		})
	}

	// allow for some clock skew in the validity period using the
	// issuer's apparent clock.
	notBefore := req.Now.Add(-1 * MaxClockSkew)
	notOnOrAfterAfter := req.Now.Add(MaxIssueDelay)
	if notBefore.Before(req.Request.IssueInstant) {
		notBefore = req.Request.IssueInstant
		notOnOrAfterAfter = notBefore.Add(MaxIssueDelay)
	}
	// The subject confirmation window SHOULD fall within the assertion's
	// (saml-core §2.4.1.2), so it ends no later than the Conditions.
	confirmationNotOnOrAfter := req.Now.Add(MaxIssueDelay)
	if notOnOrAfterAfter.Before(confirmationNotOnOrAfter) {
		confirmationNotOnOrAfter = notOnOrAfterAfter
	}

	nameIDFormat := "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

	if session.NameIDFormat != "" {
		nameIDFormat = session.NameIDFormat
	}

	remoteAddress := hostFromRemoteAddr(req.HTTPRequest.RemoteAddr)

	req.Assertion = &Assertion{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.Metadata().EntityID,
		},
		Subject: &Subject{
			NameID: &NameID{
				Format:          nameIDFormat,
				NameQualifier:   req.IDP.Metadata().EntityID,
				SPNameQualifier: req.ServiceProviderMetadata.EntityID,
				Value:           session.NameID,
			},
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
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
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
func (req *IdpAuthnRequest) MakeAssertionEl() error {
	signingContext, err := req.signingContext()
	if err != nil {
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

	certBuf, err := req.getSPEncryptionCert()
	if err == os.ErrNotExist {
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

	var encryptor xmlenc.Encrypter
	if req.IDP != nil && req.IDP.AssertionEncrypter != nil {
		encryptor = req.IDP.AssertionEncrypter
	} else {
		rsaEncryptor := xmlenc.OAEP()
		rsaEncryptor.BlockCipher = xmlenc.AES128CBC
		rsaEncryptor.DigestMethod = &xmlenc.SHA1
		encryptor = rsaEncryptor
	}
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

	if req.ACSEndpoint.Binding != HTTPPostBinding {
		return form, classify(fmt.Errorf("%s: unsupported binding %s",
			req.ServiceProviderMetadata.EntityID,
			req.ACSEndpoint.Binding), ErrUnsupported)
	}

	form.URL = req.ACSEndpoint.Location
	form.SAMLResponse = base64.StdEncoding.EncodeToString(responseBuf)
	form.RelayState = req.RelayState

	return form, nil
}

var defaultResponseFormTemplate = template.Must(template.New("saml-post-form").Parse(`<html>` +
	`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
	`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
	`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
	`<script>document.getElementById('SAMLResponseForm').submit();</script>` +
	`</html>`))

// WriteResponse writes the `Response` to the http.ResponseWriter. If
// `Response` is not already set, it calls MakeResponse to produce it.
//
// If the ACS endpoint uses the HTTP-POST-SimpleSign binding, the form is the
// one SimpleSignBinding describes, rendered with
// IdentityProvider.SimpleSignResponseFormTemplate. Otherwise it is the
// HTTP-POST form PostBinding describes, rendered with ResponseFormTemplate.
func (req *IdpAuthnRequest) WriteResponse(w http.ResponseWriter) error {
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
