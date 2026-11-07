// Package samlsp provides helpers that can be used to protect web services using SAML.
package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/signerutil"
)

// Options represents the parameters for creating a new middleware
type Options struct {
	EntityID              string
	URL                   url.URL
	Key                   crypto.Signer
	Certificate           *x509.Certificate
	Intermediates         []*x509.Certificate
	HTTPClient            *http.Client
	AllowIDPInitiated     bool
	DefaultRedirectURI    string
	IDPMetadata           *saml.EntityDescriptor
	SignRequest           bool
	UseArtifactResponse   bool
	ForceAuthn            bool // TODO(ross): this should be *bool
	RequestedAuthnContext *saml.RequestedAuthnContext
	// CookieSameSite sets the SameSite attribute of the session and request
	// tracking cookies. When it is unset and URL uses https, the request
	// tracking cookie is issued with SameSite=None, because browsers do not
	// send a SameSite=Lax cookie with the IDP's cross-site POST to the ACS URL.
	// See CookieRequestTracker.
	CookieSameSite http.SameSite
	CookieName     string
	RelayStateFunc func(w http.ResponseWriter, r *http.Request) string
	LogoutBindings []string

	// CookieDomain, if set, is the Domain attribute of the session cookie,
	// which makes the browser also send the cookie to subdomains of that
	// domain. If empty, the session cookie is a host-only cookie, sent only to
	// the host of URL.
	//
	// Earlier versions always scoped the session cookie to the host of URL.
	// To keep sharing the session with subdomains, set CookieDomain to that
	// host (or to a parent domain).
	CookieDomain string

	// EncryptionKey and EncryptionCertificate, if set, are used to decrypt
	// encrypted assertions and are advertised in the metadata for encryption,
	// instead of Key and Certificate. See saml.ServiceProvider.
	EncryptionKey         *rsa.PrivateKey
	EncryptionCertificate *x509.Certificate

	// DecryptionKeys are further keys that decrypt encrypted assertions, for
	// key rotation. See saml.ServiceProvider.
	DecryptionKeys []*rsa.PrivateKey

	// AssertionConsumerServiceBindings specify the bindings advertised for the
	// AssertionConsumerService endpoint in the SP metadata. If empty, both
	// HTTP-POST and HTTP-Artifact bindings are advertised. If set, it must
	// include the binding requested for responses (HTTP-Artifact when
	// UseArtifactResponse is true, HTTP-POST otherwise), or New returns an
	// error.
	AssertionConsumerServiceBindings []string

	// IgnoreCertificateExpiry, if true, accepts signatures made with an IDP
	// signing certificate outside its validity period. See
	// saml.ServiceProvider.IgnoreCertificateExpiry.
	IgnoreCertificateExpiry bool

	// MetadataPath, AcsPath and SloPath set the paths of the SAML metadata,
	// AssertionConsumerService and SingleLogoutService endpoints. Each is
	// resolved as a URL reference against URL, so a relative path (such as
	// the defaults "saml/metadata", "saml/acs" and "saml/slo") is appended to
	// the path of URL, and an absolute path (beginning with "/") replaces it.
	// Empty values use the defaults. When EntityID is empty the metadata URL is
	// used as the entity ID, so changing MetadataPath changes it too.
	MetadataPath string
	AcsPath      string
	SloPath      string

	// SessionKey, if set, signs and verifies the session JWTs and the
	// tracked-request JWTs issued by the default SessionCodec and
	// TrackedRequestCodec, instead of Key. Use it to keep the key that
	// protects this SP's own cookies separate from the SAML key, for example
	// so that the SAML key can live in an HSM or be rotated with the IdP
	// without invalidating sessions, or so that a leaked session key does not
	// let anyone sign SAML requests. The JWT signing method follows the type
	// of the key: RS256 for RSA, ES256/ES384/ES512 for ECDSA (by curve) and
	// EdDSA for Ed25519. If nil, Key is used, as before.
	//
	// Changing the session key invalidates existing sessions and pending
	// requests.
	SessionKey crypto.Signer
}

// sessionKey returns the key that signs session and tracked-request JWTs.
func sessionKey(opts Options) crypto.Signer {
	if !signerutil.IsNil(opts.SessionKey) {
		return opts.SessionKey
	}
	return opts.Key
}

func getDefaultSigningMethod(signer crypto.Signer) jwt.SigningMethod {
	if !signerutil.IsNil(signer) {
		switch pub := signer.Public().(type) {
		case ed25519.PublicKey:
			return jwt.SigningMethodEdDSA
		case *ecdsa.PublicKey:
			// The JWT ECDSA signing methods are bound to a specific curve, so
			// pick the one matching the key, otherwise signing fails.
			switch pub.Curve.Params().BitSize {
			case 384:
				return jwt.SigningMethodES384
			case 521:
				return jwt.SigningMethodES512
			default:
				return jwt.SigningMethodES256
			}
		case *rsa.PublicKey:
			return jwt.SigningMethodRS256
		}
	}
	return jwt.SigningMethodRS256
}

// DefaultSessionCodec returns the default SessionCodec for the provided options,
// a JWTSessionCodec configured to issue signed tokens.
func DefaultSessionCodec(opts Options) JWTSessionCodec {
	key := sessionKey(opts)
	return JWTSessionCodec{
		SigningMethod: getDefaultSigningMethod(key),
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        defaultSessionMaxAge,
		Key:           key,
	}
}

// DefaultSessionProvider returns the default SessionProvider for the provided options,
// a CookieSessionProvider configured to store sessions in a cookie.
func DefaultSessionProvider(opts Options) CookieSessionProvider {
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = defaultSessionCookieName
	}
	return CookieSessionProvider{
		Name:         cookieName,
		Domain:       opts.CookieDomain,
		MaxAge:       defaultSessionMaxAge,
		HTTPOnly:     true,
		Secure:       opts.URL.Scheme == "https",
		SameSite:     opts.CookieSameSite,
		Codec:        DefaultSessionCodec(opts),
		legacyDomain: legacySessionCookieDomain(opts),
	}
}

// legacySessionCookieDomain returns the Domain attribute that earlier versions
// of DefaultSessionProvider used for the session cookie (the host of
// opts.URL), or "" if that cookie cannot differ from the one set now.
func legacySessionCookieDomain(opts Options) string {
	host := opts.URL.Hostname()
	if host == "" || strings.EqualFold(host, opts.CookieDomain) {
		return ""
	}
	// net/http drops an IPv6 address from the Domain attribute, so earlier
	// versions set a host-only cookie in that case.
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return ""
	}
	return host
}

// DefaultTrackedRequestCodec returns a new TrackedRequestCodec for the provided
// options, a JWTTrackedRequestCodec that uses a JWT to encode TrackedRequests.
func DefaultTrackedRequestCodec(opts Options) JWTTrackedRequestCodec {
	key := sessionKey(opts)
	return JWTTrackedRequestCodec{
		SigningMethod: getDefaultSigningMethod(key),
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        saml.MaxIssueDelay,
		Key:           key,
	}
}

// DefaultRequestTracker returns a new RequestTracker for the provided options,
// a CookieRequestTracker which uses cookies to track pending requests.
func DefaultRequestTracker(opts Options, serviceProvider *saml.ServiceProvider) CookieRequestTracker {
	return CookieRequestTracker{
		ServiceProvider: serviceProvider,
		NamePrefix:      "saml_",
		Codec:           DefaultTrackedRequestCodec(opts),
		MaxAge:          saml.MaxIssueDelay,
		RelayStateFunc:  opts.RelayStateFunc,
		SameSite:        opts.CookieSameSite,
	}
}

// DefaultServiceProvider returns the default saml.ServiceProvider for the provided
// options.
func DefaultServiceProvider(opts Options) saml.ServiceProvider {
	metadataURL := opts.URL.ResolveReference(&url.URL{Path: pathOrDefault(opts.MetadataPath, "saml/metadata")})
	acsURL := opts.URL.ResolveReference(&url.URL{Path: pathOrDefault(opts.AcsPath, "saml/acs")})
	sloURL := opts.URL.ResolveReference(&url.URL{Path: pathOrDefault(opts.SloPath, "saml/slo")})

	var forceAuthn *bool
	if opts.ForceAuthn {
		forceAuthn = &opts.ForceAuthn
	}

	signatureMethod := defaultSigningMethodForKey(opts.Key)
	if !opts.SignRequest {
		signatureMethod = ""
	}

	if opts.DefaultRedirectURI == "" {
		opts.DefaultRedirectURI = "/"
	}

	if len(opts.LogoutBindings) == 0 {
		opts.LogoutBindings = []string{saml.HTTPPostBinding}
	}

	return saml.ServiceProvider{
		EntityID:              opts.EntityID,
		Key:                   opts.Key,
		Certificate:           opts.Certificate,
		HTTPClient:            opts.HTTPClient,
		Intermediates:         opts.Intermediates,
		EncryptionKey:         opts.EncryptionKey,
		EncryptionCertificate: opts.EncryptionCertificate,
		DecryptionKeys:        opts.DecryptionKeys,
		MetadataURL:           *metadataURL,
		AcsURL:                *acsURL,
		SloURL:                *sloURL,
		IDPMetadata:           opts.IDPMetadata,
		ForceAuthn:            forceAuthn,
		RequestedAuthnContext: opts.RequestedAuthnContext,
		SignatureMethod:       signatureMethod,
		AllowIDPInitiated:     opts.AllowIDPInitiated,
		DefaultRedirectURI:    opts.DefaultRedirectURI,
		LogoutBindings:        opts.LogoutBindings,

		AssertionConsumerServiceBindings: opts.AssertionConsumerServiceBindings,
		IgnoreCertificateExpiry:          opts.IgnoreCertificateExpiry,
	}
}

func pathOrDefault(path, defaultPath string) string {
	if path == "" {
		return defaultPath
	}
	return path
}

// defaultSigningMethodForKey returns the signature method used for signed
// requests when Options.SignRequest is set. SHA-1 based methods are deprecated
// for XML signatures, so SHA-256 is used for both RSA and ECDSA keys. Callers
// that need a different method can set ServiceProvider.SignatureMethod on the
// returned Middleware.
func defaultSigningMethodForKey(key crypto.Signer) string {
	if signerutil.IsNil(key) {
		return ""
	}
	// Check public key type to support crypto.Signer implementations (KMS/HSM)
	// that aren't concrete *rsa.PrivateKey or *ecdsa.PrivateKey types
	switch key.Public().(type) {
	case *rsa.PublicKey:
		return dsig.RSASHA256SignatureMethod
	case *ecdsa.PublicKey:
		return dsig.ECDSASHA256SignatureMethod
	default:
		panic(fmt.Sprintf("programming error: unsupported public key type %T", key.Public()))
	}
}

// DefaultAssertionHandler returns the default AssertionHandler for the provided options,
// a NopAssertionHandler configured to do nothing.
func DefaultAssertionHandler(_ Options) NopAssertionHandler {
	return NopAssertionHandler{}
}

// New creates a new Middleware with the default providers for the
// given options.
//
// You can customize the behavior of the middleware in more detail by
// replacing and/or changing Session, RequestTracker, and ServiceProvider
// in the returned Middleware.
func New(opts Options) (*Middleware, error) {
	m := &Middleware{
		ServiceProvider:  DefaultServiceProvider(opts),
		Binding:          "",
		ResponseBinding:  saml.HTTPPostBinding,
		OnError:          DefaultOnError,
		Session:          DefaultSessionProvider(opts),
		AssertionHandler: DefaultAssertionHandler(opts),
	}
	m.RequestTracker = DefaultRequestTracker(opts, &m.ServiceProvider)
	if opts.UseArtifactResponse {
		m.ResponseBinding = saml.HTTPArtifactBinding
	}

	if len(opts.AssertionConsumerServiceBindings) > 0 &&
		!slices.Contains(opts.AssertionConsumerServiceBindings, m.ResponseBinding) {
		return nil, fmt.Errorf("samlsp: AssertionConsumerServiceBindings must include the response binding %q (set UseArtifactResponse to match)", m.ResponseBinding)
	}

	return m, nil
}
