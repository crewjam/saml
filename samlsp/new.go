// Package samlsp provides helpers that can be used to protect web services using SAML.
package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
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
	CookieSameSite        http.SameSite
	CookieName            string
	RelayStateFunc        func(w http.ResponseWriter, r *http.Request) string
	LogoutBindings        []string
}

func getDefaultSigningMethod(signer crypto.Signer) jwt.SigningMethod {
	if signer != nil {
		switch signer.Public().(type) {
		case *ecdsa.PublicKey:
			return jwt.SigningMethodES256
		case *rsa.PublicKey:
			return jwt.SigningMethodRS256
		}
	}
	return jwt.SigningMethodRS256
}

// DefaultSessionCodec returns the default SessionCodec for the provided options,
// a JWTSessionCodec configured to issue signed tokens.
func DefaultSessionCodec(opts Options) JWTSessionCodec {
	return JWTSessionCodec{
		SigningMethod: getDefaultSigningMethod(opts.Key),
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        defaultSessionMaxAge,
		Key:           opts.Key,
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
		Name:     cookieName,
		Domain:   opts.URL.Host,
		MaxAge:   defaultSessionMaxAge,
		HTTPOnly: true,
		Secure:   opts.URL.Scheme == "https",
		SameSite: opts.CookieSameSite,
		Codec:    DefaultSessionCodec(opts),
	}
}

// DefaultTrackedRequestCodec returns a new TrackedRequestCodec for the provided
// options, a JWTTrackedRequestCodec that uses a JWT to encode TrackedRequests.
func DefaultTrackedRequestCodec(opts Options) JWTTrackedRequestCodec {
	return JWTTrackedRequestCodec{
		SigningMethod: getDefaultSigningMethod(opts.Key),
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        saml.MaxIssueDelay,
		Key:           opts.Key,
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
	metadataURL := opts.URL.ResolveReference(&url.URL{Path: "saml/metadata"})
	acsURL := opts.URL.ResolveReference(&url.URL{Path: "saml/acs"})
	sloURL := opts.URL.ResolveReference(&url.URL{Path: "saml/slo"})

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
	}
}

func defaultSigningMethodForKey(key crypto.Signer) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return dsig.RSASHA1SignatureMethod
	case *ecdsa.PrivateKey:
		return dsig.ECDSASHA256SignatureMethod
	case nil:
		return ""
	default:
		panic(fmt.Sprintf("programming error: unsupported key type %T", key))
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

	return m, nil
}
