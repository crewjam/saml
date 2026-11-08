package samlidp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/signerutil"
	"github.com/crewjam/saml/internal/timelimit"
	"github.com/crewjam/saml/x/samlsp/replay"
)

// Config is a SAML identity provider (IdP) and the service providers (SPs)
// it serves. Create one with New. A Config is immutable and safe for
// concurrent use.
type Config struct {
	serviceProviders ServiceProviderFunc
	entityID         string
	entityURL        url.URL
	ssoURL           url.URL

	key             crypto.Signer
	certificate     *x509.Certificate
	intermediates   []*x509.Certificate
	extraCerts      []*x509.Certificate
	signatureMethod string
	nameIDFormats   []saml.NameIDFormat
	replayState     ReplayState
	clock           *dsig.Clock
	rand            io.Reader
	clockSkew       time.Duration
	issueDelay      time.Duration
	metadataValid   time.Duration
	affiliated      func(ctx context.Context, serviceProvider, affiliation string) (bool, error)
	allowCBC        bool // EnableInsecureAESCBC
	allowSHA1       bool // EnableInsecureRSAOAEPSHA1

	idpOptions    []IdentityProviderOption
	metadataHooks []func(*saml.EntityDescriptor)
	checks        []func(*saml.IdentityProvider) error
}

// New returns a Config for the identity provider entityID, which serves the
// service providers whose metadata serviceProviders supplies.
//
// serviceProviders looks up the metadata of an SP by its entity ID, the
// Issuer of its AuthnRequests. It is called with the context of each
// method. See StaticServiceProviders.
//
// The entity ID is conventionally the URL where the IdP serves its
// metadata (see ServeMetadata), such as
// "https://idp.example.com/saml/metadata". The single sign-on service
// (SSO), where SPs send their AuthnRequests, is then beside it by default,
// at "sso": "https://idp.example.com/saml/sso" in that example. Serve
// ParseAuthnRequest there, or choose another URL with WithSSOURL. If the
// entity ID is not a URL, such as a URN, WithSSOURL is required.
//
// WithSigningKey is required: an IdP signs everything it sends.
//
// New returns an error if an argument is missing or a URL is not
// absolute. It does not call serviceProviders.
func New(entityID string, serviceProviders ServiceProviderFunc, opts ...Option) (*Config, error) {
	if entityID == "" {
		return nil, errors.New("samlidp: the entity ID is empty")
	}
	if serviceProviders == nil {
		return nil, errors.New("samlidp: no ServiceProviderFunc")
	}
	entityURL, err := url.Parse(entityID)
	if err != nil || entityURL.String() != entityID {
		return nil, fmt.Errorf("samlidp: the entity ID %q is not a URI", entityID)
	}
	c := &Config{serviceProviders: serviceProviders, entityID: entityID, entityURL: *entityURL}
	var o configOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyConfig(c, &o)
		}
	}

	if o.ssoURL != "" {
		if c.ssoURL, err = absoluteURL("SSO URL", o.ssoURL); err != nil {
			return nil, err
		}
	} else {
		if !entityURL.IsAbs() || entityURL.Host == "" {
			return nil, fmt.Errorf("samlidp: the entity ID %q is not a URL to put the SSO service beside; use WithSSOURL", entityID)
		}
		c.ssoURL = *entityURL.ResolveReference(&url.URL{Path: "sso"})
	}
	if signatureMethod(c.key) == "" || c.certificate == nil {
		return nil, errors.New("samlidp: WithSigningKey with an RSA or ECDSA key and its certificate is required")
	}
	if !c.key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(c.certificate.PublicKey) {
		return nil, errors.New("samlidp: the certificate of WithSigningKey is not for its key")
	}
	if c.signatureMethod != "" {
		if err := checkSignatureMethod(c.signatureMethod, c.key); err != nil {
			return nil, err
		}
	}
	if c.replayState == nil {
		c.replayState = &replay.Memory{Now: c.Now}
	}
	if err := c.encryption().checkConfigured(c.unrestrictedIdentityProvider(nil)); err != nil {
		return nil, err
	}
	if len(c.checks) > 0 {
		idp := c.identityProvider(nil)
		for _, check := range c.checks {
			if err := check(idp); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

// WithCheck adds a check that New runs on the saml.IdentityProvider it
// builds, with the IdentityProviderOptions passed to New applied: New
// returns its error. Packages that add options with
// IdentityProviderOptions use it to refuse settings that cannot work.
func WithCheck(check func(idp *saml.IdentityProvider) error) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.checks = append(c.checks, check) })
}

// Options returns an Option that applies opts in order, so that a package
// can offer a group of settings as one Option.
func Options(opts ...Option) Option {
	return optionFunc(func(c *Config, o *configOptions) {
		for _, opt := range opts {
			if opt != nil {
				opt.applyConfig(c, o)
			}
		}
	})
}

// harden turns on every check that package saml leaves off by default only
// for compatibility. An IdentityProviderOption can turn one off again.
func harden(idp *saml.IdentityProvider) {
	// Refuse AuthnRequests signed with SHA-1.
	idp.RejectSHA1Signatures = true
	// Honour the NameIDPolicy of the AuthnRequest (saml-core §3.4.1.1).
	idp.EnforceNameIDPolicy = true
	// Honour the RequestedAuthnContext of the AuthnRequest (saml-core
	// §3.3.2.2.1).
	idp.EnforceRequestedAuthnContext = true
	// Answer expired and non-2.0 requests with a SAML error Response.
	idp.SendErrorResponses = true
	// Keep the RelayState of IdP-initiated logins within 80 bytes
	// (saml-bindings §3.5.3).
	idp.LimitRelayStateLength = true
}

// absoluteURL parses s, which must be an absolute URL with a host.
func absoluteURL(what, s string) (url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return url.URL{}, fmt.Errorf("samlidp: invalid %s: %w", what, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return url.URL{}, fmt.Errorf("samlidp: the %s must be an absolute URL, not %q", what, s)
	}
	return *u, nil
}

// Option configures New.
type Option interface {
	applyConfig(c *Config, o *configOptions)
}

// configOptions holds options that New validates after applying them.
type configOptions struct {
	ssoURL string
}

type optionFunc func(c *Config, o *configOptions)

func (f optionFunc) applyConfig(c *Config, o *configOptions) { f(c, o) }

// WithSSOURL sets the absolute URL of the IdP's single sign-on service,
// where SPs send their AuthnRequests with the HTTP-Redirect and HTTP-POST
// bindings. The handler at this URL calls ParseAuthnRequest. The default is
// "sso" beside the entity ID (see New).
func WithSSOURL(ssoURL string) Option {
	return optionFunc(func(_ *Config, o *configOptions) { o.ssoURL = ssoURL })
}

// WithSigningKey sets the key that the IdP signs its Responses, assertions
// and metadata with, and its certificate, which the IdP metadata publishes,
// with any intermediates of its chain. It is required. The key must be an
// RSA or ECDSA key; it may be held in an HSM or KMS.
func WithSigningKey(key crypto.Signer, cert *x509.Certificate, intermediates ...*x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.key, c.certificate = key, cert
		c.intermediates = append([]*x509.Certificate(nil), intermediates...)
	})
}

// WithNextSigningCertificates publishes certs in the IdP metadata as
// signing keys too, after that of WithSigningKey, without signing with
// them. Use it to announce a new signing certificate before switching
// WithSigningKey to it, so that SPs that refresh the IdP metadata already
// trust it when the rollover happens, or to keep publishing the old one
// for a while afterwards.
func WithNextSigningCertificates(certs ...*x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.extraCerts = append(c.extraCerts, certs...)
	})
}

// WithSignatureMethod sets the XML signature algorithm of everything the
// IdP signs. It must suit the key of WithSigningKey:
// dsig.RSASHA256SignatureMethod, RSASHA384 or RSASHA512 for an RSA key,
// and dsig.ECDSASHA256SignatureMethod, ECDSASHA384 or ECDSASHA512 for an
// ECDSA key. SHA-1 is refused. The default is SHA-256.
func WithSignatureMethod(method string) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.signatureMethod = method })
}

// WithNameIDFormats sets the NameID formats that the IdP metadata says the
// IdP issues. The default is transient. It does not limit what Response
// issues, which is the Subject's NameIDFormat.
func WithNameIDFormats(formats ...saml.NameIDFormat) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.nameIDFormats = append(c.nameIDFormats, formats...)
	})
}

// WithMetadataValidity sets how long the IdP metadata is valid
// (validUntil) and may be cached (cacheDuration). The default is that of
// package saml, saml.DefaultValidDuration.
func WithMetadataValidity(d time.Duration) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.metadataValid = d })
}

// WithMetadata calls modify with the IdP metadata each time it is made, by
// Metadata, MetadataXML and ServeMetadata, after the other options have
// shaped it and before it is signed. Use it to add what no option adds,
// such as a SingleLogoutService or an extension element.
func WithMetadata(modify func(md *saml.EntityDescriptor)) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.metadataHooks = append(c.metadataHooks, modify)
	})
}

// WithClock sets the time source used for timestamps and to check validity
// periods: that of the saml.IdentityProvider each method builds, of Now,
// of the default ReplayState, and of ParseMetadata's validUntil check. It
// is mainly useful in tests. Without it, times come from saml.TimeNow, as
// in package saml.
func WithClock(clock *dsig.Clock) ClockOption { return ClockOption{clock} }

// ClockOption is the option that WithClock returns. It is both an Option,
// for New, and a MetadataOption, for ParseMetadata, whose validUntil check
// it judges.
type ClockOption struct{ clock *dsig.Clock }

func (o ClockOption) applyConfig(c *Config, _ *configOptions) { c.clock = o.clock }

func (o ClockOption) applyMetadata(m *metadataOptions) { m.clock = o.clock }

// WithRand sets the source of the cryptographically random bytes the
// identity provider needs: the IDs of the messages and metadata it issues,
// the keys, IVs and nonces used to encrypt assertions and NameIDs, and the
// artifacts and messages of x/samlidp/idpartifact and x/samlidp/idpslo. It
// sets saml.IdentityProvider.Rand, so it applies to this Config only. It is
// mainly useful in tests. Without it, crypto/rand is used.
func WithRand(r io.Reader) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.rand = r })
}

// WithClockSkew sets how far a service provider's clock may be from the
// IdP's: the leeway allowed when checking IssueInstant and NotOnOrAfter
// times and the AuthnInstant of a ForceAuthn request, and how far back
// the validity period of an assertion starts. It sets
// saml.IdentityProvider.MaxClockSkew, so it applies to this Config only.
// Zero, the default, means saml.MaxClockSkew.
func WithClockSkew(d time.Duration) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.clockSkew = d
		c.checks = append(c.checks, checkTimeLimits)
	})
}

// WithMaxIssueDelay sets the longest allowed time between the IssueInstant
// of a request from a service provider and its receipt, which also bounds
// how long replay records are kept and how long an issued assertion is
// valid. It sets saml.IdentityProvider.MaxIssueDelay, so it applies to
// this Config only. Zero, the default, means saml.MaxIssueDelay.
func WithMaxIssueDelay(d time.Duration) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.issueDelay = d
		c.checks = append(c.checks, checkTimeLimits)
	})
}

// checkTimeLimits refuses a negative clock skew or issue delay.
func checkTimeLimits(idp *saml.IdentityProvider) error {
	if idp.MaxClockSkew < 0 || idp.MaxIssueDelay < 0 {
		return errors.New("samlidp: WithClockSkew and WithMaxIssueDelay need a duration that is not negative")
	}
	return nil
}

// ClockSkew returns the clock skew the IdP allows: that of WithClockSkew
// (or of an IdentityProviderOption passed to New), or saml.MaxClockSkew.
func (c *Config) ClockSkew() time.Duration {
	return timelimit.IDPClockSkew(c.identityProvider(nil))
}

// MaxIssueDelay returns the issue delay the IdP allows: that of
// WithMaxIssueDelay (or of an IdentityProviderOption passed to New), or
// saml.MaxIssueDelay.
func (c *Config) MaxIssueDelay() time.Duration {
	return timelimit.IDPIssueDelay(c.identityProvider(nil))
}

// WithAffiliation sets how the IdP decides whether the service provider
// serviceProvider is a member of the affiliation affiliation, an
// SPNameQualifier other than its own entity ID that its NameIDPolicy asks
// for (saml-core §3.4.1.1): for example, by the AffiliateMembers of the
// AffiliationDescriptor in the affiliation's metadata (saml-metadata
// §2.5). Without it, or if it reports false, ParseAuthnRequest and
// Response refuse such a request with StatusInvalidNameIDPolicy; an error
// it returns is returned by them. Whatever it says, the NameID under that
// qualifier is the application's to choose: the same for every member of
// the affiliation.
func WithAffiliation(member func(ctx context.Context, serviceProvider, affiliation string) (bool, error)) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.affiliated = member })
}

// spNameQualifierError returns the error for req if it asks for an
// SPNameQualifier other than the SP's own entity ID that WithAffiliation
// does not allow, or nil. An IdentityProvider that does not enforce the
// NameIDPolicy ignores the SPNameQualifier.
func (c *Config) spNameQualifierError(ctx context.Context, idp *saml.IdentityProvider, req *AuthnRequest) error {
	q := req.SPNameQualifier
	if q == "" || q == req.ServiceProvider || !idp.EnforceNameIDPolicy {
		return nil
	}
	if c.affiliated != nil {
		ok, err := c.affiliated(ctx, req.ServiceProvider, q)
		if err != nil {
			return fmt.Errorf("samlidp: affiliation %q of service provider %q: %w", q, req.ServiceProvider, err)
		}
		if ok {
			return nil
		}
	}
	return &saml.StatusError{
		TopLevel:    saml.StatusRequester,
		SecondLevel: saml.StatusInvalidNameIDPolicy,
		Message:     "the service provider is not a member of the requested SPNameQualifier",
	}
}

// ReplayState records the messages a Config accepts, so that each is
// accepted only once: the signed AuthnRequests of ParseAuthnRequest, and
// the messages recorded with Config.Consume, such as the LogoutRequests and
// LogoutResponses of x/samlidp/idpslo. Consume records the message
// identified by key as accepted until expiresAt, after which the message
// could no longer be accepted anyway and the record may be dropped. It
// must fail with saml.ErrAssertionReplayed if key is already recorded with
// an expiry that has not passed; any other error refuses the message too.
// It must be safe for concurrent use, and may keep key.
//
// key is ReplayKey of the SP's entity ID and the message's ID: 32 bytes.
// ctx is that of the method that accepts the message, such as
// ParseAuthnRequest.
//
// It has the method set of samlsp.ReplayState, so one record, such as a
// replay.Memory of package github.com/crewjam/saml/x/samlsp/replay, or a
// database table, can serve an IdP and an SP alike.
type ReplayState interface {
	Consume(ctx context.Context, key []byte, expiresAt time.Time) error
}

// replayKeyLabel separates replay keys from other uses of SHA-256, and
// from the keys of package samlsp.
const replayKeyLabel = "github.com/crewjam/saml/x/samlidp replay key v1\x00"

// ReplayKey returns the key under which a ReplayState records the message
// whose ID is id, issued by the SP whose entity ID is sp: a SHA-256 hash of
// both. The entity ID is length-prefixed, so no other pair has the same
// key. id is that of an AuthnRequest, or, with a prefix that keeps them
// apart, that of a LogoutRequest ("LogoutRequest:") or a LogoutResponse
// ("LogoutResponse:") of x/samlidp/idpslo.
func ReplayKey(sp, id string) []byte {
	h := sha256.New()
	h.Write([]byte(replayKeyLabel))
	h.Write(binary.AppendUvarint(nil, uint64(len(sp))))
	h.Write([]byte(sp))
	h.Write([]byte(id))
	return h.Sum(nil)
}

// WithReplayState sets where ParseAuthnRequest records the signed
// AuthnRequests it accepts, and Consume the messages of other packages
// (see ReplayState), so that each is accepted only once. Unsigned
// AuthnRequests are not recorded: anyone can make a new one, so refusing a
// repeated one would protect nothing.
//
// By default, each Config records them in its own replay.Memory, which
// protects one process only. Applications served by several processes
// need state that the processes share.
func WithReplayState(state ReplayState) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.replayState = state })
}

// IdentityProviderOption customizes the saml.IdentityProvider that a
// Config method builds and uses, for settings that have no Option of
// their own. Pass it to New to apply it to every call, or to a single
// method: it is an Option, a ParseOption and a ResponseOption. The options
// of a call are applied after those passed to New.
//
// The IdentityProvider is used only to parse and validate requests and to
// make and sign Responses: its SessionProvider, ResponseWriter, OnError
// and ReplayCache are not used.
type IdentityProviderOption func(idp *saml.IdentityProvider)

func (f IdentityProviderOption) applyConfig(c *Config, _ *configOptions) {
	c.idpOptions = append(c.idpOptions, f)
}
func (f IdentityProviderOption) applyParse(o *parseOptions)       { o.idp = append(o.idp, f) }
func (f IdentityProviderOption) applyResponse(o *responseOptions) { o.idp = append(o.idp, f) }

// WithIdentityProvider returns an IdentityProviderOption that calls fn.
func WithIdentityProvider(fn func(idp *saml.IdentityProvider)) IdentityProviderOption {
	return IdentityProviderOption(fn)
}

// SignMetadata makes ServeMetadata and MetadataXML sign the IdP metadata
// with the key of WithSigningKey. Pass it to New. Metadata returns the
// metadata as a struct, which carries no signature.
var SignMetadata IdentityProviderOption = func(idp *saml.IdentityProvider) { idp.SignMetadata = true }

// RequireSignedAuthnRequests makes ParseAuthnRequest refuse unsigned
// AuthnRequests, with an error matching saml.ErrInvalidSignature, and the
// IdP metadata say so (WantAuthnRequestsSigned). Whether or not it is set,
// the AuthnRequests of an SP whose metadata says AuthnRequestsSigned must
// be signed, and every signature is verified.
var RequireSignedAuthnRequests IdentityProviderOption = func(idp *saml.IdentityProvider) { idp.WantAuthnRequestsSigned = true }

// EntityID returns the entity ID of the identity provider.
func (c *Config) EntityID() string { return c.entityID }

// SSOURL returns the URL of the IdP's single sign-on service.
func (c *Config) SSOURL() string { return c.ssoURL.String() }

// SSOPath returns the path of the SSO URL, to serve the handler that calls
// ParseAuthnRequest at, so that it cannot drift from the URL in the IdP
// metadata:
//
//	http.HandleFunc(config.SSOPath(), sso)
func (c *Config) SSOPath() string { return urlPath(&c.ssoURL) }

// MetadataPath returns the path of the entity ID, where the IdP metadata is
// conventionally served:
//
//	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)
//
// It returns "" if the entity ID is not an http or https URL, such as a
// URN; serve the metadata at a path of your choosing then.
func (c *Config) MetadataPath() string {
	u := c.entityURL
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return urlPath(&u)
}

// urlPath returns the path of u, escaped as in a URL, or "/" if it has
// none: the pattern to serve u at with an http.ServeMux.
func urlPath(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// signatureMethod returns the default XML signature method for key, or ""
// if key is nil or cannot make XML signatures.
func signatureMethod(key crypto.Signer) string {
	if signerutil.IsNil(key) {
		return ""
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		return dsig.RSASHA256SignatureMethod
	case *ecdsa.PublicKey:
		return dsig.ECDSASHA256SignatureMethod
	default:
		return ""
	}
}

// checkSignatureMethod returns an error if method cannot be used with key.
func checkSignatureMethod(method string, key crypto.Signer) error {
	_, isRSA := key.Public().(*rsa.PublicKey)
	switch method {
	case dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod:
		if !isRSA {
			return fmt.Errorf("samlidp: signature method %s needs an RSA key", method)
		}
	case dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		if isRSA {
			return fmt.Errorf("samlidp: signature method %s needs an ECDSA key", method)
		}
	case dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod:
		return fmt.Errorf("samlidp: SHA-1 signature method %s is refused", method)
	default:
		return fmt.Errorf("samlidp: unknown signature method %q", method)
	}
	return nil
}

// identityProvider returns a new saml.IdentityProvider configured from c,
// with the IdentityProviderOptions passed to New and then opts applied. It
// shares no slice with c, so that the options and the caller may change
// it while other calls use c.
func (c *Config) identityProvider(opts []IdentityProviderOption) *saml.IdentityProvider {
	idp := c.unrestrictedIdentityProvider(opts)
	c.encryption().apply(idp)
	return idp
}

// unrestrictedIdentityProvider is identityProvider without the encryption
// policy of EnableInsecureAESCBC and EnableInsecureRSAOAEPSHA1 applied.
func (c *Config) unrestrictedIdentityProvider(opts []IdentityProviderOption) *saml.IdentityProvider {
	method := c.signatureMethod
	if method == "" {
		method = signatureMethod(c.key)
	}
	idp := &saml.IdentityProvider{
		Signer:                  c.key,
		Certificate:             c.certificate,
		Intermediates:           slices.Clone(c.intermediates),
		ExtraCertificates:       slices.Clone(c.extraCerts),
		MetadataURL:             c.entityURL,
		SSOURL:                  c.ssoURL,
		SignatureMethod:         method,
		NameIDFormats:           slices.Clone(c.nameIDFormats),
		Clock:                   c.clock,
		Rand:                    c.Rand(),
		MaxClockSkew:            c.clockSkew,
		MaxIssueDelay:           c.issueDelay,
		ServiceProviderProvider: serviceProviderProvider{c.serviceProviders, c.clock},
		// Package saml logs what it refuses and ignores; this package
		// returns errors instead.
		Logger: log.New(io.Discard, "", 0),
	}
	if c.metadataValid > 0 {
		d := c.metadataValid
		idp.ValidDuration = &d
	}
	harden(idp)
	for _, opt := range c.idpOptions {
		if opt != nil {
			opt(idp)
		}
	}
	for _, opt := range opts {
		if opt != nil {
			opt(idp)
		}
	}
	return idp
}

// IdentityProvider returns the saml.IdentityProvider that the methods of c
// use, built for this call, with the IdentityProviderOptions passed to New
// and then opts applied. It is for handling SAML messages this package
// does not, such as single logout; the result is a new value, which may be
// changed. Its ServiceProviderProvider calls the ServiceProviderFunc of New
// with the context of the http.Request it is given.
//
// Its AssertionEncrypterFunc and LogoutNameIDEncrypterFunc enforce the
// encryption policy of New (see EnableInsecureAESCBC and
// EnableInsecureRSAOAEPSHA1): an AssertionEncrypter or
// LogoutNameIDEncrypter set by opts is moved into them, and checked when
// it is used. One set on the result afterwards is not checked.
func (c *Config) IdentityProvider(opts ...IdentityProviderOption) *saml.IdentityProvider {
	return c.identityProvider(opts)
}

// Metadata returns the metadata of this identity provider, to register it
// with service providers. It is not signed, whatever SignMetadata says:
// for the signed document, use MetadataXML.
func (c *Config) Metadata(opts ...IdentityProviderOption) *saml.EntityDescriptor {
	idp := c.identityProvider(opts)
	return c.metadata(idp)
}

// metadata returns the IdP metadata that idp describes, with what the
// options of c add.
func (c *Config) metadata(idp *saml.IdentityProvider) *saml.EntityDescriptor {
	md := idp.Metadata()
	for i := range md.IDPSSODescriptors {
		d := &md.IDPSSODescriptors[i]
		// The IdP of this package decrypts nothing, so it publishes no
		// encryption key (package saml publishes the signing certificate
		// for both uses).
		if idp.EncryptionCertificate == nil {
			keys := d.KeyDescriptors[:0]
			for _, k := range d.KeyDescriptors {
				if k.Use != "encryption" {
					keys = append(keys, k)
				}
			}
			d.KeyDescriptors = keys
		}
	}
	for _, modify := range c.metadataHooks {
		modify(md)
	}
	return md
}

// MetadataXML returns the metadata of this identity provider as the XML
// document that ServeMetadata serves: signed if SignMetadata was passed to
// New or is in opts.
func (c *Config) MetadataXML(opts ...IdentityProviderOption) ([]byte, error) {
	idp := c.identityProvider(opts)
	md := c.metadata(idp)
	if !idp.SignMetadata {
		return xml.MarshalIndent(md, "", "  ")
	}
	el, err := signMetadata(idp, md)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	return doc.WriteToBytes()
}

// ServeMetadata is an http.HandlerFunc that serves this identity
// provider's metadata, conventionally at the entity ID's URL. If New was
// passed SignMetadata, the metadata is signed.
func (c *Config) ServeMetadata(w http.ResponseWriter, _ *http.Request) {
	buf, err := c.MetadataXML()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(buf) //nolint:gosec // our own metadata, served as application/samlmetadata+xml
}

// signingContext returns a signing context for the key, certificates and
// signature method of idp.
func signingContext(idp *saml.IdentityProvider) (*dsig.SigningContext, error) {
	certs := make([][]byte, 0, 1+len(idp.Intermediates))
	certs = append(certs, idp.Certificate.Raw)
	for _, cert := range idp.Intermediates {
		certs = append(certs, cert.Raw)
	}
	ctx, err := dsig.NewSigningContext(idp.Signer, certs)
	if err != nil {
		return nil, err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(idp.SignatureMethod); err != nil {
		return nil, err
	}
	return ctx, nil
}

// signMetadata returns md as an element that carries an enveloped
// signature by idp, as its first child, which the metadata schema requires
// (saml-metadata-2.0-os §3). The signature references md by its ID, which
// is generated if md has none.
func signMetadata(idp *saml.IdentityProvider, md *saml.EntityDescriptor) (*etree.Element, error) {
	signer, err := signingContext(idp)
	if err != nil {
		return nil, err
	}
	unsigned := *md
	unsigned.Signature = nil
	if unsigned.ID == "" {
		unsigned.ID = newID(idp.Rand)
	}
	buf, err := xml.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(buf); err != nil {
		return nil, err
	}
	el := doc.Root()
	sig, err := signer.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}
	el.InsertChildAt(0, sig)
	return el, nil
}

// newID returns a new random XML ID, read from r or, if it is nil, from
// crypto/rand.
func newID(r io.Reader) string {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, 20)
	if _, err := io.ReadFull(r, b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("id-%x", b)
}
