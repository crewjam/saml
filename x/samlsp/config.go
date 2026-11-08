package samlsp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/signerutil"
	"github.com/crewjam/saml/x/samlsp/replay"
)

// Config is a SAML service provider (SP) and the identity provider (IdP)
// it trusts. Create one with New. A Config is immutable and safe for
// concurrent use.
type Config struct {
	identityProvider MetadataFunc
	entityID         string
	acsURL           url.URL

	key                    crypto.Signer
	certificate            *x509.Certificate
	intermediates          []*x509.Certificate
	decryptionKeys         []*rsa.PrivateKey
	encryptionKey          *rsa.PrivateKey
	encryptionCert         *x509.Certificate
	signRequests           bool
	acceptBaseID           bool
	nameIDFormat           saml.NameIDFormat
	replayState            ReplayState
	authnContextComparator func(comparison string, requested []string, got string) bool
	clock                  *dsig.Clock
	httpClient             *http.Client
	signatureMethod        string

	spOptions     []ServiceProviderOption
	spMetadata    spMetadataOptions
	checks        []func(*saml.ServiceProvider) error
	metadataHooks []func(*saml.EntityDescriptor)
}

// New returns a Config for the service provider entityID, which trusts
// the identity provider whose metadata identityProvider supplies.
//
// identityProvider supplies the metadata of the IdP that the SP trusts.
// It is called with the context of each method. See RemoteMetadata,
// StaticMetadata and StaticMetadataBytes. It may be nil when every call
// names its IdP with WithIdentityProvider (or IdentityProviderContext);
// a call that does not then fails with ErrNoIdentityProvider.
//
// The entity ID is conventionally the URL where the SP serves its metadata
// (see ServeMetadata), such as "https://sp.example.com/saml/metadata". The
// assertion consumer service (ACS), where the IdP sends its Responses, is
// then beside it by default, at "acs": "https://sp.example.com/saml/acs"
// in that example. Serve ParseResponse there, or choose another URL with
// WithACSURL. If the entity ID is not a URL, such as a URN, WithACSURL is
// required.
//
// New returns an error if an argument is missing or a URL is not
// absolute. It does not call identityProvider.
//
// New is cheap: it does no I/O and keeps no state but the replay record.
// An application can build a Config per request (when its SP differs per
// tenant, by entity ID or ACS URL), per login, or again whenever its
// configuration changes. Each Config made without WithReplayState keeps
// its own replay record, though, which is lost with the Config: a message
// accepted by one Config would be accepted again by the next. Give every
// such Config the same record with WithReplayState, such as one
// replay.NewMemory kept for the life of the process, or a database table.
// When only the IdP differs per tenant, one Config with
// WithIdentityProvider serves them all.
func New(entityID string, identityProvider MetadataFunc, opts ...Option) (*Config, error) {
	if entityID == "" {
		return nil, errors.New("samlsp: the entity ID is empty")
	}
	c := &Config{identityProvider: identityProvider, entityID: entityID}
	var o configOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyConfig(c, &o)
		}
	}

	var err error
	if o.acsURL != "" {
		if c.acsURL, err = absoluteURL("ACS URL", o.acsURL); err != nil {
			return nil, err
		}
	} else {
		u, err := url.Parse(entityID)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return nil, fmt.Errorf("samlsp: the entity ID %q is not a URL to put the ACS beside; use WithACSURL", entityID)
		}
		c.acsURL = *u.ResolveReference(&url.URL{Path: "acs"})
	}
	if c.replayState == nil {
		c.replayState = &replay.Memory{Clock: c.clock}
	}
	if c.encryptionKey != nil || c.encryptionCert != nil {
		if c.encryptionKey == nil || c.encryptionCert == nil {
			return nil, errors.New("samlsp: WithEncryptionKey needs both the key and its certificate")
		}
		if pub, ok := c.encryptionCert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&c.encryptionKey.PublicKey) {
			return nil, errors.New("samlsp: the certificate of WithEncryptionKey is not for its key")
		}
	}
	if err := c.spMetadata.check(); err != nil {
		return nil, err
	}
	if c.signatureMethod != "" {
		if err := checkSignatureMethod(c.signatureMethod, c.key); err != nil {
			return nil, err
		}
	}
	if sp := c.spForMetadata(nil); sp.SignMetadata && signatureMethod(c.key) == "" {
		return nil, errors.New("samlsp: SignMetadata needs an RSA or ECDSA key (see WithSigningKey)")
	}
	if len(c.checks) > 0 {
		sp := c.spForMetadata(nil)
		for _, check := range c.checks {
			if err := check(sp); err != nil {
				return nil, err
			}
		}
	}
	if c.signRequests && signatureMethod(c.key) == "" {
		return nil, errors.New("samlsp: SignAuthnRequests needs an RSA or ECDSA key (see WithSigningKey)")
	}
	return c, nil
}

// harden turns on every check that package saml leaves off by default only
// for compatibility. A ServiceProviderOption can turn one off again.
func harden(sp *saml.ServiceProvider) {
	// Check the AuthnContextClassRef against WithAuthnContext.
	sp.ValidateAuthnContextClassRef = true
	// Refuse assertions with conditions that are not understood
	// (saml-core §2.5.1.1).
	sp.RejectUnknownConditions = true
	// Decrypt AES-CBC only inside a signed Response: CBC does not
	// authenticate the ciphertext (saml-core errata E93).
	sp.RequireSignedResponseForCBC = true
	// Refuse signatures made with SHA-1.
	sp.RejectSHA1Signatures = true
	// Refuse messages once the IdP metadata's validUntil has passed.
	sp.RejectExpiredIDPMetadata = true
	// Resolve only type 0x0004 artifacts issued by this IdP.
	sp.RequireStandardArtifacts = true
	// Keep RelayState within 80 bytes (saml-bindings §3.4.3, §3.5.3).
	sp.LimitRelayStateLength = true
}

// absoluteURL parses s, which must be an absolute URL with a host.
func absoluteURL(what, s string) (url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return url.URL{}, fmt.Errorf("samlsp: invalid %s: %w", what, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return url.URL{}, fmt.Errorf("samlsp: the %s must be an absolute URL, not %q", what, s)
	}
	return *u, nil
}

// Option configures New.
type Option interface {
	applyConfig(c *Config, o *configOptions)
}

// configOptions holds options that New validates after applying them.
type configOptions struct {
	acsURL string
}

type optionFunc func(c *Config, o *configOptions)

func (f optionFunc) applyConfig(c *Config, o *configOptions) { f(c, o) }

// WithACSURL sets the absolute URL of the SP's assertion consumer service,
// where the IdP sends its Responses. The handler at this URL calls
// ParseResponse. The default is "acs" beside the entity ID (see New).
func WithACSURL(acsURL string) Option {
	return optionFunc(func(_ *Config, o *configOptions) { o.acsURL = acsURL })
}

// AcceptBaseID makes ParseResponse accept an assertion that identifies the
// user with a saml:BaseID instead of a NameID (saml-core §2.2.3). A
// BaseID's content is defined by its xsi:type, which this package does not
// interpret: it is given as Assertion.BaseID, and NameID is zero. Without
// it, such assertions are refused. (For LogoutRequests, see
// x/samlsp/slo.AcceptBaseID.)
var AcceptBaseID Option = optionFunc(func(c *Config, _ *configOptions) { c.acceptBaseID = true })

// ACSURL returns the URL of the SP's assertion consumer service.
func (c *Config) ACSURL() string { return c.acsURL.String() }

// ACSPath returns the path of the ACS URL, to serve the handler that
// calls ParseResponse at, so that it cannot drift from the URL the IdP is
// given:
//
//	http.HandleFunc(config.ACSPath(), acs)
func (c *Config) ACSPath() string { return urlPath(&c.acsURL) }

// MetadataPath returns the path of the entity ID, where the SP metadata is
// conventionally served:
//
//	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)
//
// It returns "" if the entity ID is not an http or https URL, such as a
// URN; serve the metadata at a path of your choosing then.
func (c *Config) MetadataPath() string {
	u, err := url.Parse(c.entityID)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return urlPath(u)
}

// urlPath returns the path of u, escaped as in a URL, or "/" if it has
// none: the pattern to serve u at with an http.ServeMux.
func urlPath(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// WithSigningKey sets the key that the SP signs with, and its certificate,
// which the SP metadata publishes for signing, with any intermediates of
// its chain. It signs logout messages, attribute queries, artifact
// resolution requests and artifact responses, AuthnRequests with SignAuthnRequests, and the metadata with
// SignMetadata. It is used only for signing: to accept encrypted
// assertions, use WithEncryptionKey, which may be given the same RSA key.
func WithSigningKey(key crypto.Signer, cert *x509.Certificate, intermediates ...*x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.key, c.certificate = key, cert
		c.intermediates = append([]*x509.Certificate(nil), intermediates...)
	})
}

// WithEncryptionKey sets the RSA key pair that the IdP encrypts assertions
// to: cert is published in the SP metadata for encryption, and key
// decrypts. It may be the key of WithSigningKey. Without it (or
// WithDecryptionKeys), encrypted assertions are refused.
func WithEncryptionKey(key *rsa.PrivateKey, cert *x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.encryptionKey, c.encryptionCert = key, cert
	})
}

// WithDecryptionKeys adds keys that can decrypt encrypted assertions, after
// that of WithEncryptionKey, for key rotation. They are not published in
// the SP metadata.
func WithDecryptionKeys(keys ...*rsa.PrivateKey) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.decryptionKeys = append(c.decryptionKeys, keys...)
	})
}

// SignAuthnRequests makes AuthnRequests carry a signature by the key of
// WithSigningKey, using RSA-SHA256 or ECDSA-SHA256.
var SignAuthnRequests Option = optionFunc(func(c *Config, _ *configOptions) { c.signRequests = true })

// WithNameIDFormat sets the NameID format requested from the IdP. The
// default is transient.
func WithNameIDFormat(format saml.NameIDFormat) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.nameIDFormat = format })
}

// ReplayState records the messages a Config accepts, so that each is
// accepted only once. Consume records the message identified by key as
// accepted until expiresAt, after which the message could no longer be
// accepted anyway and the record may be dropped. It must fail with
// saml.ErrAssertionReplayed if key is already recorded with an expiry that
// has not passed; any other error refuses the message too. It must be safe
// for concurrent use, and may keep key.
//
// key is ReplayKey of the IdP's entity ID and the message's ID: 32 bytes,
// so a database can keep it in a fixed-size binary column with a unique
// key. Since each IdP chooses the IDs of its messages, a hostile tenant's
// IdP could send messages with any IDs it likes; with the IdP in the key,
// they cannot collide with, and so block, the messages of another tenant's
// IdP, and one record can safely serve several IdPs and SPs.
//
// ctx is that of the Config method that accepts the message, such as
// ParseResponse, so a record kept in a database can use the request's
// deadline and values.
//
// The messages are assertions, LogoutRequests and resolved artifacts.
// See replay.Memory for the default.
type ReplayState interface {
	Consume(ctx context.Context, key []byte, expiresAt time.Time) error
}

// replayKeyLabel separates replay keys from other uses of SHA-256.
const replayKeyLabel = "github.com/crewjam/saml/x/samlsp replay key v1\x00"

// ReplayKey returns the key under which a ReplayState records the message
// whose ID is id, issued by the IdP whose entity ID is idp: a SHA-256 hash
// of both. The entity ID is length-prefixed, so no other pair has the same
// key.
//
// idp is the entity ID of the metadata the message was verified with, not
// a value taken from the message, and it stays the same when the IdP
// rotates its keys. So an SP that lets tenants register IdPs must not let
// two of them use the same entity ID. id is the message's ID as package
// saml records it: that of an assertion, or, with a prefix that keeps them
// apart, of a LogoutRequest ("LogoutRequest:") or a resolved artifact
// ("Artifact:").
func ReplayKey(idp, id string) []byte {
	h := sha256.New()
	h.Write([]byte(replayKeyLabel))
	h.Write(binary.AppendUvarint(nil, uint64(len(idp))))
	h.Write([]byte(idp))
	h.Write([]byte(id))
	return h.Sum(nil)
}

// replayCache is the saml.AssertionReplayCache of the ServiceProvider of
// a call: state, with the call's context and IdP.
type replayCache struct {
	ctx   context.Context
	idp   string
	state ReplayState
}

func (r replayCache) Consume(id string, expiresAt time.Time) error {
	return r.state.Consume(r.ctx, ReplayKey(r.idp, id), expiresAt)
}

// WithReplayState sets where ParseResponse (and the LogoutRequests of
// x/samlsp/slo) record the IDs of the messages they accept, so that each is
// accepted only once.
//
// By default, each Config records them in its own replay.Memory, which
// protects one process only: a Response replayed to another process, or
// after a restart, is accepted. Pass a replay.NewMemory to share one
// record between several Configs of a process. Applications served by
// several processes need state that the processes share, such as a table
// with a unique key on the record's key (see ReplayState). Records need no size
// limit (see replay.Memory).
func WithReplayState(state ReplayState) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.replayState = state })
}

// WithAuthnContextComparator sets how ParseResponse decides whether the
// authentication context class the IdP used satisfies a WithAuthnContext
// whose comparison is not saml.AuthnContextComparisonExact. satisfies reports whether got
// is acceptable when classes were requested with comparison. The SAML
// specification leaves the order of the classes to each deployment.
func WithAuthnContextComparator(satisfies func(comparison saml.AuthnContextComparison, requested []saml.AuthnContextClass, got saml.AuthnContextClass) bool) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.authnContextComparator = func(comparison string, requested []string, got string) bool {
			classes := make([]saml.AuthnContextClass, len(requested))
			for i, r := range requested {
				classes[i] = saml.AuthnContextClass(r)
			}
			return satisfies(saml.AuthnContextComparison(comparison), classes, saml.AuthnContextClass(got))
		}
	})
}

// WithSignatureMethod sets the XML signature algorithm of everything the
// SP signs: AuthnRequests (with SignAuthnRequests), logout messages,
// attribute queries and signed metadata. It must suit the key of WithSigningKey:
// dsig.RSASHA256SignatureMethod, RSASHA384 or RSASHA512 for an RSA key,
// and dsig.ECDSASHA256SignatureMethod, ECDSASHA384 or ECDSASHA512 for an
// ECDSA key. SHA-1 is refused. The default is SHA-256.
func WithSignatureMethod(method string) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.signatureMethod = method })
}

// checkSignatureMethod returns an error if method cannot be used with key.
func checkSignatureMethod(method string, key crypto.Signer) error {
	if signatureMethod(key) == "" {
		return errors.New("samlsp: WithSignatureMethod needs an RSA or ECDSA key (see WithSigningKey)")
	}
	_, isRSA := key.Public().(*rsa.PublicKey)
	switch method {
	case dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod:
		if !isRSA {
			return fmt.Errorf("samlsp: signature method %s needs an RSA key", method)
		}
	case dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		if isRSA {
			return fmt.Errorf("samlsp: signature method %s needs an ECDSA key", method)
		}
	case dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod:
		return fmt.Errorf("samlsp: SHA-1 signature method %s is refused", method)
	default:
		return fmt.Errorf("samlsp: unknown signature method %q", method)
	}
	return nil
}

// signWithLogoutMethod makes sp sign SOAP messages, attribute queries and
// metadata with the method of LogoutSignatureMethod, which is the one of
// WithSignatureMethod. Package saml signs those with SignatureMethod,
// which also turns on the signing of AuthnRequests, so it is set only on
// the ServiceProvider of a call that makes none.
func signWithLogoutMethod(sp *saml.ServiceProvider) {
	if sp.LogoutSignatureMethod != "" {
		sp.SignatureMethod = sp.LogoutSignatureMethod
	}
}

// WithClock sets the time source used to check validity periods. It is
// mainly useful in tests.
func WithClock(clock *dsig.Clock) ClockOption { return ClockOption{clock} }

// ClockOption is the option that WithClock returns. It is both an Option,
// for New, and a MetadataOption, for RemoteMetadata and MDQMetadata, whose
// refresh times it judges.
type ClockOption struct{ clock *dsig.Clock }

func (o ClockOption) applyConfig(c *Config, _ *configOptions) { c.clock = o.clock }

func (o ClockOption) applyMetadata(m *metadataOptions) { m.clock = o.clock }

// EntityID returns the entityID of the service provider.
func (c *Config) EntityID() string { return c.entityID }

// ServiceProviderOption customizes the saml.ServiceProvider that a Config
// method builds and uses, for settings that have no Option of their own.
// Pass it to New to apply it to every call, or to a single method: it is
// an Option, a MessageOption and a ResponseOption. The
// options of a call are applied after those passed to New.
type ServiceProviderOption func(sp *saml.ServiceProvider)

func (f ServiceProviderOption) applyConfig(c *Config, _ *configOptions) {
	c.spOptions = append(c.spOptions, f)
}
func (f ServiceProviderOption) applyAuthn(o *authnOptions)       { o.sp = append(o.sp, f) }
func (f ServiceProviderOption) applyMessage(o *messageOptions)   { o.sp = append(o.sp, f) }
func (f ServiceProviderOption) applyResponse(o *responseOptions) { o.sp = append(o.sp, f) }

// WithServiceProvider returns a ServiceProviderOption that calls fn.
func WithServiceProvider(fn func(sp *saml.ServiceProvider)) ServiceProviderOption {
	return ServiceProviderOption(fn)
}

// SignMetadata makes ServeMetadata and MetadataXML sign the SP metadata
// with the key of WithSigningKey. Pass it to New. Metadata returns the metadata
// as a struct, which carries no signature.
var SignMetadata ServiceProviderOption = func(sp *saml.ServiceProvider) { sp.SignMetadata = true }

// applyServiceProviderOptions applies the options of c, then extra, to sp.
func (c *Config) applyServiceProviderOptions(sp *saml.ServiceProvider, extra []ServiceProviderOption) {
	for _, opt := range c.spOptions {
		if opt != nil {
			opt(sp)
		}
	}
	for _, opt := range extra {
		if opt != nil {
			opt(sp)
		}
	}
}

// serviceProvider returns a new saml.ServiceProvider configured from c,
// with the identity provider's metadata, and with the
// ServiceProviderOptions passed to New and then opts applied.
func (c *Config) serviceProvider(ctx context.Context, opts []ServiceProviderOption) (*saml.ServiceProvider, error) {
	idp, err := c.identityProviderFor(ctx)
	if err != nil {
		return nil, err
	}
	idpMetadata, err := idp(ctx)
	if err != nil {
		return nil, fmt.Errorf("samlsp: cannot get identity provider metadata: %w", err)
	}
	if err := checkIDPMetadata(idpMetadata); err != nil {
		return nil, err
	}
	sp := c.localServiceProvider()
	sp.IDPMetadata = idpMetadata
	sp.ReplayCache = replayCache{ctx, idpMetadata.EntityID, c.replayState}
	c.applyServiceProviderOptions(sp, opts)
	return sp, nil
}

// localServiceProvider returns a new saml.ServiceProvider configured from
// c, without the identity provider's metadata and without applying any
// ServiceProviderOption. It shares no slice with c, so that changing it
// cannot change c.
func (c *Config) localServiceProvider() *saml.ServiceProvider {
	sp := &saml.ServiceProvider{
		EntityID:              c.entityID,
		Key:                   c.key,
		Certificate:           c.certificate,
		Intermediates:         slices.Clone(c.intermediates),
		DecryptionKeys:        slices.Clone(c.decryptionKeys),
		EncryptionKey:         c.encryptionKey,
		EncryptionCertificate: c.encryptionCert,
		HTTPClient:            c.httpClient,
		AcsURL:                c.acsURL,
		AuthnNameIDFormat:     c.nameIDFormat,
		Clock:                 c.clock,

		KeyOnlySigns: true,

		AuthnContextClassRefComparator: c.authnContextComparator,
		AcceptAssertionBaseID:          c.acceptBaseID,
	}
	harden(sp)
	method := c.signatureMethod
	if method == "" {
		method = signatureMethod(c.key)
	}
	if c.signRequests {
		sp.SignatureMethod = method
	}
	// The single logout profile requires logout messages to be signed with
	// the HTTP-Redirect and HTTP-POST bindings (saml-profiles §4.4.3), so
	// sign them whenever there is a key that can.
	sp.LogoutSignatureMethod = method
	return sp
}

// signatureMethod returns the XML signature method for key, or "" if key is
// nil or cannot make XML signatures.
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

// Metadata returns the metadata of this service provider, to register it
// with the identity provider. It does not call the identity provider's
// MetadataFunc. It is not signed, whatever SignMetadata says: for the
// signed document, use MetadataXML.
func (c *Config) Metadata(_ context.Context, opts ...ServiceProviderOption) *saml.EntityDescriptor {
	md := c.spForMetadata(opts).Metadata()
	c.decorateMetadata(md)
	return md
}

// spForMetadata returns the saml.ServiceProvider that describes this SP's
// metadata. The SP metadata does not depend on the IdP, so it is served
// even when the IdP metadata cannot be had.
func (c *Config) spForMetadata(opts []ServiceProviderOption) *saml.ServiceProvider {
	sp := c.localServiceProvider()
	c.applyServiceProviderOptions(sp, opts)
	return sp
}

// ServeMetadata is an http.HandlerFunc that serves this service provider's
// metadata, conventionally at the entity ID's URL. If New was passed
// SignMetadata, the metadata is signed.
func (c *Config) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	buf, err := c.MetadataXML(r.Context())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(buf) //nolint:gosec // our own metadata, served as application/samlmetadata+xml
}

// decorateMetadata adds to md, the SP metadata, what the options add.
func (c *Config) decorateMetadata(md *saml.EntityDescriptor) {
	c.spMetadata.apply(md)
	for _, modify := range c.metadataHooks {
		modify(md)
	}
}

// MetadataXML returns the metadata of this service provider as the XML
// document that ServeMetadata serves: signed if SignMetadata was passed to
// New or is in opts. Like Metadata, it applies opts after the
// ServiceProviderOptions passed to New, and does not call the identity
// provider's MetadataFunc.
func (c *Config) MetadataXML(_ context.Context, opts ...ServiceProviderOption) ([]byte, error) {
	sp := c.spForMetadata(opts)
	md := sp.Metadata()
	c.decorateMetadata(md)
	if !sp.SignMetadata {
		return xml.MarshalIndent(md, "", "  ")
	}
	signWithLogoutMethod(sp)
	el, err := sp.SignEntityDescriptor(md)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	return doc.WriteToBytes()
}
