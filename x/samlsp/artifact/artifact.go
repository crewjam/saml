// Package artifact sends SAML requests and responses from a service
// provider to the identity provider with the HTTP-Artifact binding
// (saml-bindings §3.6): the browser carries only a short artifact, and the
// IdP fetches the message itself from the SP's ArtifactResolutionService.
//
// Advertise the ArtifactResolutionService with ResolutionService when
// making the samlsp.Config, serve the Binding at its path, and pass the
// Binding with samlsp.WithCustomBinding to Config.AuthnRequest, or to the
// messages of github.com/crewjam/saml/x/samlsp/slo:
//
//	config, err := samlsp.New(entityID, idp, samlsp.WithSigningKey(key, cert),
//		artifact.ResolutionService("https://sp.example.com/saml/artifact", 1))
//	binding, err := artifact.New(config, artifact.NewMemoryStore(), 1)
//	http.Handle(binding.Path(), binding)
//
//	msg, err := config.AuthnRequest(ctx, relayState, samlsp.WithCustomBinding(binding))
//	msg.Write(w)
//
// The browser takes the artifact to the IdP with a redirect, or, with
// Binding.Form, with a form it posts. The IdP must list an HTTP-Artifact
// endpoint for the message in its metadata, and must sign its
// ArtifactResolve requests, or, with Binding.TLSClientAuth, present a TLS
// client certificate with the key of one of its signing certificates
// (saml-bindings §3.6.5.2). The SP signs its ArtifactResponses with the
// key of samlsp.WithSigningKey, which ResolutionService requires.
//
// An SP that serves several IdPs, made with a nil MetadataFunc, names the
// IdP of each message with samlsp.WithIdentityProvider, which reaches the
// Binding's Encode. The IdP's ArtifactResolve carries no such option: set
// Binding.IdentityProvider to find the IdP by the request's Issuer, or name
// it with samlsp.IdentityProviderContext in a handler around the Binding.
//
// The Binding keeps each message in a Store until the IdP resolves its
// artifact. A MemoryStore serves a single process: if the SP runs as
// several, the IdP's ArtifactResolve may reach one that never saw the
// message, and finds nothing. Share a SQLStore between them instead, in
// a table of a database reached through database/sql (PostgreSQL, MySQL
// or SQLite):
//
//	store, err := artifact.NewSQLStore(db, artifact.PostgreSQL, "")
//	err = store.CreateTable(ctx) // or run artifact.SQLSchema with your migrations
//	binding, err := artifact.New(config, store, 1)
//
// It gives each message out once, however many processes take it at the
// same time. The processes compare expiries with their own clocks, so
// keep them close together (see SQLStore.ClockSkew).
package artifact

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SAML type 0x0004 artifacts identify their source by SHA-1 (saml-bindings §3.6.4)
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/signerutil"
	"github.com/crewjam/saml/internal/timelimit"
	"github.com/crewjam/saml/internal/xmlroundtrip"
	"github.com/crewjam/saml/x/samlsp"
)

// DefaultLifetime is how long a message waits for its artifact to be
// resolved, unless Binding.Lifetime says otherwise.
const DefaultLifetime = 2 * time.Minute

// maxResolveSize is the largest ArtifactResolve request read.
const maxResolveSize = 64 << 10

// entityNameIDFormat is the NameID Format of an entity identifier, the
// only Format the Issuer of an ArtifactResolve may have (saml-profiles
// §5.4.1).
const entityNameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

// Binding sends messages with the HTTP-Artifact binding, and serves the
// ArtifactResolutionService from which the IdP fetches them. It is a
// samlsp.Binding and an http.Handler.
type Binding struct {
	config *samlsp.Config
	store  Store
	index  uint16

	// Lifetime is how long a message waits for its artifact to be
	// resolved. If zero, DefaultLifetime is used.
	Lifetime time.Duration

	// Form makes Encode send the artifact to the IdP with an HTML form
	// that the browser posts, instead of a redirect (saml-bindings
	// §3.6.3). A form keeps the artifact and RelayState out of the URL,
	// and so out of logs and the Referer header.
	Form bool

	// OnError, if not nil, is called with each ArtifactResolve request
	// that ServeHTTP refuses, and why, before it answers with a SOAP
	// fault, which does not say why. Use it to log the error.
	OnError func(r *http.Request, err error)

	// IdentityProvider, if not nil, returns the metadata of the IdP whose
	// entity ID is entityID. Set it when the SP serves several IdPs and
	// samlsp.New was given a nil MetadataFunc (see
	// samlsp.WithIdentityProvider). ServeHTTP calls it when the request's
	// context names no IdP (see samlsp.IdentityProviderContext), with the
	// Issuer of the ArtifactResolve, unverified, and then verifies the
	// request with the metadata it returns, as for any other IdP. A forged
	// Issuer thus only chooses metadata that the request fails to verify
	// against; but two IdPs must not share an entity ID.
	IdentityProvider func(ctx context.Context, entityID string) (samlsp.MetadataFunc, error)

	// TLSClientAuth makes ServeHTTP accept an ArtifactResolve that is not
	// signed, if the IdP authenticated itself instead with a TLS client
	// certificate (saml-bindings §3.6.5.2, SOAP binding §3.2.3.1): one
	// whose public key is that of a signing certificate in the metadata of
	// the IdP that the request names as its Issuer. The certificate is
	// matched by its key, not its name, so its chain need not be verified;
	// but the server must ask for it, with a tls.Config.ClientAuth of
	// RequireAnyClientCert or stronger, since a TLS server does not by
	// default. A signed ArtifactResolve is verified as without
	// TLSClientAuth, and refused if its signature is not valid, whatever
	// the client certificate.
	TLSClientAuth bool

	// ClientCertificate, if not nil, returns the TLS client certificate of
	// the request for TLSClientAuth, instead of the first of
	// r.TLS.PeerCertificates. Behind a proxy that terminates TLS, r.TLS is
	// nil; ClientCertificate can then return the certificate that the
	// proxy forwards, in a header for example. That certificate is then
	// only as trustworthy as the proxy, and as the guarantee that no
	// request reaches the Binding except through it with that header set
	// by it: anyone who can set the header can claim to be any IdP.
	ClientCertificate func(r *http.Request) *x509.Certificate
}

var (
	_ samlsp.Binding = (*Binding)(nil)
	_ http.Handler   = (*Binding)(nil)
)

// New returns a Binding for config that keeps messages in store until they
// are resolved. index is the index of the SP's ArtifactResolutionService,
// as passed to ResolutionService. New returns an error if the SP metadata
// has no ArtifactResolutionService with the SOAP binding and that index,
// since the IdP could then resolve none of the Binding's artifacts.
//
// If store is a *MemoryStore with no Now, New sets its Now to the time
// source of config (see samlsp.WithClock), by which the Binding's messages
// expire.
func New(config *samlsp.Config, store Store, index uint16) (*Binding, error) {
	var clock *dsig.Clock
	md := config.Metadata(context.Background(), func(sp *saml.ServiceProvider) { clock = sp.Clock })
	b := &Binding{config: config, store: store, index: index}
	if _, err := b.path(md); err != nil {
		return nil, err
	}
	if m, ok := store.(*MemoryStore); ok {
		m.DefaultNow(func() time.Time { return clockNow(clock) })
	}
	return b, nil
}

// ResolutionService advertises, in the SP metadata, the SP's
// ArtifactResolutionService at location, an absolute URL, with the SOAP
// binding and index. Serve the Binding at Binding.Path. samlsp.New refuses
// it without a signing key (see samlsp.WithSigningKey), which signs the
// ArtifactResponses.
func ResolutionService(location string, index uint16) samlsp.Option {
	u, err := url.Parse(location)
	if err == nil && (!u.IsAbs() || u.Host == "") {
		err = fmt.Errorf("artifact: the ArtifactResolutionService URL must be an absolute URL, not %q", location)
	}
	if err != nil {
		return samlsp.WithCheck(func(*saml.ServiceProvider) error { return err })
	}
	return samlsp.Options(
		samlsp.WithMetadata(func(md *saml.EntityDescriptor) {
			for i := range md.SPSSODescriptors {
				md.SPSSODescriptors[i].ArtifactResolutionServices = append(md.SPSSODescriptors[i].ArtifactResolutionServices,
					saml.IndexedEndpoint{Binding: saml.SOAPBinding, Location: location, Index: int(index)})
			}
		}),
		samlsp.WithCheck(func(sp *saml.ServiceProvider) error {
			if !canSign(sp.Key) {
				return errors.New("artifact: ResolutionService needs an RSA or ECDSA key (see samlsp.WithSigningKey) to sign ArtifactResponses")
			}
			return nil
		}),
	)
}

// Path returns the path of the URL of the SP's ArtifactResolutionService
// with the Binding's index, to serve the Binding at, so that it cannot
// drift from the URL in the SP metadata:
//
//	http.Handle(binding.Path(), binding)
//
// New has checked that the SP metadata has such a service.
func (b *Binding) Path() string {
	p, err := b.path(b.config.Metadata(context.Background()))
	if err != nil {
		// New checked the metadata, which a Config does not change.
		panic(err)
	}
	return p
}

// path returns the path of the URL of the ArtifactResolutionService with
// the SOAP binding and the Binding's index in md.
func (b *Binding) path(md *saml.EntityDescriptor) (string, error) {
	location, err := b.location(md)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("artifact: the ArtifactResolutionService URL %q: %w", location, err)
	}
	if p := u.EscapedPath(); p != "" {
		return p, nil
	}
	return "/", nil
}

// location returns the URL of the ArtifactResolutionService with the SOAP
// binding and the Binding's index in md.
func (b *Binding) location(md *saml.EntityDescriptor) (string, error) {
	for _, d := range md.SPSSODescriptors {
		for _, ars := range d.ArtifactResolutionServices {
			if ars.Index == int(b.index) && ars.Binding == saml.SOAPBinding {
				return ars.Location, nil
			}
		}
	}
	return "", fmt.Errorf("artifact: the SP metadata has no ArtifactResolutionService with index %d (see ResolutionService)", b.index)
}

// URI implements samlsp.Binding.
func (b *Binding) URI() string { return saml.HTTPArtifactBinding }

// Encode implements samlsp.Binding. It keeps the message under a new
// artifact, for the IdP only, and returns a Message that sends the browser
// to the IdP with the artifact: a redirect, or, with Form, a form that
// the browser posts.
func (b *Binding) Encode(ctx context.Context, m *samlsp.OutboundMessage) (*samlsp.Message, error) {
	sp, err := b.config.ServiceProvider(ctx)
	if err != nil {
		return nil, err
	}
	el, err := m.Element()
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	art, err := newArtifact(b.config.Rand(), b.config.EntityID(), b.index)
	if err != nil {
		return nil, err
	}
	expires := now(sp).Add(b.lifetime())
	if err := b.store.Save(ctx, art, StoredMessage{XML: buf, Recipient: sp.IDPMetadata.EntityID, ExpiresAt: expires}); err != nil {
		return nil, fmt.Errorf("artifact: cannot store the message: %w", err)
	}

	fields := url.Values{"SAMLart": {art}}
	if m.RelayState != "" {
		fields.Set("RelayState", m.RelayState)
	}
	if b.Form {
		return m.PostForm(fields)
	}
	u, err := url.Parse(m.Destination)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for name, values := range fields {
		q[name] = values
	}
	u.RawQuery = q.Encode()
	return m.Redirect(u), nil
}

func (b *Binding) lifetime() time.Duration {
	if b.Lifetime > 0 {
		return b.Lifetime
	}
	return DefaultLifetime
}

// now returns the current time by the clock of sp.
func now(sp *saml.ServiceProvider) time.Time { return clockNow(sp.Clock) }

// clockNow returns the current time in UTC from clock or, if it is nil,
// from saml.TimeNow, as package saml does.
func clockNow(clock *dsig.Clock) time.Time {
	if clock != nil {
		return clock.Now().UTC()
	}
	return saml.TimeNow() //nolint:staticcheck // package saml's fallback when no Clock is set
}

// canSign reports whether key can sign the ArtifactResponses: it is an
// RSA or ECDSA key, the kinds XML signatures support here.
func canSign(key crypto.Signer) bool {
	if signerutil.IsNil(key) {
		return false
	}
	switch key.Public().(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return true
	}
	return false
}

// newArtifact returns a new type 0x0004 artifact (saml-bindings §3.6.4):
// the type code, the endpoint index, the SHA-1 hash of the issuer's
// entity ID and a random message handle, read from randReader.
func newArtifact(randReader io.Reader, entityID string, index uint16) (string, error) {
	buf := make([]byte, 44)
	binary.BigEndian.PutUint16(buf[0:2], 0x0004)
	binary.BigEndian.PutUint16(buf[2:4], index)
	source := sha1.Sum([]byte(entityID)) //nolint:gosec // see the import
	copy(buf[4:24], source[:])
	if _, err := io.ReadFull(randReader, buf[24:44]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// ServeHTTP implements the ArtifactResolutionService: it answers an
// ArtifactResolve that the IdP sends with the SAML SOAP binding with an
// ArtifactResponse signed by the SP, carrying the message of the artifact.
//
// The ArtifactResolve must be signed by the IdP (or, with TLSClientAuth,
// come with its TLS client certificate), be issued by it, and be fresh. A message is given only once, and only to the IdP it was sent to;
// an artifact that is unknown, expired, already resolved or meant for
// another party is answered with no message (saml-core §3.5.3). A request
// that is refused is answered with a SOAP fault, and passed to OnError.
//
// The request is checked as package saml checks the SOAP messages it
// receives: it must be XML that encoding/xml reads as written, a SOAP 1.1
// Envelope whose Body holds only the ArtifactResolve, with no header that
// the SOAP envelope marks mustUnderstand.
func (b *Binding) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := b.resolve(r)
	if err != nil {
		if b.OnError != nil {
			b.OnError(r, err)
		}
		_ = saml.WriteSOAPFault(w, "invalid artifact resolution request")
		return
	}
	envelope := etree.NewElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	envelope.CreateElement("soapenv:Body").AddChild(resp)
	doc := etree.NewDocument()
	doc.SetRoot(envelope)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = doc.WriteTo(w)
}

func (b *Binding) resolve(r *http.Request) (*etree.Element, error) {
	if !saml.IsSOAPRequest(r) {
		return nil, errors.New("artifact: not a SOAP request: expected a POST with Content-Type text/xml")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxResolveSize+1))
	if err != nil {
		return nil, fmt.Errorf("artifact: cannot read the request: %w", err)
	}
	if len(body) > maxResolveSize {
		return nil, fmt.Errorf("artifact: the request is larger than %d bytes", maxResolveSize)
	}
	el, err := readArtifactResolve(body)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	sp, err := b.config.ServiceProvider(ctx)
	if errors.Is(err, samlsp.ErrNoIdentityProvider) && b.IdentityProvider != nil {
		ctx, err = b.identityProviderContext(ctx, el)
		if err != nil {
			return nil, err
		}
		sp, err = b.config.ServiceProvider(ctx)
	}
	if err != nil {
		return nil, err
	}
	var signed *etree.Element
	if b.TLSClientAuth && !isSigned(el) {
		signed, err = b.tlsAuthenticated(r, sp, el)
	} else {
		signed, err = sp.ValidateIDPSignedElement(el)
	}
	if err != nil {
		return nil, fmt.Errorf("artifact: the ArtifactResolve: %w", err)
	}
	var req saml.ArtifactResolve
	if err := unmarshal(signed, &req); err != nil {
		return nil, fmt.Errorf("artifact: cannot read the ArtifactResolve: %w", err)
	}
	if req.ID == "" {
		return nil, errors.New("artifact: the ArtifactResolve has no ID")
	}
	if req.Version != "2.0" {
		return nil, fmt.Errorf("artifact: the ArtifactResolve has Version %q, not 2.0", req.Version)
	}
	if req.Destination != "" {
		// saml-core §3.2.1: a Destination must be checked.
		location, err := b.location(b.config.Metadata(ctx))
		if err != nil {
			return nil, err
		}
		if req.Destination != location {
			return nil, fmt.Errorf("artifact: the ArtifactResolve is addressed to %q, not %q: %w", req.Destination, location, saml.ErrDestinationMismatch)
		}
	}
	if err := checkResolveIssuer(req.Issuer, sp.IDPMetadata.EntityID); err != nil {
		return nil, err
	}
	t := now(sp)
	if req.IssueInstant.After(t.Add(timelimit.SPClockSkew(sp))) || t.After(req.IssueInstant.Add(timelimit.SPIssueDelay(sp))) {
		return nil, fmt.Errorf("artifact: the ArtifactResolve was issued at %s, which is not current", req.IssueInstant)
	}

	var message *etree.Element
	stored, err := b.store.Take(ctx, req.Artifact, req.Issuer.Value)
	if err != nil {
		return nil, fmt.Errorf("artifact: cannot take the message from the store: %w", err)
	}
	// The recipient is checked again, in case the Store does not.
	if stored != nil && stored.Recipient == req.Issuer.Value && !t.After(stored.ExpiresAt) {
		msgDoc := etree.NewDocument()
		if err := msgDoc.ReadFromBytes(stored.XML); err != nil {
			return nil, fmt.Errorf("artifact: cannot read the stored message: %w", err)
		}
		message = msgDoc.Root()
	}
	resp, err := b.artifactResponse(sp, req.ID, t, message)
	if err != nil && message != nil {
		// Keep the message, which the IdP did not get, for another try.
		_ = b.store.Save(ctx, req.Artifact, *stored)
	}
	return resp, err
}

// identityProviderContext returns a copy of ctx that names the IdP that
// IdentityProvider returns for the Issuer of el, an ArtifactResolve that
// is not yet verified. The Issuer only chooses the metadata that must then
// verify el.
func (b *Binding) identityProviderContext(ctx context.Context, el *etree.Element) (context.Context, error) {
	issuer := el.FindElement("./Issuer")
	if issuer == nil || issuer.NamespaceURI() != samlAssertionNamespace || strings.TrimSpace(issuer.Text()) == "" {
		return nil, errors.New("artifact: the ArtifactResolve names no Issuer")
	}
	entityID := strings.TrimSpace(issuer.Text())
	idp, err := b.IdentityProvider(ctx, entityID)
	if err != nil {
		return nil, fmt.Errorf("artifact: cannot find the IdP %s: %w", entityID, err)
	}
	if idp == nil {
		return nil, fmt.Errorf("artifact: no IdP %s", entityID)
	}
	return samlsp.IdentityProviderContext(ctx, idp), nil
}

const (
	soapEnvelopeNamespace  = "http://schemas.xmlsoap.org/soap/envelope/"
	samlProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// readArtifactResolve returns the samlp:ArtifactResolve that must be the
// only element of the Body of body, a SOAP 1.1 Envelope, as package saml
// reads the SOAP messages it receives: body must be XML that encoding/xml
// reads as written, each element is matched by its namespace, and a header
// entry with mustUnderstand="1" is refused, since none is understood (SOAP
// 1.1 §4.2.3).
func readArtifactResolve(body []byte) (*etree.Element, error) {
	if err := xmlroundtrip.Validate(body); err != nil {
		return nil, fmt.Errorf("artifact: invalid XML: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return nil, fmt.Errorf("artifact: the request is not XML: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Envelope" || root.NamespaceURI() != soapEnvelopeNamespace {
		return nil, errors.New("artifact: the request is not a SOAP 1.1 Envelope")
	}
	var soapBody *etree.Element
	for _, child := range root.ChildElements() {
		if child.NamespaceURI() != soapEnvelopeNamespace {
			continue
		}
		switch child.Tag {
		case "Header":
			for _, entry := range child.ChildElements() {
				for _, attr := range entry.Attr {
					if attr.Key == "mustUnderstand" && attr.NamespaceURI() == soapEnvelopeNamespace && attr.Value == "1" {
						return nil, fmt.Errorf("artifact: cannot understand the mandatory SOAP header %s", entry.FullTag())
					}
				}
			}
		case "Body":
			if soapBody != nil {
				return nil, errors.New("artifact: the SOAP Envelope has more than one Body")
			}
			soapBody = child
		}
	}
	if soapBody == nil {
		return nil, errors.New("artifact: the SOAP Envelope has no Body")
	}
	children := soapBody.ChildElements()
	if len(children) != 1 || children[0].Tag != "ArtifactResolve" || children[0].NamespaceURI() != samlProtocolNamespace {
		return nil, errors.New("artifact: the SOAP Body does not hold just a samlp:ArtifactResolve")
	}
	return children[0], nil
}

// artifactResponse returns a signed ArtifactResponse to the request
// inResponseTo, carrying message if it is not nil.
func (b *Binding) artifactResponse(sp *saml.ServiceProvider, inResponseTo string, t time.Time, message *etree.Element) (*etree.Element, error) {
	id := make([]byte, 20)
	if _, err := io.ReadFull(b.config.Rand(), id); err != nil {
		return nil, err
	}
	el := etree.NewElement("samlp:ArtifactResponse")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("ID", fmt.Sprintf("id-%x", id))
	el.CreateAttr("InResponseTo", inResponseTo)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", t.UTC().Format(time.RFC3339Nano))
	el.CreateElement("saml:Issuer").SetText(sp.EntityID)
	el.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", saml.StatusSuccess)
	if message != nil {
		el.AddChild(message)
	}

	// SignElement puts the Signature right after the Issuer, as the schema
	// requires.
	return b.config.SignElement(el)
}

// checkResolveIssuer checks issuer, the Issuer of an ArtifactResolve, which
// must name the IdP entityID. saml-profiles §5.4.1: it "MUST be present and
// MUST contain the unique identifier of the requesting entity; the Format
// attribute MUST be omitted or have a value of
// urn:oasis:names:tc:SAML:2.0:nameid-format:entity".
func checkResolveIssuer(issuer *saml.Issuer, entityID string) error {
	if issuer == nil || issuer.Value != entityID {
		return fmt.Errorf("artifact: the ArtifactResolve is not issued by the IdP %s", entityID)
	}
	if issuer.Format != "" && issuer.Format != entityNameIDFormat {
		return fmt.Errorf("artifact: the ArtifactResolve Issuer Format %q is not %s (saml-profiles §5.4.1): %w", issuer.Format, entityNameIDFormat, saml.ErrIssuerMismatch)
	}
	return nil
}
