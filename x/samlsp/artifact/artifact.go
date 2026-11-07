// Package artifact sends SAML requests and responses from a service
// provider to the identity provider with the HTTP-Artifact binding
// (saml-bindings §3.6): the browser carries only a short artifact, and the
// IdP fetches the message itself from the SP's ArtifactResolutionService.
//
// It is an extension of github.com/crewjam/saml/x/samlsp, built only on
// that package's extension points: a Binding is passed to
// AuthnRequest, LogoutRequest or LogoutResponse with
// samlsp.WithCustomBinding, and serves the ArtifactResolutionService.
//
//	config, err := samlsp.New(idp, entityID, samlsp.WithKey(key, cert),
//		artifact.ResolutionService("https://sp.example.com/saml/artifact", 1))
//	binding := artifact.New(config, artifact.NewMemoryStore(), 1)
//	http.Handle("/saml/artifact", binding)
//
//	msg, err := config.AuthnRequest(ctx, relayState, samlsp.WithCustomBinding(binding))
//	msg.Write(w)
//
// The IdP must list an HTTP-Artifact endpoint for the message in its
// metadata, and must sign its ArtifactResolve requests.
package artifact

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SAML type 0x0004 artifacts identify their source by SHA-1 (saml-bindings §3.6.4)
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// DefaultLifetime is how long a message waits for its artifact to be
// resolved, unless Binding.Lifetime says otherwise.
const DefaultLifetime = 2 * time.Minute

// maxResolveSize is the largest ArtifactResolve request read.
const maxResolveSize = 64 << 10

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
}

var (
	_ samlsp.Binding = (*Binding)(nil)
	_ http.Handler   = (*Binding)(nil)
)

// New returns a Binding for config that keeps messages in store until they
// are resolved. index is the index of the SP's ArtifactResolutionService,
// which New does not check; advertise it with ResolutionService.
func New(config *samlsp.Config, store Store, index uint16) *Binding {
	return &Binding{config: config, store: store, index: index}
}

// ResolutionService advertises, in the SP metadata, the SP's
// ArtifactResolutionService at location, with the SOAP binding and index.
// Serve the Binding there.
func ResolutionService(location string, index uint16) samlsp.Option {
	return samlsp.WithMetadata(func(md *saml.EntityDescriptor) {
		for i := range md.SPSSODescriptors {
			md.SPSSODescriptors[i].ArtifactResolutionServices = append(md.SPSSODescriptors[i].ArtifactResolutionServices,
				saml.IndexedEndpoint{Binding: saml.SOAPBinding, Location: location, Index: int(index)})
		}
	})
}

// URI implements samlsp.Binding.
func (b *Binding) URI() string { return saml.HTTPArtifactBinding }

// Encode implements samlsp.Binding. It keeps the message under a new
// artifact, for the IdP only, and returns a Message that redirects the
// browser to the IdP with the artifact.
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

	art, err := newArtifact(b.config.EntityID(), b.index)
	if err != nil {
		return nil, err
	}
	expires := now(sp).Add(b.lifetime())
	if err := b.store.Save(ctx, art, StoredMessage{XML: buf, Recipient: sp.IDPMetadata.EntityID, ExpiresAt: expires}); err != nil {
		return nil, fmt.Errorf("artifact: cannot store the message: %w", err)
	}

	u, err := url.Parse(m.Destination)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("SAMLart", art)
	if m.RelayState != "" {
		q.Set("RelayState", m.RelayState)
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

func now(sp *saml.ServiceProvider) time.Time { return sp.Clock.Now() }

// newArtifact returns a new type 0x0004 artifact (saml-bindings §3.6.4):
// the type code, the endpoint index, the SHA-1 hash of the issuer's
// entity ID and a random message handle.
func newArtifact(entityID string, index uint16) (string, error) {
	buf := make([]byte, 44)
	binary.BigEndian.PutUint16(buf[0:2], 0x0004)
	binary.BigEndian.PutUint16(buf[2:4], index)
	source := sha1.Sum([]byte(entityID)) //nolint:gosec // see the import
	copy(buf[4:24], source[:])
	if _, err := io.ReadFull(rand.Reader, buf[24:44]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// ServeHTTP implements the ArtifactResolutionService: it answers an
// ArtifactResolve that the IdP sends with the SAML SOAP binding with an
// ArtifactResponse signed by the SP, carrying the message of the artifact.
//
// The ArtifactResolve must be signed by the IdP, be issued by it, and be
// fresh. A message is given only once, and only to the IdP it was sent to;
// an artifact that is unknown, expired, already resolved or meant for
// another party is answered with no message (saml-core §3.5.3). A request
// that is refused is answered with a SOAP fault.
func (b *Binding) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := b.resolve(r)
	if err != nil {
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

// errRefused is returned by resolve for a request it does not answer.
var errRefused = errors.New("artifact: refused")

func (b *Binding) resolve(r *http.Request) (*etree.Element, error) {
	if !saml.IsSOAPRequest(r) {
		return nil, errRefused
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxResolveSize+1))
	if err != nil || len(body) > maxResolveSize {
		return nil, errRefused
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return nil, errRefused
	}
	el := doc.FindElement("/Envelope/Body/ArtifactResolve")
	if el == nil || el.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return nil, errRefused
	}

	sp, err := b.config.ServiceProvider(r.Context())
	if err != nil {
		return nil, err
	}
	signed, err := sp.ValidateIDPSignedElement(el)
	if err != nil {
		return nil, err
	}
	var req saml.ArtifactResolve
	if err := unmarshal(signed, &req); err != nil {
		return nil, errRefused
	}
	if req.ID == "" || req.Issuer == nil || req.Issuer.Value != sp.IDPMetadata.EntityID {
		return nil, errRefused
	}
	t := now(sp)
	if req.IssueInstant.After(t.Add(saml.MaxClockSkew)) || t.After(req.IssueInstant.Add(saml.MaxIssueDelay)) {
		return nil, errRefused
	}

	var message *etree.Element
	stored, err := b.store.Take(r.Context(), req.Artifact)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.Recipient == req.Issuer.Value && !t.After(stored.ExpiresAt) {
		msgDoc := etree.NewDocument()
		if err := msgDoc.ReadFromBytes(stored.XML); err != nil {
			return nil, err
		}
		message = msgDoc.Root()
	}
	return b.artifactResponse(sp, req.ID, t, message)
}

// artifactResponse returns a signed ArtifactResponse to the request
// inResponseTo, carrying message if it is not nil.
func (b *Binding) artifactResponse(sp *saml.ServiceProvider, inResponseTo string, t time.Time, message *etree.Element) (*etree.Element, error) {
	id := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
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
