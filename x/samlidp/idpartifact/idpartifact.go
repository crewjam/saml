// Package idpartifact sends SAML Responses from an identity provider made
// with github.com/crewjam/saml/x/samlidp to service providers with the
// HTTP-Artifact binding (saml-bindings §3.6): the browser carries only a
// short artifact to the SP's assertion consumer service, and the SP fetches
// the Response itself from the IdP's ArtifactResolutionService, server to
// server. The assertion then never passes through the browser. It is the
// IdP's side of the HTTP-Artifact binding that x/samlsp resolves, and the
// counterpart of github.com/crewjam/saml/x/samlsp/artifact.
//
// Advertise the ArtifactResolutionService with ResolutionService when
// making the samlidp.Config, serve the Binding at its path, and pass the
// Binding with samlidp.WithCustomBinding to ParseAuthnRequest, Response and
// ErrorResponse:
//
//	config, err := samlidp.New(entityID, sps, samlidp.WithSigningKey(key, cert),
//		idpartifact.ResolutionService("https://idp.example.com/saml/artifact", 1))
//	binding, err := idpartifact.New(config, idpartifact.NewMemoryStore(), 1)
//	http.Handle(binding.Path(), binding)
//
//	artifacts := samlidp.WithCustomBinding(binding)
//	req, err := config.ParseAuthnRequest(ctx, r, artifacts)
//	...
//	msg, err := config.Response(ctx, req, subject, artifacts)
//	msg.Write(w)
//
// The artifact is used when the AuthnRequest asks for an assertion
// consumer service with the HTTP-Artifact binding, by index, or by URL
// with ProtocolBinding HTTP-Artifact (as x/samlsp does with
// samlsp.WithResponseBinding(saml.HTTPArtifactBinding)); other requests
// are answered with HTTP-POST as before.
//
// The browser takes the artifact to the SP with a redirect, or, with
// Binding.Form, with a form it posts. The SP must sign its ArtifactResolve
// requests; the IdP signs its ArtifactResponses with the key of
// samlidp.WithSigningKey.
package idpartifact

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SAML type 0x0004 artifacts identify their source by SHA-1 (saml-bindings §3.6.4)
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp/artifact"
)

// Store keeps messages until their artifacts are resolved. It is the
// Store of x/samlsp/artifact: a message's Recipient is the entity ID of
// the SP the Response is for. A Binding served by several processes needs
// a Store that they share, since the SP's request may reach any of them.
type Store = artifact.Store

// StoredMessage is a message waiting for its artifact to be resolved.
type StoredMessage = artifact.StoredMessage

// MemoryStore is a Store in memory, for a single process.
type MemoryStore = artifact.MemoryStore

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return artifact.NewMemoryStore() }

// DefaultLifetime is how long a Response waits for its artifact to be
// resolved, unless Binding.Lifetime says otherwise.
const DefaultLifetime = 2 * time.Minute

// maxResolveSize is the largest ArtifactResolve request read.
const maxResolveSize = 64 << 10

// Binding sends Responses with the HTTP-Artifact binding, and serves the
// ArtifactResolutionService from which the SPs fetch them. It is a
// samlidp.Binding and an http.Handler.
type Binding struct {
	config *samlidp.Config
	store  Store
	index  uint16

	// Lifetime is how long a Response waits for its artifact to be
	// resolved. If zero, DefaultLifetime is used.
	Lifetime time.Duration

	// Form makes Encode send the artifact to the SP with an HTML form
	// that the browser posts, instead of a redirect (saml-bindings
	// §3.6.3). A form keeps the artifact and RelayState out of the URL,
	// and so out of logs and the Referer header.
	Form bool
}

var (
	_ samlidp.Binding = (*Binding)(nil)
	_ http.Handler    = (*Binding)(nil)
)

// New returns a Binding for config that keeps Responses in store until
// they are resolved. index is the index of the IdP's
// ArtifactResolutionService, as passed to ResolutionService; the artifacts
// name it, so that the SP knows where to resolve them. New returns an
// error if the IdP metadata has no ArtifactResolutionService with the SOAP
// binding and that index, since the SPs could then resolve none of the
// Binding's artifacts.
//
// If store is a *MemoryStore with no Clock, New sets its Clock to that of
// config (see samlidp.WithClock), by which the Binding's messages expire.
func New(config *samlidp.Config, store Store, index uint16) (*Binding, error) {
	b := &Binding{config: config, store: store, index: index}
	if _, err := b.path(); err != nil {
		return nil, err
	}
	if m, ok := store.(*MemoryStore); ok && m.Clock == nil {
		m.Clock = config.IdentityProvider().Clock
	}
	return b, nil
}

// ResolutionService advertises, in the IdP metadata, the IdP's
// ArtifactResolutionService at location, an absolute URL, with the SOAP
// binding and index. Serve the Binding at Binding.Path.
func ResolutionService(location string, index uint16) samlidp.Option {
	u, err := url.Parse(location)
	if err == nil && (!u.IsAbs() || u.Host == "") {
		err = fmt.Errorf("idpartifact: the ArtifactResolutionService URL must be an absolute URL, not %q", location)
	}
	if err != nil {
		return samlidp.WithCheck(func(*saml.IdentityProvider) error { return err })
	}
	return samlidp.WithMetadata(func(md *saml.EntityDescriptor) {
		for i := range md.IDPSSODescriptors {
			d := &md.IDPSSODescriptors[i].SSODescriptor
			d.ArtifactResolutionServices = append(d.ArtifactResolutionServices,
				saml.IndexedEndpoint{Binding: saml.SOAPBinding, Location: location, Index: int(index)})
		}
	})
}

// Path returns the path of the URL of the IdP's ArtifactResolutionService
// with the Binding's index, to serve the Binding at, so that it cannot
// drift from the URL in the IdP metadata:
//
//	http.Handle(binding.Path(), binding)
//
// New has checked that the IdP metadata has such a service.
func (b *Binding) Path() string {
	p, err := b.path()
	if err != nil {
		// New checked the metadata, which a Config does not change.
		panic(err)
	}
	return p
}

// path returns the path of the URL of the ArtifactResolutionService with
// the SOAP binding and the Binding's index in the IdP metadata.
func (b *Binding) path() (string, error) {
	for _, d := range b.config.Metadata().IDPSSODescriptors {
		for _, ars := range d.SSODescriptor.ArtifactResolutionServices {
			if ars.Index != int(b.index) || ars.Binding != saml.SOAPBinding {
				continue
			}
			u, err := url.Parse(ars.Location)
			if err != nil {
				return "", fmt.Errorf("idpartifact: the ArtifactResolutionService URL %q: %w", ars.Location, err)
			}
			if p := u.EscapedPath(); p != "" {
				return p, nil
			}
			return "/", nil
		}
	}
	return "", fmt.Errorf("idpartifact: the IdP metadata has no ArtifactResolutionService with index %d (see ResolutionService)", b.index)
}

// URI implements samlidp.Binding.
func (b *Binding) URI() string { return saml.HTTPArtifactBinding }

// Encode implements samlidp.Binding. It keeps the message under a new
// artifact, for m.ServiceProvider only, and returns a Message that sends
// the browser to the SP with the artifact: a redirect, or, with Form, a
// form that the browser posts.
func (b *Binding) Encode(ctx context.Context, m *samlidp.OutboundMessage) (*samlidp.Message, error) {
	if m.ServiceProvider == "" {
		return nil, errors.New("idpartifact: the message names no service provider to resolve it")
	}
	doc := etree.NewDocument()
	doc.SetRoot(m.Element.Copy())
	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	art, err := newArtifact(b.config.EntityID(), b.index)
	if err != nil {
		return nil, err
	}
	expires := b.config.Now().Add(b.lifetime())
	if err := b.store.Save(ctx, art, StoredMessage{XML: buf, Recipient: m.ServiceProvider, ExpiresAt: expires}); err != nil {
		return nil, fmt.Errorf("idpartifact: cannot store the message: %w", err)
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
// ArtifactResolve that an SP sends with the SAML SOAP binding with an
// ArtifactResponse signed by the IdP, carrying the message of the
// artifact.
//
// The ArtifactResolve must be signed by an SP that the ServiceProviderFunc
// knows, be issued by it, and be fresh. A message is given only once, and
// only to the SP it was sent to; an artifact that is unknown, expired,
// already resolved or meant for another SP is answered with no message
// (saml-core §3.5.3). A request that is refused is answered with a SOAP
// fault.
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
var errRefused = errors.New("idpartifact: refused")

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

	// The Issuer names the SP whose keys must verify the signature; it is
	// trusted only once they have.
	issuer := el.FindElement("./Issuer")
	if issuer == nil || issuer.Text() == "" {
		return nil, errRefused
	}
	ctx := r.Context()
	md, err := b.config.ServiceProvider(ctx, issuer.Text())
	if err != nil {
		return nil, err
	}
	signed, err := b.config.IdentityProvider().ValidateSPSignedElement(el, md)
	if err != nil {
		return nil, err
	}
	var req saml.ArtifactResolve
	if err := unmarshal(signed, &req); err != nil {
		return nil, errRefused
	}
	if req.ID == "" || req.Issuer == nil || req.Issuer.Value != md.EntityID {
		return nil, errRefused
	}
	t := b.config.Now()
	if req.IssueInstant.After(t.Add(saml.MaxClockSkew)) || t.After(req.IssueInstant.Add(saml.MaxIssueDelay)) {
		return nil, errRefused
	}

	var message *etree.Element
	stored, err := b.store.Take(ctx, req.Artifact, md.EntityID)
	if err != nil {
		return nil, err
	}
	// The recipient is checked again, in case the Store does not.
	if stored != nil && stored.Recipient == md.EntityID && !t.After(stored.ExpiresAt) {
		msgDoc := etree.NewDocument()
		if err := msgDoc.ReadFromBytes(stored.XML); err != nil {
			return nil, err
		}
		message = msgDoc.Root()
	}
	return b.artifactResponse(req.ID, t, message)
}

// artifactResponse returns a signed ArtifactResponse to the request
// inResponseTo, carrying message if it is not nil.
func (b *Binding) artifactResponse(inResponseTo string, t time.Time, message *etree.Element) (*etree.Element, error) {
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
	el.CreateElement("saml:Issuer").SetText(b.config.EntityID())
	el.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", saml.StatusSuccess)
	if message != nil {
		el.AddChild(message)
	}
	// SignElement puts the Signature right after the Issuer, as the schema
	// requires.
	return b.config.SignElement(el)
}

// unmarshal reads el into v.
func unmarshal(el *etree.Element, v any) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	buf, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(buf, v) //nolint:gosec // el is what a verified signature covers
}
