package samlsp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
)

// This file holds the extension points of the package: the means for
// other packages to add bindings, extend the SP metadata, and handle SAML
// messages this package does not.

// Binding sends an OutboundMessage to the IdP. AuthnRequest, LogoutRequest
// and LogoutResponse use one passed with WithCustomBinding instead of the
// bindings built in (HTTP-Redirect, HTTP-POST and HTTP-POST-SimpleSign).
type Binding interface {
	// URI is the binding's URI, such as saml.HTTPArtifactBinding. The
	// message is addressed to the IdP endpoint that has this binding in
	// its metadata.
	URI() string

	// Encode returns the Message that sends m to the IdP, made with
	// m.Redirect or m.Respond.
	Encode(ctx context.Context, m *OutboundMessage) (*Message, error)
}

// WithCustomBinding sends the message with b instead of a built-in
// binding. The IdP metadata must have an endpoint for b.URI() of the right
// kind: a SingleSignOnService for an AuthnRequest, a SingleLogoutService
// for logout messages; otherwise the error matches ErrNoEndpoint.
func WithCustomBinding(b Binding) MessageOption {
	return messageOptionFunc(func(o *messageOptions) { o.custom = b })
}

// OutboundMessage is a SAML protocol message that a Config has built, for
// a Binding to send. It is addressed and, if the SP signs messages of its
// kind, signed.
type OutboundMessage struct {
	// ID is the ID of the message.
	ID string

	// Binding is the URI of the binding, and Destination the IdP endpoint
	// with that binding, to which the message is addressed.
	Binding     string
	Destination string

	// Param is the name the bindings give the message: "SAMLRequest" or
	// "SAMLResponse".
	Param string

	// RelayState and ScriptNonce are those of the call that built the
	// message.
	RelayState  string
	ScriptNonce string

	element func() (*etree.Element, error)
}

// Element returns the message as XML, carrying an enveloped signature if
// the SP signs messages of its kind: AuthnRequests with SignAuthnRequests,
// logout messages whenever it has a key that can sign.
func (m *OutboundMessage) Element() (*etree.Element, error) { return m.element() }

// Redirect returns a Message that sends the browser to u with a 302
// redirect.
func (m *OutboundMessage) Redirect(u *url.URL) *Message {
	return &Message{ID: m.ID, Binding: m.Binding, Destination: m.Destination, RelayState: m.RelayState, redirectURL: u}
}

// Respond returns a Message whose Write calls write.
func (m *OutboundMessage) Respond(write func(w http.ResponseWriter)) *Message {
	return &Message{ID: m.ID, Binding: m.Binding, Destination: m.Destination, RelayState: m.RelayState, write: write}
}

// pickBinding returns the binding to send a message with, and the IdP
// endpoint for it found by locate: the custom binding of o if there is
// one, the built-in one chooseBinding picks otherwise.
func pickBinding(o messageOptions, locate func(string) string) (string, string, error) {
	if o.custom == nil {
		return chooseBinding(o.binding, locate)
	}
	uri := o.custom.URI()
	location := locate(uri)
	if location == "" {
		return "", "", fmt.Errorf("%w %s", ErrNoEndpoint, uri)
	}
	return uri, location, nil
}

// WithMetadata calls modify with the SP metadata each time it is made, by
// Metadata and ServeMetadata, after the other options have shaped it and
// before it is signed. Use it to add what no option adds, such as an
// ArtifactResolutionService or an extension element.
func WithMetadata(modify func(md *saml.EntityDescriptor)) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.metadataHooks = append(c.metadataHooks, modify)
	})
}

// ServiceProvider returns the saml.ServiceProvider that the methods of c
// use, built for this call with the identity provider's metadata, and with
// the ServiceProviderOptions passed to New and then opts applied. It is
// for packages that handle SAML messages this package does not; the
// result is a new value, which may be changed.
//
// To sign with the SP's key, use SignElement: the ServiceProvider signs
// AuthnRequests with SignatureMethod only when SignAuthnRequests is set.
func (c *Config) ServiceProvider(ctx context.Context, opts ...ServiceProviderOption) (*saml.ServiceProvider, error) {
	return c.serviceProvider(ctx, opts)
}

// SignElement returns el with an enveloped XML signature made with the key
// of WithKey and the method of WithSignatureMethod (by default SHA-256).
// The signature references el by its ID attribute, which el must have.
// el is not modified.
func (c *Config) SignElement(el *etree.Element) (*etree.Element, error) {
	if signatureMethod(c.key) == "" {
		return nil, errors.New("samlsp: SignElement needs an RSA or ECDSA key (see WithKey)")
	}
	sp := c.localServiceProvider()
	signWithLogoutMethod(sp)
	signingContext, err := saml.GetSigningContext(sp)
	if err != nil {
		return nil, err
	}
	return signingContext.SignEnveloped(el.Copy())
}
