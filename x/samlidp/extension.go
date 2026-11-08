package samlidp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

// This file holds the extension points of the package: the means for
// other packages, such as x/samlidp/idpslo, to send SAML messages this
// package does not.

// OutgoingMessage is a SAML protocol message for Send to sign and send to
// a service provider through the browser.
type OutgoingMessage struct {
	// Element is the message, unsigned. It must have an ID attribute,
	// which its signature references, and should have an Issuer.
	Element *etree.Element

	// Destination is the SP endpoint it is sent to, and Binding its
	// binding: saml.HTTPRedirectBinding or saml.HTTPPostBinding.
	Destination string
	Binding     string

	// Param is the name the bindings give the message: "SAMLRequest" or
	// "SAMLResponse".
	Param string

	// RelayState is sent with the message.
	RelayState string

	// InResponseTo is the ID of the request the message answers, if any,
	// for Message.InResponseTo.
	InResponseTo string

	// ScriptNonce, if set, is the nonce attribute of the script of the
	// HTTP-POST form (see WithScriptNonce).
	ScriptNonce string
}

// Send signs msg with the key of WithSigningKey and returns the Message
// that sends it from the browser: with HTTP-Redirect, a redirect whose
// query carries the signature (saml-bindings §3.4.4.1); with HTTP-POST, a
// form that posts the message with an enveloped signature. opts are
// applied after the IdentityProviderOptions passed to New, as for the
// other methods.
func (c *Config) Send(msg OutgoingMessage, opts ...IdentityProviderOption) (*Message, error) {
	if msg.Element == nil {
		return nil, errors.New("samlidp: Send needs a message")
	}
	if msg.Param != "SAMLRequest" && msg.Param != "SAMLResponse" {
		return nil, fmt.Errorf("samlidp: invalid message parameter %q", msg.Param)
	}
	idp, err := c.checkedIdentityProvider(opts)
	if err != nil {
		return nil, err
	}
	m := &Message{
		ID:           msg.Element.SelectAttrValue("ID", ""),
		InResponseTo: msg.InResponseTo,
		Binding:      msg.Binding,
		Destination:  msg.Destination,
		RelayState:   msg.RelayState,
	}
	switch msg.Binding {
	case saml.HTTPRedirectBinding:
		u, err := idp.RedirectBindingURL(msg.Destination, msg.Param, msg.Element, msg.RelayState)
		if err != nil {
			return nil, err
		}
		m.redirectURL = u
		return m, nil
	case saml.HTTPPostBinding:
		signed, err := signElement(idp, msg.Element)
		if err != nil {
			return nil, err
		}
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		buf, err := doc.WriteToBytes()
		if err != nil {
			return nil, err
		}
		m.fields = []formField{{msg.Param, base64.StdEncoding.EncodeToString(buf)}}
		if msg.RelayState != "" {
			m.fields = append(m.fields, formField{"RelayState", msg.RelayState})
		}
		if err := m.setForm(msg.ScriptNonce); err != nil {
			return nil, err
		}
		return m, nil
	default:
		return nil, fmt.Errorf("samlidp: Send cannot send with binding %q", msg.Binding)
	}
}

// SignElement returns a copy of el with an enveloped XML signature made
// with the key of WithSigningKey and the method of WithSignatureMethod (by
// default SHA-256). The signature references el by its ID attribute, which
// el must have. It is placed right after el's Issuer child, if el has one,
// as the SAML schema requires of protocol messages and assertions, and
// last otherwise. el is not modified.
func (c *Config) SignElement(el *etree.Element, opts ...IdentityProviderOption) (*etree.Element, error) {
	idp, err := c.checkedIdentityProvider(opts)
	if err != nil {
		return nil, err
	}
	return signElement(idp, el)
}

// signElement returns a copy of el signed by idp.
func signElement(idp *saml.IdentityProvider, el *etree.Element) (*etree.Element, error) {
	if el.SelectAttrValue("ID", "") == "" {
		return nil, errors.New("samlidp: the element to sign has no ID")
	}
	signer, err := signingContext(idp)
	if err != nil {
		return nil, err
	}
	signed := el.Copy()
	sig, err := signer.ConstructSignature(signed, true)
	if err != nil {
		return nil, err
	}
	at := len(signed.Child)
	if first := signed.ChildElements(); len(first) > 0 && first[0].Tag == "Issuer" {
		at = first[0].Index() + 1
	}
	signed.InsertChildAt(at, sig)
	return signed, nil
}

// Consume records, in the ReplayState of WithReplayState, that the
// message id of the SP serviceProvider has been accepted, until
// expiresAt, under ReplayKey(serviceProvider, id). It fails with
// saml.ErrAssertionReplayed if it already was. Packages that accept other
// messages from SPs use it; prefix id with the kind of message so that the
// IDs of different kinds cannot collide, as x/samlidp/idpslo does with
// "LogoutRequest:" and "LogoutResponse:". AuthnRequests are recorded by
// their bare ID.
func (c *Config) Consume(ctx context.Context, serviceProvider, id string, expiresAt time.Time) error {
	return c.replayState.Consume(ctx, ReplayKey(serviceProvider, id), expiresAt)
}

// Now returns the current time in UTC, by the clock of WithClock, as
// package saml reads it to validate requests and stamp what the IdP
// issues: without WithClock, from saml.TimeNow.
func (c *Config) Now() time.Time { return clockNow(c.clock) }

// Rand returns the source of cryptographically random bytes of WithRand,
// or crypto/rand's Reader without it. Packages that extend this one, such
// as x/samlidp/idpartifact, read their random IDs and artifacts from it.
func (c *Config) Rand() io.Reader {
	if c.randReader != nil {
		return c.randReader
	}
	return rand.Reader
}

// clockNow returns the current time in UTC from clock or, if it is nil,
// from saml.TimeNow, as package saml does.
func clockNow(clock *dsig.Clock) time.Time {
	if clock != nil {
		return clock.Now().UTC()
	}
	return saml.TimeNow() //nolint:staticcheck // package saml's fallback when no Clock is set
}

// Binding sends a Response to a service provider's assertion consumer
// service with a binding other than those built in (HTTP-POST and
// HTTP-POST-SimpleSign), such as the HTTP-Artifact binding of
// github.com/crewjam/saml/x/samlidp/idpartifact. Pass it with
// WithCustomBinding.
type Binding interface {
	// URI is the binding's URI, such as saml.HTTPArtifactBinding.
	URI() string

	// Encode returns the Message that sends m to the SP, made with
	// m.Redirect or m.PostForm, or with NewMessage.
	Encode(ctx context.Context, m *OutboundMessage) (*Message, error)
}

// CustomBindingOption is the option that WithCustomBinding returns. It is
// a ParseOption and a ResponseOption.
type CustomBindingOption struct{ b Binding }

// WithCustomBinding lets ParseAuthnRequest accept an AuthnRequest whose
// assertion consumer service has the binding of b, and makes Response and
// ErrorResponse send to such a service with b. Pass it to all three, and
// to IDPInitiated, which then chooses the SP's default ACS among those
// with b's binding as well as those a Response can be posted to.
//
// An AuthnRequest that names its ACS by index gets that ACS. One that
// names it by URL and asks for b's binding (ProtocolBinding) gets the ACS
// with that binding at that URL, if the SP lists one; one that names none
// and asks for b's binding gets the SP's default ACS with that binding
// (saml-metadata §2.2.3), if it lists one. Without WithCustomBinding, an
// ACS with b's binding is answered with StatusUnsupportedBinding at the
// SP's default ACS.
func WithCustomBinding(b Binding) CustomBindingOption { return CustomBindingOption{b} }

func (o CustomBindingOption) applyParse(p *parseOptions)       { p.custom = o.b }
func (o CustomBindingOption) applyResponse(r *responseOptions) { r.custom = o.b }

// OutboundMessage is a signed SAML protocol message that a Config has
// made, for a Binding to send.
type OutboundMessage struct {
	// ID is the ID of the message, and InResponseTo that of the request it
	// answers, if any.
	ID           string
	InResponseTo string

	// Binding is the URI of the binding, and Destination the SP endpoint
	// with that binding, to which the message is addressed.
	Binding     string
	Destination string

	// ServiceProvider is the entity ID of the SP the message is for.
	ServiceProvider string

	// Param is the name the bindings give the message: "SAMLRequest" or
	// "SAMLResponse".
	Param string

	// RelayState and ScriptNonce are those of the call that made the
	// message.
	RelayState  string
	ScriptNonce string

	// Element is the message, signed. It must not be modified.
	Element *etree.Element
}

// Redirect returns a Message that sends the browser to u with a 302
// redirect.
func (m *OutboundMessage) Redirect(u *url.URL) *Message {
	msg := m.message()
	msg.redirectURL = u
	return msg
}

// PostForm returns a Message that posts fields to m.Destination from the
// browser, with a page holding an HTML form that submits itself, as the
// POST bindings do: the fields are escaped, the page's
// Content-Security-Policy allows only the form's script (and that script
// carries m.ScriptNonce, if set), and it is not cached. Add RelayState to
// fields yourself if the binding sends it.
func (m *OutboundMessage) PostForm(fields url.Values) (*Message, error) {
	msg := m.message()
	names := slices.Sorted(maps.Keys(fields))
	msg.fields = []formField{}
	for _, name := range names {
		for _, value := range fields[name] {
			msg.fields = append(msg.fields, formField{name, value})
		}
	}
	if err := msg.setForm(m.ScriptNonce); err != nil {
		return nil, err
	}
	return msg, nil
}

func (m *OutboundMessage) message() *Message {
	return &Message{
		ID: m.ID, InResponseTo: m.InResponseTo, Binding: m.Binding,
		Destination: m.Destination, RelayState: m.RelayState,
	}
}
