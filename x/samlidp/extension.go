package samlidp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"

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
	idp := c.identityProvider(opts)
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
	return signElement(c.identityProvider(opts), el)
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
// messages from SPs, such as LogoutRequests, use it; prefix id with the
// kind of message (such as "LogoutRequest:") so that the IDs of different
// kinds cannot collide.
func (c *Config) Consume(ctx context.Context, serviceProvider, id string, expiresAt time.Time) error {
	return c.replayState.Consume(ctx, ReplayKey(serviceProvider, id), expiresAt)
}

// Now returns the current time, by the clock of WithClock.
func (c *Config) Now() time.Time { return c.clock.Now() }
