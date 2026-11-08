package samlsp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
)

// Service is the kind of IdP endpoint that Send addresses a message to.
type Service int

const (
	// SingleSignOnService is the IdP's SingleSignOnService, which receives
	// AuthnRequests.
	SingleSignOnService Service = iota + 1

	// SingleLogoutService is the IdP's SingleLogoutService, which receives
	// LogoutRequests at its Location and LogoutResponses at its
	// ResponseLocation, if it has one, and otherwise at its Location
	// (saml-metadata §2.2.2).
	SingleLogoutService
)

// OutgoingMessage describes a SAML protocol message for Send to build and
// send to the IdP through the browser.
type OutgoingMessage struct {
	// Service is the kind of IdP endpoint the message goes to.
	Service Service

	// Param is the name the bindings give the message: "SAMLRequest" or
	// "SAMLResponse". For a request, a RelayState longer than 80 bytes is
	// refused.
	Param string

	// RelayState is sent with the message.
	RelayState string

	// Sign says to sign the message with the key of WithSigningKey, if there is
	// one that can sign: with an enveloped XML signature, or with the
	// binding's own signature for HTTP-Redirect. Without such a key, the
	// message is sent unsigned. HTTP-POST-SimpleSign always signs, and
	// fails without a key. A request to the SingleSignOnService is also
	// signed when the call's ServiceProvider has a SignatureMethod, as its
	// metadata then says AuthnRequestsSigned="true".
	Sign bool

	// Build returns the message, unsigned, addressed to destination. sp is
	// the ServiceProvider of the call, built with the call's
	// ServiceProviderOptions, which Build may also use or change. Build
	// must call modify with the message, as a pointer to its saml type,
	// before returning its element, so that WithModify options apply.
	Build func(sp *saml.ServiceProvider, destination string, modify func(message any) error) (*etree.Element, error)
}

// WithModify changes the message a call builds, before it is signed, if
// the message is of type T: a pointer to its saml type, such as
// *saml.AuthnRequest. It is ignored for messages of other types. An error
// it returns is returned by the call. Packages that build messages with
// Send define their options with it.
func WithModify[T any](modify func(message T) error) MessageOption {
	return messageOptionFunc(func(o *messageOptions) {
		o.modify = append(o.modify, func(v any) error {
			if m, ok := v.(T); ok {
				return modify(m)
			}
			return nil
		})
	})
}

// modifier returns a function that applies the WithModify options of o.
func (o *messageOptions) modifier() func(any) error {
	return func(v any) error {
		for _, modify := range o.modify {
			if err := modify(v); err != nil {
				return err
			}
		}
		return nil
	}
}

// Send builds msg and sends it to the IdP's endpoint for its Service with
// the binding that opts choose: WithBinding, WithCustomBinding, or by
// default HTTP-Redirect when the IdP supports it and HTTP-POST otherwise.
// It returns the Message that sends it from the browser. AuthnRequest uses
// it; it is for packages that send other messages, such as single logout.
//
// If the IdP has no endpoint for the binding, the error matches
// ErrNoEndpoint.
func (c *Config) Send(ctx context.Context, msg OutgoingMessage, opts ...MessageOption) (*Message, error) {
	var o messageOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyMessage(&o)
		}
	}
	return c.send(IdentityProviderContext(ctx, o.idp), msg, o)
}

func (c *Config) send(ctx context.Context, msg OutgoingMessage, o messageOptions) (*Message, error) {
	if msg.Build == nil {
		return nil, errors.New("samlsp: Send needs a Build function")
	}
	if msg.Param != "SAMLRequest" && msg.Param != "SAMLResponse" {
		return nil, fmt.Errorf("samlsp: invalid message parameter %q", msg.Param)
	}
	sp, err := c.serviceProvider(ctx, o.sp)
	if err != nil {
		return nil, err
	}
	var locate func(string) string
	switch msg.Service {
	case SingleSignOnService:
		locate = sp.GetSSOBindingLocation
	case SingleLogoutService:
		locate = sp.GetSLOBindingLocation
		if msg.Param == "SAMLResponse" {
			locate = func(binding string) string { return sloResponseLocation(sp.IDPMetadata, binding) }
		}
	default:
		return nil, fmt.Errorf("samlsp: invalid service %d", msg.Service)
	}
	binding, location, err := pickBinding(o, locate)
	if err != nil {
		return nil, err
	}

	// Sign with the ServiceProvider of this call, as it is before Build,
	// which may change it.
	signer, method := messageSigner(sp, msg.Service)

	el, err := msg.Build(sp, location, o.modifier())
	if err != nil {
		return nil, err
	}
	if msg.Param == "SAMLRequest" && sp.LimitRelayStateLength && len(msg.RelayState) > saml.MaxRelayStateLength {
		return nil, fmt.Errorf("samlsp: the RelayState is longer than %d bytes", saml.MaxRelayStateLength)
	}

	// The SP metadata says AuthnRequestsSigned="true" whenever
	// SignatureMethod is set (saml-metadata §2.4.4), so keep that promise
	// even when a ServiceProviderOption, rather than SignAuthnRequests,
	// set it.
	if msg.Service == SingleSignOnService && msg.Param == "SAMLRequest" && sp.SignatureMethod != "" {
		msg.Sign = true
	}
	signMethod := ""
	if msg.Sign {
		signMethod = method
	}
	signed := func() (*etree.Element, error) {
		if signMethod == "" {
			return el, nil
		}
		return signElement(signer, el)
	}

	out := &OutboundMessage{
		ID: el.SelectAttrValue("ID", ""), Binding: binding, Destination: location, Param: msg.Param,
		RelayState: msg.RelayState, ScriptNonce: o.scriptNonce, element: signed,
	}
	if o.custom != nil {
		return o.custom.Encode(ctx, out)
	}
	switch binding {
	case saml.HTTPRedirectBinding:
		u, err := signer.RedirectBindingURL(location, msg.Param, el, msg.RelayState, signMethod)
		if err != nil {
			return nil, err
		}
		return out.Redirect(u), nil
	case saml.HTTPPostBinding:
		s, err := signed()
		if err != nil {
			return nil, err
		}
		doc := etree.NewDocument()
		doc.SetRoot(s)
		buf, err := doc.WriteToBytes()
		if err != nil {
			return nil, err
		}
		fields := url.Values{msg.Param: {base64.StdEncoding.EncodeToString(buf)}}
		if msg.RelayState != "" {
			fields.Set("RelayState", msg.RelayState)
		}
		return out.PostForm(fields)
	case saml.HTTPPostSimpleSignBinding:
		if method == "" {
			return nil, errors.New("samlsp: the HTTP-POST-SimpleSign binding needs an RSA or ECDSA key (see WithSigningKey)")
		}
		fields, err := signer.SimpleSignValues(msg.Param, el, msg.RelayState, method)
		if err != nil {
			return nil, err
		}
		return out.PostForm(fields)
	}
	return nil, fmt.Errorf("samlsp: unsupported binding %q", binding)
}

// sloResponseLocation returns where the IdP of md receives LogoutResponses
// with binding: the ResponseLocation of its first SingleLogoutService with
// binding, if set, and otherwise its Location (saml-metadata §2.2.2).
func sloResponseLocation(md *saml.EntityDescriptor, binding string) string {
	if md == nil {
		return ""
	}
	for _, d := range md.IDPSSODescriptors {
		for _, ep := range d.SingleLogoutServices {
			if ep.Binding != binding {
				continue
			}
			if ep.ResponseLocation != "" {
				return ep.ResponseLocation
			}
			return ep.Location
		}
	}
	return ""
}

// Prepare returns, for a message that a package sends other than through
// Send, such as directly to the IdP with the SOAP binding: the
// saml.ServiceProvider of the call, with the ServiceProviderOptions of
// opts applied, and a function that applies the WithModify options of opts
// to the message. The other options of opts do not apply.
func (c *Config) Prepare(ctx context.Context, opts ...MessageOption) (*saml.ServiceProvider, func(message any) error, error) {
	var o messageOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyMessage(&o)
		}
	}
	sp, err := c.serviceProvider(IdentityProviderContext(ctx, o.idp), o.sp)
	if err != nil {
		return nil, nil, err
	}
	return sp, o.modifier(), nil
}

// messageSigner returns a copy of sp, the ServiceProvider of a call, that
// signs a message for service, and the signature method it uses: the
// SignatureMethod of an AuthnRequest, if set, and otherwise
// LogoutSignatureMethod, which is that of WithSignatureMethod unless a
// ServiceProviderOption changed it. The method is "" without a key that
// can sign.
func messageSigner(sp *saml.ServiceProvider, service Service) (*saml.ServiceProvider, string) {
	method := sp.LogoutSignatureMethod
	if service == SingleSignOnService && sp.SignatureMethod != "" {
		method = sp.SignatureMethod
	}
	if signatureMethod(sp.Key) == "" {
		method = ""
	}
	signer := *sp
	signer.SignatureMethod = method
	return &signer, method
}

// NewMessage returns a Message whose Write calls write: for example, the
// answer to a request the IdP made directly, such as with the SOAP
// binding.
func NewMessage(id, binding string, write func(w http.ResponseWriter)) *Message {
	return &Message{ID: id, Binding: binding, write: write}
}

// WithCheck adds a check that New runs on the saml.ServiceProvider it
// builds, with the ServiceProviderOptions passed to New applied: New
// returns its error. Packages that add options with ServiceProviderOptions
// use it to refuse settings that cannot work.
func WithCheck(check func(sp *saml.ServiceProvider) error) Option {
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
