package samlidp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// Subject is what the identity provider asserts about the user it has
// authenticated: who they are, how and when they logged in, and their
// attributes.
type Subject struct {
	// NameID identifies the user to the SP. It is required.
	NameID string

	// NameIDFormat is the format of NameID, such as
	// saml.PersistentNameIDFormat or saml.EmailAddressNameIDFormat. The
	// default is saml.TransientNameIDFormat, which the SP takes to change
	// at each login, as package saml has it. For the persistent and
	// transient formats, the NameID is qualified with the IdP's and the
	// SP's entity IDs (saml-core §8.3.7, §8.3.8).
	NameIDFormat saml.NameIDFormat

	// AuthnInstant is when the IdP authenticated the user. It is required.
	// For a login from an existing session, it is when that session
	// began, not now.
	AuthnInstant time.Time

	// AuthnContextClassRef is how the IdP authenticated the user. The
	// default is saml.AuthnContextPasswordProtectedTransport. It must
	// satisfy the AuthnRequest's AuthnContextClasses.
	AuthnContextClassRef saml.AuthnContextClass

	// SessionIndex, if not empty, names the user's session at the IdP, for
	// single logout.
	SessionIndex string

	// SessionNotOnOrAfter, if not zero, is when the SP must end the
	// session it creates from the assertion.
	SessionNotOnOrAfter time.Time

	// Attributes are the attributes the IdP sends about the user.
	Attributes []Attribute
}

// Attribute is a SAML attribute, with its values as strings
// (xs:string).
type Attribute struct {
	// Name identifies the attribute, as NameFormat says how to read it:
	// for example "urn:oid:0.9.2342.19200300.100.1.3" (mail) with the
	// NameFormat "urn:oasis:names:tc:SAML:2.0:attrname-format:uri". An
	// empty NameFormat means unspecified.
	Name       string
	NameFormat string

	// FriendlyName is an optional, human-readable form of Name, such as
	// "mail".
	FriendlyName string

	// Values are the attribute's values.
	Values []string
}

// ResponseOption customizes Response and ErrorResponse.
type ResponseOption interface {
	applyResponse(*responseOptions)
}

type responseOptions struct {
	idp     []IdentityProviderOption
	address string
	modify  []func(*saml.Assertion) error
	nonce   string
}

type responseOptionFunc func(*responseOptions)

func (f responseOptionFunc) applyResponse(o *responseOptions) { f(o) }

// WithSubjectAddress sets the network address of the user's browser, as
// the application sees it, which the assertion carries in its
// SubjectConfirmationData and SubjectLocality (saml-core §2.4.1.2). Some
// SPs check it against the address the Response arrives from. Without
// it, the assertion carries none.
func WithSubjectAddress(address string) ResponseOption {
	return responseOptionFunc(func(o *responseOptions) { o.address = address })
}

// WithAssertion calls modify with the assertion before it is signed (and
// encrypted), to set what has no option of its own, such as attributes
// of a complex type or an AttributeStatement's encrypted attributes. An
// error it returns is returned by Response.
func WithAssertion(modify func(a *saml.Assertion) error) ResponseOption {
	return responseOptionFunc(func(o *responseOptions) { o.modify = append(o.modify, modify) })
}

// WithScriptNonce sets the nonce attribute of the script that makes the
// form of the Response submit itself. Use it when a
// Content-Security-Policy set by your application allows scripts by
// nonce. Message.Write's own policy allows the script by its hash.
func WithScriptNonce(nonce string) ResponseOption {
	return responseOptionFunc(func(o *responseOptions) { o.nonce = nonce })
}

// Response returns the Response that tells the service provider who the
// user is, as the answer to req, to send with Message.Write. The assertion
// is signed, and so is the Response; the assertion is encrypted if the
// SP's metadata publishes an encryption certificate.
//
// The service provider is looked up again, and req.ACSURL must still be
// one of its assertion consumer services.
//
// The request may ask for what the IdP will not assert: a NameID format
// other than subject.NameIDFormat, an authentication context that
// subject.AuthnContextClassRef does not satisfy, or a user other than
// subject. The error then matches *saml.StatusError; send it to the SP
// with ErrorResponse.
func (c *Config) Response(ctx context.Context, req *AuthnRequest, subject Subject, opts ...ResponseOption) (*Message, error) {
	o := newResponseOptions(opts)
	if subject.NameID == "" {
		return nil, errors.New("samlidp: the subject has no NameID")
	}
	if subject.AuthnInstant.IsZero() {
		return nil, errors.New("samlidp: the subject has no AuthnInstant")
	}
	ireq, err := c.answer(ctx, req, o)
	if err != nil {
		return nil, err
	}

	session := &saml.Session{
		NameID:               subject.NameID,
		NameIDFormat:         string(subject.NameIDFormat),
		Index:                subject.SessionIndex,
		CreateTime:           subject.AuthnInstant,
		AuthnContextClassRef: string(subject.AuthnContextClassRef),
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(ireq, session); err != nil {
		return nil, err
	}
	a := ireq.Assertion
	// DefaultAssertionMaker makes attributes of its own from the fields of
	// the Session, which are left empty: the subject's are the only ones.
	a.AttributeStatements = nil
	if len(subject.Attributes) > 0 {
		a.AttributeStatements = []saml.AttributeStatement{{Attributes: samlAttributes(subject.Attributes)}}
	}
	if !subject.SessionNotOnOrAfter.IsZero() {
		t := subject.SessionNotOnOrAfter
		for i := range a.AuthnStatements {
			a.AuthnStatements[i].SessionNotOnOrAfter = &t
		}
	}
	for _, modify := range o.modify {
		if err := modify(a); err != nil {
			return nil, err
		}
	}
	if err := ireq.CheckRequestSubject(); err != nil {
		return nil, err
	}
	participant := &saml.SessionParticipant{
		ServiceProviderID: ireq.ServiceProviderMetadata.EntityID,
		SessionIndex:      subject.SessionIndex,
	}
	if a.Subject != nil && a.Subject.NameID != nil {
		participant.NameID = *a.Subject.NameID
	}
	if err := ireq.MakeResponse(); err != nil {
		return nil, err
	}
	msg, err := postResponse(ireq, o.nonce)
	if err != nil {
		return nil, err
	}
	msg.Participant = participant
	return msg, nil
}

// ErrorResponse returns a Response to req that carries status and no
// assertion, to send with Message.Write: for example, with
// saml.StatusResponder and the second-level status saml.StatusNoPassive,
// for an IsPassive request when the user has no session, or
// saml.StatusAuthnFailed or saml.StatusRequestDenied. Its Message is read
// by the SP, so it should not reveal anything the SP should not know.
//
// Use it too for the *saml.StatusError that ParseAuthnRequest and
// Response return.
func (c *Config) ErrorResponse(ctx context.Context, req *AuthnRequest, status *saml.StatusError, opts ...ResponseOption) (*Message, error) {
	if status == nil {
		return nil, errors.New("samlidp: ErrorResponse needs a status")
	}
	o := newResponseOptions(opts)
	ireq, err := c.answer(ctx, req, o)
	if err != nil {
		return nil, err
	}
	if err := ireq.MakeErrorResponse(status.TopLevel, status.SecondLevel, status.Message); err != nil {
		return nil, err
	}
	return postResponse(ireq, o.nonce)
}

func newResponseOptions(opts []ResponseOption) responseOptions {
	var o responseOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyResponse(&o)
		}
	}
	return o
}

// answer returns the saml.IdpAuthnRequest that answers req: with the
// IdentityProvider of the call, the SP's metadata, and its assertion
// consumer service at req.ACSURL.
func (c *Config) answer(ctx context.Context, req *AuthnRequest, o responseOptions) (*saml.IdpAuthnRequest, error) {
	if req == nil {
		return nil, errors.New("samlidp: nil AuthnRequest")
	}
	if !sendable(req.ACSBinding) {
		return nil, fmt.Errorf("samlidp: cannot send a response with binding %q", req.ACSBinding)
	}
	md, err := lookupServiceProvider(ctx, c.serviceProviders, req.ServiceProvider)
	if err != nil {
		return nil, err
	}
	idp := c.identityProvider(o.idp)
	ireq := &saml.IdpAuthnRequest{
		IDP:                     idp,
		HTTPRequest:             (&http.Request{RemoteAddr: o.address}).WithContext(ctx),
		RelayState:              req.RelayState,
		Request:                 req.samlRequest(),
		ServiceProviderMetadata: md,
		Now:                     idp.Clock.Now(),
	}
	ireq.SPSSODescriptor, ireq.ACSEndpoint = findACS(md, req.ACSURL, req.ACSBinding)
	if ireq.ACSEndpoint == nil {
		return nil, fmt.Errorf("samlidp: service provider %q has no assertion consumer service %s with binding %s: %w",
			req.ServiceProvider, req.ACSURL, req.ACSBinding, saml.ErrUnknownAssertionConsumerService)
	}
	return ireq, nil
}

// findACS returns copies of the assertion consumer service of md at
// location with binding, and of its SPSSODescriptor, or nils.
func findACS(md *saml.EntityDescriptor, location, binding string) (*saml.SPSSODescriptor, *saml.IndexedEndpoint) {
	u, err := url.Parse(location)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, nil
	}
	for _, d := range md.SPSSODescriptors {
		for _, ep := range d.AssertionConsumerServices {
			if ep.Location == location && ep.Binding == binding {
				d, ep := d, ep
				return &d, &ep
			}
		}
	}
	return nil, nil
}

// samlAttributes returns attrs as saml.Attributes, with xs:string values.
func samlAttributes(attrs []Attribute) []saml.Attribute {
	out := make([]saml.Attribute, 0, len(attrs))
	for _, attr := range attrs {
		values := make([]saml.AttributeValue, 0, len(attr.Values))
		for _, v := range attr.Values {
			values = append(values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		out = append(out, saml.Attribute{
			Name:         attr.Name,
			NameFormat:   attr.NameFormat,
			FriendlyName: attr.FriendlyName,
			Values:       values,
		})
	}
	return out
}
