package samlsp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
)

// ErrNoEndpoint is returned when the identity provider's metadata lists no
// endpoint for the binding a message would be sent with. LogoutRequest
// returns it when the IdP does not support single logout. In that case,
// end the local session only.
var ErrNoEndpoint = errors.New("samlsp: the identity provider has no endpoint for the binding")

// ErrNoRequestID is returned by ParseResponse when it is called with
// neither WithRequestID nor AllowUnsolicited, and by ParseLogoutResponse
// when it is called with no request ID.
var ErrNoRequestID = errors.New("samlsp: no request ID to match InResponseTo against")

// AuthnOption customizes an AuthnRequest.
type AuthnOption interface {
	applyAuthn(*authnOptions)
}

type authnOptions struct {
	messageOptions
	responseBinding string
	forceAuthn      bool
	isPassive       bool
	authnContext    *saml.RequestedAuthnContext
}

type authnOptionFunc func(*authnOptions)

func (f authnOptionFunc) applyAuthn(o *authnOptions) { f(o) }

var (
	// ForceAuthn asks the IdP to authenticate the user again, even if the
	// IdP already has a session for them (ForceAuthn="true").
	ForceAuthn AuthnOption = authnOptionFunc(func(o *authnOptions) { o.forceAuthn = true })

	// IsPassive asks the IdP not to interact with the user. If it cannot
	// authenticate the user silently, ParseResponse fails with an error
	// that matches saml.ErrBadStatus with the status NoPassive.
	IsPassive AuthnOption = authnOptionFunc(func(o *authnOptions) { o.isPassive = true })
)

// WithAuthnContext asks the IdP to authenticate the user with one of the
// authentication context classes in classRefs, such as
// "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".
// comparison is "exact", "minimum", "maximum" or "better". If comparison
// is empty, "exact" is used.
//
// ParseResponse does not check the class the IdP actually used. To check it,
// read Assertion.AuthnContextClassRef, or set
// saml.ServiceProvider.ValidateAuthnContextClassRef in Config.Customize.
func WithAuthnContext(comparison string, classRefs ...string) AuthnOption {
	return authnOptionFunc(func(o *authnOptions) {
		if comparison == "" {
			comparison = "exact"
		}
		o.authnContext = &saml.RequestedAuthnContext{
			Comparison:            comparison,
			AuthnContextClassRefs: append([]string(nil), classRefs...),
		}
	})
}

// WithResponseBinding asks the IdP to send its response with binding:
// saml.HTTPPostBinding (the default), saml.HTTPArtifactBinding or
// saml.HTTPPostSimpleSignBinding. ParseResponse accepts all three either way.
func WithResponseBinding(binding string) AuthnOption {
	return authnOptionFunc(func(o *authnOptions) { o.responseBinding = binding })
}

// MessageOption is an option for any message sent through the browser. It
// can be passed to AuthnRequest, LogoutRequest and LogoutResponse.
type MessageOption interface {
	AuthnOption
	LogoutOption
}

type messageOptions struct {
	binding     string
	scriptNonce string
}

type messageOptionFunc func(*messageOptions)

func (f messageOptionFunc) applyAuthn(o *authnOptions)   { f(&o.messageOptions) }
func (f messageOptionFunc) applyLogout(o *logoutOptions) { f(&o.messageOptions) }

// WithBinding sends the message with binding: saml.HTTPRedirectBinding,
// saml.HTTPPostBinding or saml.HTTPPostSimpleSignBinding. The
// HTTP-POST-SimpleSign binding needs a Key that can sign.
//
// By default HTTP-Redirect is used when the identity provider supports it,
// and HTTP-POST otherwise.
func WithBinding(binding string) MessageOption {
	return messageOptionFunc(func(o *messageOptions) { o.binding = binding })
}

// WithScriptNonce sets the nonce attribute of the script that makes a POST
// binding form submit itself. Use it when a Content-Security-Policy set by
// your application allows scripts by nonce. Message.Write's own policy
// allows the script by its hash.
func WithScriptNonce(nonce string) MessageOption {
	return messageOptionFunc(func(o *messageOptions) { o.scriptNonce = nonce })
}

// chooseBinding returns the binding to use and the IdP location for it.
// locate returns the IdP location for a binding, or "".
func chooseBinding(preferred string, locate func(string) string) (string, string, error) {
	if preferred != "" {
		switch preferred {
		case saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding:
		default:
			return "", "", fmt.Errorf("samlsp: unsupported binding %q", preferred)
		}
		if loc := locate(preferred); loc != "" {
			return preferred, loc, nil
		}
		return "", "", fmt.Errorf("%w %s", ErrNoEndpoint, preferred)
	}
	for _, b := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		if loc := locate(b); loc != "" {
			return b, loc, nil
		}
	}
	return "", "", ErrNoEndpoint
}

// AuthnRequest returns a new authentication request to send the user's
// browser to the identity provider with, by calling Message.Write.
//
// relayState comes back with the response. Use it to find the pending
// login, which must hold the returned Message.ID until ParseResponse is called.
// It should be unpredictable and at most 80 bytes long.
func (c *Config) AuthnRequest(relayState string, opts ...AuthnOption) (*Message, error) {
	o := authnOptions{responseBinding: saml.HTTPPostBinding}
	for _, opt := range opts {
		opt.applyAuthn(&o)
	}
	sp, err := c.serviceProvider(context.Background())
	if err != nil {
		return nil, err
	}
	switch o.responseBinding {
	case saml.HTTPPostBinding, saml.HTTPArtifactBinding, saml.HTTPPostSimpleSignBinding:
	default:
		return nil, fmt.Errorf("samlsp: unsupported response binding %q", o.responseBinding)
	}

	binding, location, err := chooseBinding(o.binding, sp.GetSSOBindingLocation)
	if err != nil {
		return nil, err
	}
	if o.forceAuthn {
		t := true
		sp.ForceAuthn = &t
	}
	if o.authnContext != nil {
		sp.RequestedAuthnContext = o.authnContext
	}

	// Build the request unsigned (the binding argument "" makes no
	// signature), so that IsPassive can be set before signing.
	req, err := sp.MakeAuthenticationRequest(location, "", o.responseBinding)
	if err != nil {
		return nil, err
	}
	if o.isPassive {
		t := true
		req.IsPassive = &t
	}

	m := &Message{ID: req.ID, Binding: binding, Destination: location, RelayState: relayState, scriptHash: requestScriptHash}
	switch binding {
	case saml.HTTPRedirectBinding:
		if m.redirectURL, err = req.Redirect(relayState, sp); err != nil {
			return nil, err
		}
	case saml.HTTPPostBinding:
		if sp.SignatureMethod != "" {
			if err := sp.SignAuthnRequest(req); err != nil {
				return nil, err
			}
		}
		m.form = req.PostWithNonce(relayState, o.scriptNonce)
	case saml.HTTPPostSimpleSignBinding:
		if sp.SignatureMethod == "" {
			sp.SignatureMethod = sp.LogoutSignatureMethod
		}
		if sp.SignatureMethod == "" {
			return nil, errors.New("samlsp: the HTTP-POST-SimpleSign binding needs an RSA or ECDSA Key")
		}
		if m.form, err = req.SimpleSignWithNonce(relayState, o.scriptNonce, sp); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ResponseOption customizes ParseResponse.
type ResponseOption interface {
	applyResponse(*responseOptions)
}

type responseOptions struct {
	requestIDs  []string
	unsolicited bool
}

type responseOptionFunc func(*responseOptions)

func (f responseOptionFunc) applyResponse(o *responseOptions) { f(o) }

// WithRequestID accepts a response to the AuthnRequest with this ID (the
// Message.ID returned by AuthnRequest). It can be passed more than once,
// for example when a user has several logins pending in different tabs.
func WithRequestID(id string) ResponseOption {
	return responseOptionFunc(func(o *responseOptions) {
		if id != "" {
			o.requestIDs = append(o.requestIDs, id)
		}
	})
}

// AllowUnsolicited accepts an unsolicited response, sent by the IdP without
// an AuthnRequest (IdP-initiated login). Responses that answer an
// AuthnRequest must still match a WithRequestID.
//
// Unsolicited responses are open to login CSRF: anyone can make a browser
// post a valid response for their own account. Accept them only when needed.
// The RelayState of an unsolicited response is chosen by the IdP or by the
// attacker. Never redirect to it without checking it.
var AllowUnsolicited ResponseOption = responseOptionFunc(func(o *responseOptions) { o.unsolicited = true })

// ParseResponse verifies the identity provider's Response in r, sent to
// the ACS URL, and returns its assertion. Call it from the handler at
// Config.ACSURL.
//
// It accepts the HTTP-POST, HTTP-POST-SimpleSign and HTTP-Artifact
// bindings. For HTTP-Artifact, it resolves the artifact with a request to
// the IdP. That request uses ctx and the HTTP client from ClientContext.
//
// At least one WithRequestID or AllowUnsolicited is required. Otherwise
// ParseResponse returns ErrNoRequestID.
func (c *Config) ParseResponse(ctx context.Context, r *http.Request, opts ...ResponseOption) (*Assertion, error) {
	var o responseOptions
	for _, opt := range opts {
		opt.applyResponse(&o)
	}
	if len(o.requestIDs) == 0 && !o.unsolicited {
		return nil, ErrNoRequestID
	}
	sp, err := c.serviceProvider(ctx)
	if err != nil {
		return nil, err
	}
	sp.AllowIDPInitiated = o.unsolicited

	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	a, err := sp.ParseResponse(r.WithContext(ctx), o.requestIDs)
	if err != nil {
		return nil, err
	}
	return newAssertion(a), nil
}
