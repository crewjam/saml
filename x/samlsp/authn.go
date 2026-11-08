package samlsp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/timelimit"
)

// ErrNoEndpoint is returned when the identity provider's metadata lists no
// endpoint for the binding a message would be sent with.
var ErrNoEndpoint = errors.New("samlsp: the identity provider has no endpoint for the binding")

// ErrNoRequestID is returned by ParseResponse when it is called with
// neither WithRequestID nor AllowUnsolicited.
var ErrNoRequestID = errors.New("samlsp: no request ID to match InResponseTo against")

// ErrAuthnTooOld is returned by ParseResponse, through a
// *saml.InvalidResponseError, for an assertion whose AuthnInstant is older
// than WithMaxAuthnAge allows.
var ErrAuthnTooOld = errors.New("samlsp: the user was authenticated too long ago")

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
	acsIndex        *int
	attributeIndex  *int
}

type authnOptionFunc func(*authnOptions)

func (f authnOptionFunc) applyAuthn(o *authnOptions) { f(o) }

var (
	// ForceAuthn asks the IdP to authenticate the user again, even if the
	// IdP already has a session for them (ForceAuthn="true"). See
	// WithForceAuthn to set it from a setting. An IdP may ignore it; pass
	// ParseResponse WithMaxAuthnAge to refuse an authentication that is
	// not fresh.
	ForceAuthn AuthnOption = authnOptionFunc(func(o *authnOptions) { o.forceAuthn = true })

	// IsPassive asks the IdP not to interact with the user. If it cannot
	// authenticate the user silently, ParseResponse fails with an error
	// that matches saml.ErrBadStatus with the status Responder and the
	// second-level status NoPassive (saml-core §3.2.2.2):
	//
	//	errors.Is(err, saml.ErrBadStatus{Status: saml.StatusResponder, SubStatus: saml.StatusNoPassive})
	IsPassive AuthnOption = authnOptionFunc(func(o *authnOptions) { o.isPassive = true })
)

// WithForceAuthn is ForceAuthn when force is true, and no option
// otherwise, for an application that sets it from configuration.
func WithForceAuthn(force bool) AuthnOption {
	return authnOptionFunc(func(o *authnOptions) { o.forceAuthn = o.forceAuthn || force })
}

// WithAuthnContext asks the IdP to authenticate the user with one of
// classes, compared as comparison says. At least one class is required
// (saml-core §3.3.2.2.1): without one, AuthnRequest and ParseResponse
// return an error.
//
// The IdP may answer with another class: the class is enforced only if the
// same option is passed to ParseResponse too, which then refuses an
// assertion whose AuthnContextClassRef does not satisfy it, with an error
// matching saml.ErrAuthnContextMismatch, even if a ServiceProviderOption
// turned the saml.ServiceProvider's ValidateAuthnContextClassRef off.
// A comparison other than saml.AuthnContextComparisonExact
// needs WithAuthnContextComparator, since the order of the classes is
// up to each deployment; without it, ParseResponse refuses every
// assertion.
func WithAuthnContext(comparison saml.AuthnContextComparison, classes ...saml.AuthnContextClass) AuthnContextOption {
	refs := make([]string, len(classes))
	for i, c := range classes {
		refs[i] = string(c)
	}
	return AuthnContextOption{rac: &saml.RequestedAuthnContext{
		Comparison:            string(comparison),
		AuthnContextClassRefs: refs,
	}}
}

// AuthnContextOption is the option that WithAuthnContext returns. It is an
// AuthnOption, which puts it in the AuthnRequest, and a ResponseOption,
// which checks the assertion against it.
type AuthnContextOption struct {
	rac *saml.RequestedAuthnContext
}

func (a AuthnContextOption) applyAuthn(o *authnOptions)       { o.authnContext = a.rac }
func (a AuthnContextOption) applyResponse(o *responseOptions) { o.authnContext = a.rac }

// checkAuthnContext returns an error if rac, from WithAuthnContext, names
// no class: a RequestedAuthnContext needs at least one (saml-core
// §3.3.2.2.1), and package saml checks an assertion against none.
func checkAuthnContext(rac *saml.RequestedAuthnContext) error {
	if rac != nil && len(rac.AuthnContextClassRefs) == 0 {
		return errors.New("samlsp: WithAuthnContext needs at least one class")
	}
	return nil
}

// WithAuthnRequest calls modify with the AuthnRequest before it is signed
// and sent, to set fields that have no option of their own. Options run in
// the order given, after the other options have shaped the request. An
// error from modify is returned by AuthnRequest.
func WithAuthnRequest(modify func(req *saml.AuthnRequest) error) AuthnOption {
	return WithModify(modify)
}

func modifyRequest(f func(req *saml.AuthnRequest)) AuthnOption {
	return WithAuthnRequest(func(req *saml.AuthnRequest) error { f(req); return nil })
}

// WithSubject names the user the IdP should authenticate, as a hint (for
// example, a login_hint from a "sign in as" form): the AuthnRequest
// carries it as its Subject (saml-core §3.4.1). The IdP must then
// authenticate that user or fail.
func WithSubject(nameID saml.NameID) AuthnOption {
	return modifyRequest(func(req *saml.AuthnRequest) {
		id := nameID
		req.Subject = &saml.Subject{NameID: &id}
	})
}

// WithScoping sets the Scoping of the AuthnRequest (saml-core §3.4.1.2),
// which a proxying IdP uses: the IdPs the SP trusts to authenticate the
// user (IDPList), how many times the request may be proxied (ProxyCount),
// and on whose behalf it is made (RequesterIDs).
func WithScoping(scoping saml.Scoping) AuthnOption {
	return modifyRequest(func(req *saml.AuthnRequest) {
		s := scoping
		req.Scoping = &s
	})
}

// WithIDPList asks a proxying IdP to authenticate the user with one of the
// IdPs whose entity IDs are given. It sets the IDPList of the Scoping.
func WithIDPList(entityIDs ...string) AuthnOption {
	return modifyRequest(func(req *saml.AuthnRequest) {
		if req.Scoping == nil {
			req.Scoping = &saml.Scoping{}
		}
		list := &saml.IDPList{}
		for _, id := range entityIDs {
			list.IDPEntries = append(list.IDPEntries, saml.IDPEntry{ProviderID: id})
		}
		req.Scoping.IDPList = list
	})
}

// WithProviderName sets the ProviderName of the AuthnRequest: a
// human-readable name of the SP, which some IdPs show the user.
func WithProviderName(name string) AuthnOption {
	return modifyRequest(func(req *saml.AuthnRequest) { req.ProviderName = name })
}

// WithAttributeConsumingServiceIndex asks the IdP to send the attributes
// that the SP metadata lists in the AttributeConsumingService with this
// index (see WithRequestedAttributes). AuthnRequest returns an error if
// the SP metadata, as ServeMetadata publishes it, has no such index.
func WithAttributeConsumingServiceIndex(index int) AuthnOption {
	return authnOptionFunc(func(o *authnOptions) { o.attributeIndex = &index })
}

// WithAllowCreate sets the AllowCreate of the NameIDPolicy, which is true
// by default: whether the IdP may create a new identifier for the user
// for this SP (saml-core §3.4.1.1).
func WithAllowCreate(allow bool) AuthnOption {
	return modifyRequest(func(req *saml.AuthnRequest) {
		if req.NameIDPolicy == nil {
			req.NameIDPolicy = &saml.NameIDPolicy{}
		}
		req.NameIDPolicy.AllowCreate = &allow
	})
}

// WithSPNameQualifier asks the IdP to return a NameID in the namespace of
// qualifier rather than of this SP, as when several SPs share one
// affiliation (saml-core §3.4.1.1).
func WithSPNameQualifier(qualifier string) AuthnOption {
	return modifyRequest(func(req *saml.AuthnRequest) {
		if req.NameIDPolicy == nil {
			req.NameIDPolicy = &saml.NameIDPolicy{}
		}
		req.NameIDPolicy.SPNameQualifier = &qualifier
	})
}

// WithACSIndex names the assertion consumer service by its index in the
// SP metadata instead of by URL and binding, as some IdPs require. The
// index chooses the response binding, so WithResponseBinding is ignored.
// AuthnRequest returns an error if the SP metadata, as ServeMetadata
// publishes it, has no such index.
func WithACSIndex(index int) AuthnOption {
	return authnOptionFunc(func(o *authnOptions) { o.acsIndex = &index })
}

// WithResponseBinding asks the IdP to send its response with binding:
// saml.HTTPPostBinding (the default), saml.HTTPArtifactBinding or
// saml.HTTPPostSimpleSignBinding. ParseResponse accepts all three either way.
// The SP metadata must list the ACS with any binding other than
// HTTP-POST, as it lists HTTP-Artifact by default, or AuthnRequest
// returns an error:
// for HTTP-POST-SimpleSign, add it to the saml.ServiceProvider's
// AssertionConsumerServiceBindings with WithServiceProvider.
func WithResponseBinding(binding string) AuthnOption {
	return authnOptionFunc(func(o *authnOptions) { o.responseBinding = binding })
}

// MessageOption is an option for any message sent through the browser: it
// can be passed to AuthnRequest and to Send, and so to the messages of
// packages built on Send, such as x/samlsp/slo.
type MessageOption interface {
	AuthnOption
	applyMessage(*messageOptions)
}

type messageOptions struct {
	binding     string
	custom      Binding
	scriptNonce string
	sp          []ServiceProviderOption
	modify      []func(any) error
	idp         MetadataFunc
}

type messageOptionFunc func(*messageOptions)

func (f messageOptionFunc) applyMessage(o *messageOptions) { f(o) }
func (f messageOptionFunc) applyAuthn(o *authnOptions)     { f(&o.messageOptions) }

// WithBinding sends the message with binding: saml.HTTPRedirectBinding,
// saml.HTTPPostBinding or saml.HTTPPostSimpleSignBinding. The
// HTTP-POST-SimpleSign binding needs a key that can sign (see WithSigningKey).
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
func (c *Config) AuthnRequest(ctx context.Context, relayState string, opts ...AuthnOption) (*Message, error) {
	o := authnOptions{responseBinding: saml.HTTPPostBinding}
	for _, opt := range opts {
		if opt != nil {
			opt.applyAuthn(&o)
		}
	}
	switch o.responseBinding {
	case saml.HTTPPostBinding, saml.HTTPArtifactBinding, saml.HTTPPostSimpleSignBinding:
	default:
		return nil, fmt.Errorf("samlsp: unsupported response binding %q", o.responseBinding)
	}
	if err := checkAuthnContext(o.authnContext); err != nil {
		return nil, err
	}
	ctx = IdentityProviderContext(ctx, o.idp)
	return c.send(ctx, OutgoingMessage{
		Service:    SingleSignOnService,
		Param:      "SAMLRequest",
		RelayState: relayState,
		Sign:       c.signRequests,
		Build: func(sp *saml.ServiceProvider, destination string, modify func(any) error) (*etree.Element, error) {
			if o.forceAuthn {
				t := true
				sp.ForceAuthn = &t
			}
			if o.authnContext != nil {
				sp.RequestedAuthnContext = o.authnContext
			}
			if o.acsIndex != nil {
				// The index must be in the metadata the IdP has, which
				// ServeMetadata publishes, with what WithMetadata adds.
				if !hasACSIndex(c.Metadata(ctx), *o.acsIndex) {
					return nil, fmt.Errorf("samlsp: the SP metadata has no AssertionConsumerService with index %d", *o.acsIndex)
				}
				sp.AcsIndex = o.acsIndex
			} else if acsURL := sp.AcsURL.String(); o.responseBinding != saml.HTTPPostBinding && !hasACS(c.Metadata(ctx), acsURL, o.responseBinding) {
				// An IdP may refuse a request for an ACS, by URL and
				// binding, that the SP metadata does not list
				// (saml-profiles §4.1.4.1). HTTP-POST, the default, is
				// not checked, to spare building the metadata.
				return nil, fmt.Errorf("samlsp: the SP metadata has no AssertionConsumerService at %s with the binding %s; list it in the saml.ServiceProvider's AssertionConsumerServiceBindings", acsURL, o.responseBinding)
			}
			if o.attributeIndex != nil && !hasAttributeConsumingServiceIndex(c.Metadata(ctx), *o.attributeIndex) {
				return nil, fmt.Errorf("samlsp: the SP metadata has no AttributeConsumingService with index %d", *o.attributeIndex)
			}
			// The binding argument "" makes no signature; Send signs.
			req, err := sp.MakeAuthenticationRequest(destination, "", o.responseBinding)
			if err != nil {
				return nil, err
			}
			if o.isPassive {
				t := true
				req.IsPassive = &t
			}
			if o.attributeIndex != nil {
				req.AttributeConsumingServiceIndex = strconv.Itoa(*o.attributeIndex)
			}
			if err := modify(req); err != nil {
				return nil, err
			}
			return req.Element(), nil
		},
	}, o.messageOptions)
}

// ResponseOption customizes ParseResponse.
type ResponseOption interface {
	applyResponse(*responseOptions)
}

type responseOptions struct {
	maxAuthnAge  time.Duration
	requestIDs   []string
	unsolicited  bool
	authnContext *saml.RequestedAuthnContext
	sp           []ServiceProviderOption
	idp          MetadataFunc
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

// WithMaxAuthnAge refuses an assertion whose AuthnStatement says the IdP
// authenticated the user more than maxAge ago (its AuthnInstant), allowing
// the clock skew (see WithClockSkew), with an error matching ErrAuthnTooOld. Use it with
// ForceAuthn, which an IdP may ignore, to require a fresh authentication:
// for example, with maxAge as long as a login may take. Without it, an
// assertion is accepted however long ago the user was authenticated.
func WithMaxAuthnAge(maxAge time.Duration) ResponseOption {
	return responseOptionFunc(func(o *responseOptions) { o.maxAuthnAge = maxAge })
}

// checkAuthnAge returns an error if an AuthnStatement of a is older than
// maxAge, allowing skew, at now, or if a has none.
func checkAuthnAge(a *saml.Assertion, maxAge, skew time.Duration, now time.Time) error {
	if len(a.AuthnStatements) == 0 {
		return fmt.Errorf("%w: the assertion has no AuthnStatement", ErrAuthnTooOld)
	}
	oldest := now.Add(-maxAge - skew)
	for _, s := range a.AuthnStatements {
		if s.AuthnInstant.Before(oldest) {
			return fmt.Errorf("%w: AuthnInstant %s is more than %s before %s", ErrAuthnTooOld,
				s.AuthnInstant.Format(time.RFC3339), maxAge, now.Format(time.RFC3339))
		}
	}
	return nil
}

// ParseResponse verifies the identity provider's Response in r, sent to
// the ACS URL, and returns its assertion. Call it from the handler at
// the ACS URL passed to New.
//
// It accepts the HTTP-POST, HTTP-POST-SimpleSign and HTTP-Artifact
// bindings. For HTTP-Artifact, it resolves the artifact with a request to
// the IdP. That request uses ctx and the HTTP client of WithHTTPClient.
//
// At least one WithRequestID or AllowUnsolicited is required (or
// AllowIDPInitiated set with WithServiceProvider). Otherwise ParseResponse
// returns ErrNoRequestID.
//
// AllowUnsolicited and an AuthnContextOption passed to ParseResponse take
// precedence over the corresponding settings made with WithServiceProvider;
// without them, those settings apply.
func (c *Config) ParseResponse(ctx context.Context, r *http.Request, opts ...ResponseOption) (*Assertion, error) {
	var o responseOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyResponse(&o)
		}
	}
	if err := checkAuthnContext(o.authnContext); err != nil {
		return nil, err
	}
	ctx = IdentityProviderContext(ctx, o.idp)
	sp, err := c.serviceProvider(ctx, o.sp)
	if err != nil {
		return nil, err
	}
	if err := checkIDPSSO(sp.IDPMetadata); err != nil {
		return nil, err
	}
	if o.unsolicited {
		sp.AllowIDPInitiated = true
	}
	if o.authnContext != nil {
		// The option is passed to enforce the class, whatever a
		// ServiceProviderOption set.
		sp.RequestedAuthnContext = o.authnContext
		sp.ValidateAuthnContextClassRef = true
	}
	if len(o.requestIDs) == 0 && !sp.AllowIDPInitiated {
		return nil, ErrNoRequestID
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	// Sign the ArtifactResolve of an HTTP-Artifact response, which package
	// saml does only with SignatureMethod: the IdP must authenticate the
	// SP before it hands over the Response (saml-bindings §3.6.3).
	c.signWithGeneralMethod(sp)
	start := sp.Clock.Now() // the real time if Clock is nil
	a, err := sp.ParseResponse(r.WithContext(ctx), o.requestIDs)
	if err != nil {
		return nil, err
	}
	now := sp.Clock.Now()
	skew := timelimit.SPClockSkew(sp)
	if o.maxAuthnAge > 0 {
		if err := checkAuthnAge(a, o.maxAuthnAge, skew, now); err != nil {
			return nil, &saml.InvalidResponseError{PrivateErr: err, Now: now}
		}
	}
	return newAssertion(a, o.requestIDs, bearerCheck{recipient: sp.AcsURL.String(), skew: skew, start: start, end: now}), nil
}

// hasACS reports whether md, SP metadata, lists an
// AssertionConsumerService at location with binding.
func hasACS(md *saml.EntityDescriptor, location, binding string) bool {
	for _, d := range md.SPSSODescriptors {
		for _, acs := range d.AssertionConsumerServices {
			if acs.Location == location && acs.Binding == binding {
				return true
			}
		}
	}
	return false
}

// hasACSIndex reports whether md has an AssertionConsumerService with index.
func hasACSIndex(md *saml.EntityDescriptor, index int) bool {
	for _, d := range md.SPSSODescriptors {
		for _, acs := range d.AssertionConsumerServices {
			if acs.Index == index {
				return true
			}
		}
	}
	return false
}

// hasAttributeConsumingServiceIndex reports whether md has an
// AttributeConsumingService with index.
func hasAttributeConsumingServiceIndex(md *saml.EntityDescriptor, index int) bool {
	for _, d := range md.SPSSODescriptors {
		for _, svc := range d.AttributeConsumingServices {
			if svc.Index == index {
				return true
			}
		}
	}
	return false
}
