package samlidp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/timelimit"
)

// bearerMethod is the bearer SubjectConfirmation method, the only one the
// assertions of this package carry (saml-profiles §4.1.4.2).
const bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // a URI, not a credential

// AuthnRequest is a verified authentication request from a service
// provider: what the IdP must answer with Response or ErrorResponse, once
// it has authenticated the user (or decided not to).
//
// It is plain data, so that the application can keep it while the user
// logs in, such as in a server-side session or with encoding/json. Keep it
// where the user cannot change it: its fields are trusted when the
// Response is made. It holds what bears on the answer, not the whole
// request: the request's Conditions, for example, are not kept. Response checks again that the SP is known and that
// ACSURL is one of its assertion consumer services, so a changed
// AuthnRequest cannot send an assertion anywhere else.
type AuthnRequest struct {
	// ID is the ID of the request, which the Response answers
	// (InResponseTo). It is empty for an IdP-initiated login (see
	// IDPInitiated).
	ID string

	// ServiceProvider is the entity ID of the SP that sent the request.
	ServiceProvider string

	// IssueInstant is when the SP made the request. It is zero for an
	// IdP-initiated login.
	IssueInstant time.Time

	// RelayState is sent back to the SP with the Response.
	RelayState string

	// ACSURL is the assertion consumer service of the SP that the
	// Response is sent to, and ACSBinding its binding:
	// saml.HTTPPostBinding or saml.HTTPPostSimpleSignBinding.
	ACSURL     string
	ACSBinding string

	// ProviderName is a human-readable name of the SP that it sent with
	// the request, if any.
	ProviderName string

	// Consent, if not empty, is the SP's claim of the user's consent to
	// the request: a URI such as "urn:oasis:names:tc:SAML:2.0:consent:obtained"
	// (saml-core §3.2.1, §8.4).
	Consent string

	// AttributeConsumingServiceIndex, if not empty, is the index of the
	// AttributeConsumingService of the SP's metadata that lists the
	// attributes it asks for (saml-core §3.4.1). Which attributes to send
	// is the application's to decide.
	AttributeConsumingServiceIndex string

	// Scoping, if not nil, is the Scoping of the request (saml-core
	// §3.4.1.2): the IdPs the SP trusts (IDPList), the SPs on whose
	// behalf it asks (RequesterIDs), and how many times the request may
	// be proxied to another IdP (ProxyCount). An IdP that proxies requests
	// must honour it; one that does not may ignore it.
	Scoping *saml.Scoping

	// ForceAuthn asks the IdP to authenticate the user again, even if it
	// has a session for them (saml-core §3.4.1). The Subject's
	// AuthnInstant must then be that of the new authentication: Response
	// refuses one before IssueInstant.
	ForceAuthn bool

	// IsPassive asks the IdP not to interact with the user. If it cannot
	// authenticate the user without doing so, answer with ErrorResponse
	// and StatusNoPassive.
	IsPassive bool

	// NameIDFormat is the format of the NameID the SP asked for, if any
	// (the Format of its NameIDPolicy). Response refuses a Subject whose
	// NameIDFormat differs, unless this is unspecified or
	// "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted". For the
	// latter, Response issues the NameID as an EncryptedID (saml-core
	// §8.3.9), and refuses it, with StatusInvalidNameIDPolicy, if the SP
	// publishes no encryption key.
	NameIDFormat saml.NameIDFormat

	// SPNameQualifier is the SPNameQualifier of the NameIDPolicy, if any:
	// the namespace that the SP asked the NameID to be in, which, if not
	// the SP's own entity ID, must name an affiliation the SP is a member
	// of (saml-core §3.4.1.1). ParseAuthnRequest and Response refuse one
	// that WithAffiliation does not allow, with StatusInvalidNameIDPolicy.
	// Response puts it in the NameID, whose value must then be the user's
	// identifier in the affiliation.
	SPNameQualifier string

	// AllowCreate is the AllowCreate of the NameIDPolicy: whether the IdP
	// may create a new identifier for the user for this SP (saml-core
	// §3.4.1.1). If it is false and the user has no identifier for the SP
	// (or its affiliation) yet, such as no persistent NameID, do not make
	// one: answer with ErrorResponse and StatusInvalidNameIDPolicy.
	AllowCreate bool

	// AuthnContextClasses are the authentication context classes the SP
	// asked the user to be authenticated with, compared as
	// AuthnContextComparison says ("exact" if empty). Response refuses a
	// Subject whose AuthnContextClassRef does not satisfy them, with
	// StatusNoAuthnContext.
	AuthnContextComparison saml.AuthnContextComparison
	AuthnContextClasses    []saml.AuthnContextClass

	// Subject, if not nil, names the user the SP asked the IdP to
	// authenticate. Response refuses a Subject whose NameID does not
	// match it, with StatusUnknownPrincipal.
	Subject *saml.NameID

	// Extensions are the extension elements of the request's
	// samlp:Extensions, if any (saml-core §3.2.1), each as an XML
	// document that declares the namespaces it uses. What they mean, and
	// whether to honour them, is the application's to decide.
	Extensions [][]byte
}

// ParseOption customizes ParseAuthnRequest and IDPInitiated.
type ParseOption interface {
	applyParse(*parseOptions)
}

type parseOptions struct {
	idp    []IdentityProviderOption
	custom Binding
}

// ParseAuthnRequest verifies the AuthnRequest in r, received at the SSO
// URL, and returns it. Call it from the handler at that URL. It accepts the
// HTTP-Redirect (GET), HTTP-POST and HTTP-POST-SimpleSign (POST) bindings.
//
// It checks the request as package saml does: it must be current, be
// addressed to the SSO URL if it is signed or has a Destination, come from
// an SP that the ServiceProviderFunc knows, carry a valid signature by
// that SP if it is signed (and must be, if the SP's metadata says it signs
// its requests, or with RequireSignedAuthnRequests), and name an assertion
// consumer service in the SP's metadata that a Response can be posted to.
// A signed request is accepted only once (see WithReplayState).
//
// Some invalid requests must be answered with a SAML error Response
// rather than an HTTP error: an expired request, one that is not SAML 2.0,
// one that names an assertion consumer service that the IdP cannot post a
// Response to, or one whose Subject the IdP cannot satisfy. For those,
// ParseAuthnRequest returns both the AuthnRequest, addressed to the SP's
// default assertion consumer service if need be, and an error that matches
// *saml.StatusError; send it with ErrorResponse:
//
//	req, err := config.ParseAuthnRequest(ctx, r)
//	var status *saml.StatusError
//	if errors.As(err, &status) && req != nil {
//		msg, err := config.ErrorResponse(ctx, req, status)
//		...
//		msg.Write(w)
//		return
//	}
//	if err != nil {
//		http.Error(w, "bad request", http.StatusBadRequest)
//		return
//	}
//
// Other errors come from package saml unchanged, and match the saml.Err*
// values, such as saml.ErrUnknownServiceProvider, saml.ErrExpired and
// saml.ErrInvalidSignature.
func (c *Config) ParseAuthnRequest(ctx context.Context, r *http.Request, opts ...ParseOption) (*AuthnRequest, error) {
	var o parseOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyParse(&o)
		}
	}
	idp := c.identityProvider(o.idp)

	// ServeSSO does everything that comes before asking for a session:
	// parsing, validation and choosing the ACS. Drive it with a
	// SessionProvider, ResponseWriter and OnError that record what it
	// reaches.
	var captured ssoCapture
	idp.SessionProvider = &captured
	idp.ResponseWriter = &captured
	idp.OnError = func(_ http.ResponseWriter, _ *http.Request, _ int, err error) { captured.err = err }
	idp.ReplayCache = nil
	r = r.WithContext(ctx)
	// Parse the form here, so that it is kept for the second look below.
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("samlidp: cannot parse the request: %w: %w", saml.ErrMalformedMessage, err)
		}
	}
	idp.ServeSSO(discardResponseWriter{}, r)

	switch {
	case captured.err != nil:
		return nil, captured.err
	case captured.errorResponse != nil:
		// Validation failed in a way that is answered with a SAML error
		// Response, which ServeSSO made, and does not say why: validate
		// again for the cause, so that the error matches it too.
		var cause error
		if again, err := saml.NewIdpAuthnRequest(idp, r); err == nil {
			cause = again.Validate()
		}
		status := responseStatus(captured.errorResponse.ResponseEl)
		if cause == nil {
			return newAuthnRequest(captured.errorResponse), status
		}
		return newAuthnRequest(captured.errorResponse), fmt.Errorf("%w: %w", cause, status)
	case captured.request == nil:
		return nil, errors.New("samlidp: the request was not handled")
	}

	ireq := captured.request
	req := newAuthnRequest(ireq)

	// Package saml matches an ACS named by URL on its location, and prefers
	// HTTP-POST there. If the request asks for the custom binding, and the
	// SP lists an ACS with that binding at that location, use it.
	if o.custom != nil && ireq.Request.ProtocolBinding == o.custom.URI() && ireq.Request.AssertionConsumerServiceIndex == "" &&
		ireq.ACSEndpoint.Binding != o.custom.URI() {
		if _, ep := findACS(ireq.ServiceProviderMetadata, ireq.ACSEndpoint.Location, o.custom.URI()); ep != nil {
			req.ACSURL, req.ACSBinding = ep.Location, ep.Binding
		}
	}

	// With a custom ResponseWriter, ServeSSO lets through an ACS of any
	// binding; this package only posts, or uses the custom binding.
	if !o.sendable(req.ACSBinding) {
		def, err := c.defaultACS(ctx, idp, req.ServiceProvider)
		if err != nil {
			return nil, fmt.Errorf("samlidp: cannot send a response to an assertion consumer service with binding %q: %w", ireq.ACSEndpoint.Binding, err)
		}
		req.ACSURL, req.ACSBinding = def.Location, def.Binding
		return req, &saml.StatusError{
			TopLevel:    saml.StatusRequester,
			SecondLevel: saml.StatusUnsupportedBinding,
			Message:     "the requested assertion consumer service binding is not supported",
		}
	}
	if statusErr := requestSubjectError(ireq.Request.Subject); statusErr != nil {
		return req, statusErr
	}
	if err := c.spNameQualifierError(ctx, idp, req); err != nil {
		var status *saml.StatusError
		if errors.As(err, &status) {
			return req, err
		}
		return nil, err
	}

	if ireq.RequestSigned {
		key := ReplayKey(req.ServiceProvider, req.ID)
		if err := c.replayState.Consume(ctx, key, req.IssueInstant.Add(timelimit.IDPIssueDelay(idp))); err != nil {
			return nil, fmt.Errorf("samlidp: authn request %q: %w", req.ID, err)
		}
	}
	return req, nil
}

// IDPInitiated returns an AuthnRequest for an IdP-initiated login to the
// service provider serviceProvider, to answer with Response once the user
// has been authenticated. Its Response is unsolicited, and goes to the
// SP's default assertion consumer service among those that a Response can
// be posted to. relayState is sent with it: many SPs take it as the URL to
// go to after login.
//
// The error matches ErrUnknownServiceProvider if the ServiceProviderFunc
// does not know serviceProvider, saml.ErrUnknownAssertionConsumerService if
// the SP has no assertion consumer service to post to, and
// saml.ErrRelayStateTooLong if relayState is longer than 80 bytes.
func (c *Config) IDPInitiated(ctx context.Context, serviceProvider, relayState string, opts ...ParseOption) (*AuthnRequest, error) {
	var o parseOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyParse(&o)
		}
	}
	idp := c.identityProvider(o.idp)
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ssoURL.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	ireq, err := idp.NewIdpInitiatedRequest(r, serviceProvider, relayState)
	if err != nil {
		return nil, err
	}
	return newAuthnRequest(ireq), nil
}

// defaultACS returns the default assertion consumer service of the SP
// that a Response can be posted to.
func (c *Config) defaultACS(ctx context.Context, idp *saml.IdentityProvider, serviceProvider string) (*saml.IndexedEndpoint, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ssoURL.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	ireq, err := idp.NewIdpInitiatedRequest(r, serviceProvider, "")
	if err != nil {
		return nil, err
	}
	return ireq.ACSEndpoint, nil
}

// newAuthnRequest returns the AuthnRequest that ireq, a validated
// request, describes.
func newAuthnRequest(ireq *saml.IdpAuthnRequest) *AuthnRequest {
	q := &ireq.Request
	req := &AuthnRequest{
		ID:           q.ID,
		IssueInstant: q.IssueInstant,
		RelayState:   ireq.RelayState,
		ACSURL:       ireq.ACSEndpoint.Location,
		ACSBinding:   ireq.ACSEndpoint.Binding,
		ProviderName: q.ProviderName,
		Consent:      q.Consent,
		ForceAuthn:   q.ForceAuthn != nil && *q.ForceAuthn,
		IsPassive:    q.IsPassive != nil && *q.IsPassive,

		AttributeConsumingServiceIndex: q.AttributeConsumingServiceIndex,
		Scoping:                        q.Scoping,
	}
	if ireq.ServiceProviderMetadata != nil {
		req.ServiceProvider = ireq.ServiceProviderMetadata.EntityID
	}
	if p := q.NameIDPolicy; p != nil {
		if p.Format != nil {
			req.NameIDFormat = saml.NameIDFormat(*p.Format)
		}
		if p.SPNameQualifier != nil {
			req.SPNameQualifier = *p.SPNameQualifier
		}
		req.AllowCreate = p.AllowCreate != nil && *p.AllowCreate
	}
	if rac := q.RequestedAuthnContext; rac != nil {
		req.AuthnContextComparison = saml.AuthnContextComparison(rac.Comparison)
		for _, ref := range rac.AuthnContextClassRefs {
			req.AuthnContextClasses = append(req.AuthnContextClasses, saml.AuthnContextClass(ref))
		}
	}
	if q.Subject != nil && q.Subject.NameID != nil {
		nameID := *q.Subject.NameID
		req.Subject = &nameID
	}
	if q.Extensions != nil {
		for _, el := range q.Extensions.ChildElements() {
			if buf, err := standaloneXML(el); err == nil {
				req.Extensions = append(req.Extensions, buf)
			}
		}
	}
	return req
}

// protocolNamespace is the namespace of the SAML protocol elements.
const protocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"

// standaloneXML returns el as an XML document of its own, which declares
// the namespaces el and its descendants use but its ancestors declare.
func standaloneXML(el *etree.Element) ([]byte, error) {
	missing := map[string]string{}
	collectNamespaces(el, map[string]bool{"xml": true}, missing)
	out := el.Copy()
	for prefix, uri := range missing {
		if prefix == "" {
			out.CreateAttr("xmlns", uri)
		} else {
			out.CreateAttr("xmlns:"+prefix, uri)
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(out)
	return doc.WriteToBytes()
}

// collectNamespaces adds to missing the prefixes, with their namespaces,
// that el and its descendants use but that are not in scope, the prefixes
// declared by the elements from the one being written down to el's parent.
func collectNamespaces(el *etree.Element, scope map[string]bool, missing map[string]string) {
	local := scope
	for _, attr := range el.Attr {
		prefix := attr.Key
		switch {
		case attr.Space == "xmlns":
		case attr.Space == "" && attr.Key == "xmlns":
			prefix = ""
		default:
			continue
		}
		if local[prefix] {
			continue
		}
		if len(local) == len(scope) {
			local = maps.Clone(scope)
		}
		local[prefix] = true
	}
	use := func(prefix, uri string) {
		if _, ok := missing[prefix]; !ok && !local[prefix] && uri != "" {
			missing[prefix] = uri
		}
	}
	use(el.Space, el.NamespaceURI())
	for i := range el.Attr {
		attr := &el.Attr[i]
		if attr.Space != "" && attr.Space != "xmlns" {
			use(attr.Space, attr.NamespaceURI())
		}
	}
	for _, child := range el.ChildElements() {
		collectNamespaces(child, local, missing)
	}
}

// extensionsElement returns the samlp:Extensions element that holds
// extensions, each an XML document, or nil if there are none.
func extensionsElement(extensions [][]byte) (*etree.Element, error) {
	if len(extensions) == 0 {
		return nil, nil
	}
	el := etree.NewElement("samlp:Extensions")
	el.CreateAttr("xmlns:samlp", protocolNamespace)
	for i, buf := range extensions {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(buf); err != nil {
			return nil, fmt.Errorf("samlidp: AuthnRequest.Extensions[%d]: %w", i, err)
		}
		if doc.Root() == nil {
			return nil, fmt.Errorf("samlidp: AuthnRequest.Extensions[%d] has no element", i)
		}
		el.AddChild(doc.Root())
	}
	return el, nil
}

// samlRequest returns the saml.AuthnRequest that req describes, as package
// saml needs it to make the Response.
func (req *AuthnRequest) samlRequest() (saml.AuthnRequest, error) {
	extensions, err := extensionsElement(req.Extensions)
	if err != nil {
		return saml.AuthnRequest{}, err
	}
	q := saml.AuthnRequest{
		Extensions:                  extensions,
		ID:                          req.ID,
		Version:                     "2.0",
		IssueInstant:                req.IssueInstant,
		Issuer:                      &saml.Issuer{Value: req.ServiceProvider},
		AssertionConsumerServiceURL: req.ACSURL,
		ProtocolBinding:             req.ACSBinding,
		ProviderName:                req.ProviderName,
		Consent:                     req.Consent,
		Scoping:                     req.Scoping,

		AttributeConsumingServiceIndex: req.AttributeConsumingServiceIndex,
	}
	if req.ForceAuthn {
		q.ForceAuthn = &req.ForceAuthn
	}
	if req.IsPassive {
		q.IsPassive = &req.IsPassive
	}
	if req.NameIDFormat != "" || req.SPNameQualifier != "" || req.AllowCreate {
		p := &saml.NameIDPolicy{}
		if req.NameIDFormat != "" {
			f := string(req.NameIDFormat)
			p.Format = &f
		}
		if req.SPNameQualifier != "" {
			s := req.SPNameQualifier
			p.SPNameQualifier = &s
		}
		allow := req.AllowCreate
		p.AllowCreate = &allow
		q.NameIDPolicy = p
	}
	if len(req.AuthnContextClasses) > 0 {
		refs := make([]string, len(req.AuthnContextClasses))
		for i, c := range req.AuthnContextClasses {
			refs[i] = string(c)
		}
		q.RequestedAuthnContext = &saml.RequestedAuthnContext{
			Comparison:            string(req.AuthnContextComparison),
			AuthnContextClassRefs: refs,
		}
	}
	if req.Subject != nil {
		nameID := *req.Subject
		q.Subject = &saml.Subject{NameID: &nameID}
	}
	return q, nil
}

// requestSubjectError returns the error status for a request whose
// Subject no assertion of this package can match (saml-core §3.4.1.4), or
// nil. The NameID itself is matched by Response.
func requestSubjectError(subject *saml.Subject) *saml.StatusError {
	if subject == nil {
		return nil
	}
	switch {
	case subject.BaseID != nil || subject.EncryptedID != nil:
		return &saml.StatusError{
			TopLevel:    saml.StatusResponder,
			SecondLevel: saml.StatusUnknownPrincipal,
			Message:     "the request subject identifier is not supported",
		}
	case subject.NameID == nil:
		return &saml.StatusError{
			TopLevel:    saml.StatusRequester,
			SecondLevel: saml.StatusUnknownPrincipal,
			Message:     "the request subject has no identifier",
		}
	}
	if len(subject.SubjectConfirmations) == 0 {
		return nil
	}
	for _, sc := range subject.SubjectConfirmations {
		if sc.Method == bearerMethod {
			return nil
		}
	}
	return &saml.StatusError{
		TopLevel:    saml.StatusResponder,
		SecondLevel: saml.StatusRequestUnsupported,
		Message:     "the requested subject confirmation method is not supported",
	}
}

// sendable reports whether a Response can be sent to an assertion consumer
// service with binding, without a custom Binding.
func sendable(binding string) bool {
	return binding == saml.HTTPPostBinding || binding == saml.HTTPPostSimpleSignBinding
}

// sendable reports whether a Response can be sent to an assertion consumer
// service with binding, with the custom Binding of o, if any.
func (o *parseOptions) sendable(binding string) bool {
	return sendable(binding) || (o.custom != nil && binding == o.custom.URI())
}

// responseStatus returns the status of the error Response el.
func responseStatus(el *etree.Element) *saml.StatusError {
	statusErr := &saml.StatusError{TopLevel: saml.StatusResponder}
	if el == nil {
		return statusErr
	}
	status := el.FindElement("./Status")
	if status == nil {
		return statusErr
	}
	if code := status.FindElement("./StatusCode"); code != nil {
		statusErr.TopLevel = code.SelectAttrValue("Value", saml.StatusResponder)
		if second := code.FindElement("./StatusCode"); second != nil {
			statusErr.SecondLevel = second.SelectAttrValue("Value", "")
		}
	}
	if msg := status.FindElement("./StatusMessage"); msg != nil {
		statusErr.Message = msg.Text()
	}
	return statusErr
}

// ssoCapture records how far IdentityProvider.ServeSSO got with a
// request: the validated request it asks a session for, the request it
// answers with an error Response, or the error it reports.
type ssoCapture struct {
	request       *saml.IdpAuthnRequest
	errorResponse *saml.IdpAuthnRequest
	err           error
}

// GetSession implements saml.SessionProvider. ServeSSO calls it once the
// request has been validated; returning nil ends ServeSSO there.
func (c *ssoCapture) GetSession(_ http.ResponseWriter, _ *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	c.request = req
	return nil
}

// WriteResponse implements saml.ResponseWriter. ServeSSO calls it, before
// GetSession, only to send an error Response.
func (c *ssoCapture) WriteResponse(_ http.ResponseWriter, req *saml.IdpAuthnRequest) error {
	c.errorResponse = req
	return nil
}

// discardResponseWriter is the http.ResponseWriter of a ServeSSO that
// writes nothing.
type discardResponseWriter struct{}

func (discardResponseWriter) Header() http.Header         { return http.Header{} }
func (discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (discardResponseWriter) WriteHeader(int)             {}
