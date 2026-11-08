package samlsp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
)

// Middleware implements middleware than allows a web application
// to support SAML.
//
// It implements http.Handler so that it can provide the metadata and ACS endpoints,
// typically /saml/metadata and /saml/acs, respectively.
//
// It also provides middleware RequireAccount which redirects users to
// the auth process if they do not have session credentials.
//
// When redirecting the user through the SAML auth flow, the middleware assigns
// a temporary cookie with a random name beginning with "saml_". The value of
// the cookie is a signed JSON Web Token containing the original URL requested
// and the SAML request ID. The random part of the name corresponds to the
// RelayState parameter passed through the SAML flow.
//
// When validating the SAML response, the RelayState is used to look up the
// correct cookie, validate that the SAML request ID, and redirect the user
// back to their original URL.
//
// Sessions are established by issuing a JSON Web Token (JWT) as a session
// cookie once the SAML flow has succeeded. The JWT token contains the
// authenticated attributes from the SAML assertion.
//
// When the middleware receives a request with a valid session JWT it extracts
// the SAML attributes and modifies the http.Request object adding a Context
// object to the request context that contains attributes from the initial
// SAML assertion.
//
// When issuing JSON Web Tokens, a signing key is required. Because the
// SAML service provider already has a private key, we borrow that key
// to sign the JWTs as well.
type Middleware struct {
	ServiceProvider  saml.ServiceProvider
	OnError          func(w http.ResponseWriter, r *http.Request, err error)
	Binding          string // saml.HTTPRedirectBinding, saml.HTTPPostBinding or saml.HTTPPostSimpleSignBinding
	ResponseBinding  string // saml.HTTPPostBinding, saml.HTTPArtifactBinding or saml.HTTPPostSimpleSignBinding
	RequestTracker   RequestTracker
	Session          SessionProvider
	AssertionHandler AssertionHandler

	// LogoutRequestTracker tracks the LogoutRequests sent by
	// HandleStartLogout, so that ServeSLO accepts only a LogoutResponse to
	// one of them. It must not share pending requests with RequestTracker.
	// SP initiated single logout fails if it is nil.
	LogoutRequestTracker RequestTracker

	// ScriptNonce, if set, is called when the middleware serves the
	// auto-submitting HTML form of the HTTP-POST binding. A non-empty result
	// is set as the nonce attribute of the form's <script> element, for
	// applications whose own Content-Security-Policy allows scripts by nonce.
	ScriptNonce func(r *http.Request) string

	// FormReplayStore, if set, lets a POST request that starts the auth flow
	// be posted again once the user has logged in. If it is nil, the
	// default, the user is redirected to the URI of the request with a GET
	// request, and the form is lost.
	//
	// The form is saved only if the browser says the request comes from a
	// page on the same origin (by the Sec-Fetch-Site or Origin header), and
	// only if the FormReplayStore accepts it. After login it is posted back
	// by an auto-submitting form, which carries the new session cookie.
	// Enable this only for forms that are safe to submit again, and keep
	// validating them, CSRF tokens included, as usual.
	//
	// Forms are saved under the RelayState returned by the RequestTracker,
	// which must be unique to each auth flow: a RelayStateFunc that returns
	// a fixed value must not be used with FormReplayStore.
	FormReplayStore FormReplayStore

	// LogoutBinding is the binding preferred for sending logout messages to
	// the IDP (LogoutRequests from HandleStartLogout, and LogoutResponses to
	// IDP initiated logout): saml.HTTPRedirectBinding,
	// saml.HTTPPostBinding or saml.HTTPPostSimpleSignBinding. It is used
	// when the IDP metadata has a SingleLogoutService endpoint for it.
	// Otherwise, and when it is empty, HTTP-Redirect is used if the IDP
	// supports it, HTTP-POST otherwise. The HTTP-POST-SimpleSign binding
	// signs messages with ServiceProvider.Key and SignatureMethod, which
	// must be set.
	//
	// saml.SOAPBinding makes HandleStartLogout send its LogoutRequest from
	// the server, signed with ServiceProvider.Key, when the IDP metadata has
	// a SOAP SingleLogoutService endpoint (see HandleStartLogout). The
	// LogoutResponses to IDP initiated logout are then sent with the
	// default front-channel binding.
	LogoutBinding string

	// RequirePOSTToStartLogout makes HandleStartLogout refuse any method
	// but POST with 405 Method Not Allowed. Logging out changes state, and
	// a GET handler lets any other site log the user out with a link or an
	// image (logout CSRF). It is off by default because applications
	// commonly link to their logout URL; when setting it, start logout
	// from a form that POSTs to it.
	RequirePOSTToStartLogout bool
}

// ServeHTTP implements http.Handler and serves the SAML-specific HTTP endpoints
// on the URIs specified by m.ServiceProvider.MetadataURL,
// m.ServiceProvider.AcsURL and m.ServiceProvider.SloURL.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == m.ServiceProvider.MetadataURL.Path {
		m.ServeMetadata(w, r)
		return
	}

	if r.URL.Path == m.ServiceProvider.AcsURL.Path {
		m.ServeACS(w, r)
		return
	}

	if m.ServiceProvider.SloURL.Path != "" && r.URL.Path == m.ServiceProvider.SloURL.Path {
		m.ServeSLO(w, r)
		return
	}

	http.NotFoundHandler().ServeHTTP(w, r)
}

// ServeMetadata handles requests for the SAML metadata endpoint. If
// ServiceProvider.SignMetadata is set, the metadata is signed.
func (m *Middleware) ServeMetadata(w http.ResponseWriter, _ *http.Request) {
	var buf []byte
	if m.ServiceProvider.SignMetadata {
		el, err := m.ServiceProvider.SignedMetadata()
		if err != nil {
			log.Printf("ERROR: failed to sign metadata: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		doc := etree.NewDocument()
		doc.SetRoot(el)
		if buf, err = doc.WriteToBytes(); err != nil {
			log.Printf("ERROR: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		buf, _ = xml.MarshalIndent(m.ServiceProvider.Metadata(), "", "  ")
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if _, err := w.Write(buf); err != nil { //nolint:gosec // buf is our own XML metadata, served as application/samlmetadata+xml
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// ServeACS handles requests for the SAML ACS endpoint.
func (m *Middleware) ServeACS(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		m.OnError(w, r, err)
		return
	}

	possibleRequestIDs := []string{}
	if m.ServiceProvider.AllowIDPInitiated {
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests := m.RequestTracker.GetTrackedRequests(r)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	assertion, err := m.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		m.OnError(w, r, err)
		return
	}

	if handlerErr := m.AssertionHandler.HandleAssertion(assertion); handlerErr != nil {
		m.OnError(w, r, handlerErr)
		return
	}

	m.CreateSessionFromAssertion(w, r, assertion, m.ServiceProvider.DefaultRedirectURI)
}

// errSessionProviderReturnedNil is passed to OnError when a SessionProvider
// returns neither a session nor an error.
var errSessionProviderReturnedNil = errors.New("saml: session provider returned nil session without an error")

// RequireAccount is HTTP middleware that requires that each request be
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middleware redirects the user
// to start the SAML auth flow.
//
// If the SessionProvider returns an error that matches ErrNoSession (as
// determined by errors.Is), the auth flow is started. Any other error, or a nil
// session, is passed to OnError and the wrapped handler is not called, even if
// the SessionProvider also returned a non-nil session.
func (m *Middleware) RequireAccount(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.Session.GetSession(r)
		if errors.Is(err, ErrNoSession) {
			m.HandleStartAuthFlow(w, r)
			return
		}
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		if session == nil {
			m.OnError(w, r, errSessionProviderReturnedNil)
			return
		}

		r = r.WithContext(ContextWithSession(r.Context(), session))
		handler.ServeHTTP(w, r)
	})
}

// HandleStartAuthFlow is called to start the SAML authentication process.
func (m *Middleware) HandleStartAuthFlow(w http.ResponseWriter, r *http.Request) {
	// If we try to redirect when the original request is the ACS URL we'll
	// end up in a loop. This is a programming error, so we panic here. In
	// general this means a 500 to the user, which is preferable to a
	// redirect loop.
	if r.URL.Path == m.ServiceProvider.AcsURL.Path {
		panic("don't wrap Middleware with RequireAccount")
	}

	var binding, bindingLocation string
	if m.Binding != "" {
		binding = m.Binding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
	} else {
		binding = saml.HTTPRedirectBinding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		if bindingLocation == "" {
			binding = saml.HTTPPostBinding
			bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		}
	}

	authReq, err := m.ServiceProvider.MakeAuthenticationRequest(bindingLocation, binding, m.ResponseBinding)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// relayState is limited to 80 bytes but also must be integrity protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a signed cookie that encodes the original URL which we'll check
	// against the SAML response when we get it.
	relayState, err := m.RequestTracker.TrackRequest(w, r, authReq.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if m.FormReplayStore != nil && r.Method == http.MethodPost && isSameOriginRequest(r) {
		if _, err := m.FormReplayStore.SaveForm(r, relayState); err != nil {
			m.OnError(w, r, err)
			return
		}
	}

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := authReq.Redirect(relayState, &m.ServiceProvider)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		setNoCacheHeaders(w.Header())
		w.Header().Add("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)
		return
	}
	if binding == saml.HTTPPostBinding {
		m.writePostForm(w, postRequestScriptHash, authReq.PostWithNonce(relayState, m.scriptNonce(r)))
		return
	}
	if binding == saml.HTTPPostSimpleSignBinding {
		form, err := authReq.SimpleSignWithNonce(relayState, m.scriptNonce(r), &m.ServiceProvider)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The SimpleSign form uses the same auto-submit script as the
		// HTTP-POST AuthnRequest form, so the same hash allows it.
		m.writePostForm(w, postRequestScriptHash, form)
		return
	}
	panic("not reached")
}

// The SHA-256 hashes of the auto-submit scripts of the HTTP-POST binding
// forms, for the Content-Security-Policy of the pages that carry them. The
// form of an AuthnRequest and of a LogoutRequest share the same script, as
// do the HTTP-POST-SimpleSign AuthnRequest and LogoutRequest forms; the
// HTTP-POST and HTTP-POST-SimpleSign LogoutResponse forms share the other.
const (
	postRequestScriptHash  = "sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE="
	postResponseScriptHash = "sha256-ae3F9sw3MnGNUqmT+7gdyojm/I6ukOUOr9mHRkJJvCU="
)

// scriptNonce returns the nonce for the auto-submit script of a form, or ""
// if ScriptNonce is not set.
func (m *Middleware) scriptNonce(r *http.Request) string {
	if m.ScriptNonce == nil {
		return ""
	}
	return m.ScriptNonce(r)
}

// setNoCacheHeaders sets the headers the SAML bindings ask of an HTTP
// response that carries a SAML message, so that neither the browser nor a
// proxy keeps a copy: "Include a Cache-Control header field set to
// "no-cache, no-store". Include a Pragma header field set to "no-cache"."
// (saml-bindings-2.0-os §3.4.5.1 and §3.5.5.1).
func setNoCacheHeaders(h http.Header) {
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Pragma", "no-cache")
}

// writePostForm writes an HTML page holding form, the auto-submitting form of
// the HTTP-POST binding whose script has the hash scriptHash.
func (m *Middleware) writePostForm(w http.ResponseWriter, scriptHash string, form []byte) {
	w.Header().Add("Content-Security-Policy", ""+
		"default-src; "+
		"script-src '"+scriptHash+"'; "+
		"reflected-xss block; referrer no-referrer;")
	w.Header().Add("Content-type", "text/html")
	setNoCacheHeaders(w.Header())
	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html>` +
		`<html xmlns="http://www.w3.org/1999/xhtml">` +
		`<head><title>Continue</title></head>` +
		`<body>`)
	buf.Write(form)
	buf.WriteString(`</body></html>`)
	if _, err := w.Write(buf.Bytes()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// CreateSessionFromAssertion is invoked by ServeHTTP when we have a new, valid SAML assertion.
func (m *Middleware) CreateSessionFromAssertion(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion, redirectURI string) {
	var replay *SavedForm
	if trackedRequestIndex := r.Form.Get("RelayState"); trackedRequestIndex != "" {
		trackedRequest, err := m.RequestTracker.GetTrackedRequest(r, trackedRequestIndex)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) && m.ServiceProvider.AllowIDPInitiated {
				// The RelayState of an unsolicited response comes from the
				// IdP, or from whoever posted the form, so only follow it
				// to a path on this site.
				if uri := r.Form.Get("RelayState"); isLocalRedirect(uri) {
					redirectURI = uri
				}
			} else {
				m.OnError(w, r, err)
				return
			}
		} else {
			if err := m.RequestTracker.StopTrackingRequest(w, r, trackedRequestIndex); err != nil {
				m.OnError(w, r, err)
				return
			}

			// The tracked URI is the URL of the request that started the
			// login, which is whatever request-target the client sent: a
			// path beginning "//" makes it "//evil.example/...", which
			// http.Redirect would send the newly logged-in user off to. So
			// it is followed only to a path on this site, like the
			// RelayState of an IdP-initiated response.
			if isLocalRedirect(trackedRequest.URI) {
				redirectURI = trackedRequest.URI
			}

			if m.FormReplayStore != nil {
				saved, ok, err := m.FormReplayStore.TakeForm(r, trackedRequestIndex)
				if err != nil {
					m.OnError(w, r, err)
					return
				}
				// Replay the form only to the URI of the tracked request,
				// whose cookie this browser holds, and only on this site.
				if ok && saved.URI == trackedRequest.URI && isLocalRedirect(saved.URI) {
					replay = saved
				}
			}
		}
	}

	if err := m.Session.CreateSession(w, r, assertion); err != nil {
		m.OnError(w, r, err)
		return
	}

	if replay != nil {
		form, err := replayForm(replay.URI, replay.Form, m.scriptNonce(r))
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		// The page holds the user's form data.
		w.Header().Set("Cache-Control", "no-store")
		m.writePostForm(w, replayScriptHash, form)
		return
	}

	http.Redirect(w, r, redirectURI, http.StatusFound) //nolint:gosec // redirectURI is a local tracked request URI, a local RelayState path, or the caller's default
}

// isLocalRedirect reports whether uri is an absolute path on this site, and
// so safe to redirect to. It refuses anything a browser could resolve to
// another origin: URLs with a scheme or host, protocol-relative URLs
// ("//evil.example"), backslashes, which browsers treat as slashes
// ("/\\evil.example"), and control characters, which browsers strip
// ("/\t/evil.example").
func isLocalRedirect(uri string) bool {
	if !strings.HasPrefix(uri, "/") {
		return false
	}
	for _, c := range uri {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	if strings.HasPrefix(uri, "//") {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return u.Scheme == "" && u.Host == "" && u.User == nil
}

// RequireAttribute returns a middleware function that requires that the
// SAML attribute `name` be set to `value`. This can be used to require
// that a remote user be a member of a group. It relies on the Claims assigned
// to to the context in RequireAccount.
func RequireAttribute(name, value string) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if session := SessionFromContext(r.Context()); session != nil {
				// this will panic if we have the wrong type of Session, and that is OK.
				sessionWithAttributes := session.(SessionWithAttributes)
				attributes := sessionWithAttributes.GetAttributes()
				if values, ok := attributes[name]; ok {
					for _, v := range values {
						if v == value {
							handler.ServeHTTP(w, r)
							return
						}
					}
				}
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		})
	}
}
