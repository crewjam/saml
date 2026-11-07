package samlsp

import (
	"bytes"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
)

// Message is a SAML protocol message that is ready to send to the identity
// provider through the user's browser. Depending on Binding, it is either a
// redirect or an HTML form that submits itself.
type Message struct {
	// ID is the ID of the message. For an AuthnRequest, pass it to
	// ParseResponse with WithRequestID, and for a LogoutRequest to
	// ParseLogoutResponse. For a LogoutResponse it is only for logging.
	ID string

	// Binding is the SAML binding that carries the message:
	// saml.HTTPRedirectBinding, saml.HTTPPostBinding,
	// saml.HTTPPostSimpleSignBinding, or saml.SOAPBinding for the answer to
	// a back-channel LogoutRequest.
	Binding string

	// Destination is the IdP endpoint the message is sent to.
	Destination string

	// RelayState is the RelayState that goes with the message.
	RelayState string

	redirectURL  *url.URL
	form         []byte
	scriptHash   string
	soapResponse *saml.LogoutResponse
	write        func(http.ResponseWriter)
}

// RedirectURL returns the URL to redirect the browser to, for a message
// with the HTTP-Redirect binding. For any other binding it returns nil.
func (m *Message) RedirectURL() *url.URL {
	if m.redirectURL == nil {
		return nil
	}
	u := *m.redirectURL
	return &u
}

// Write sends the message to the browser. With the HTTP-Redirect binding,
// it writes a 302 redirect. With the POST bindings, it writes an HTML page
// with a form that submits itself, and a Content-Security-Policy that allows
// only the form's script. With the SOAP binding, which LogoutResponse uses
// to answer a back-channel LogoutRequest, it writes the SOAP response to
// the IdP. Write must be called before anything else is written to w.
func (m *Message) Write(w http.ResponseWriter) {
	if m.write != nil {
		m.write(w)
		return
	}
	if m.soapResponse != nil {
		_ = saml.WriteSOAPLogoutResponse(w, m.soapResponse)
		return
	}
	h := w.Header()
	// saml-bindings-2.0-os §3.4.5.1 and §3.5.5.1.
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Pragma", "no-cache")

	if m.redirectURL != nil {
		h.Set("Location", m.redirectURL.String())
		w.WriteHeader(http.StatusFound)
		return
	}

	h.Set("Content-Security-Policy", "default-src; script-src '"+m.scriptHash+"'; referrer no-referrer;")
	h.Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml">` +
		`<head><title>Continue</title></head><body>`)
	buf.Write(m.form)
	buf.WriteString(`</body></html>`)
	_, _ = w.Write(buf.Bytes()) //nolint:gosec // the form is built by package saml, which escapes its values
}

// ServeHTTP calls Write, so that a Message can be returned as an
// http.Handler.
func (m *Message) ServeHTTP(w http.ResponseWriter, _ *http.Request) { m.Write(w) }

// The SHA-256 hashes of the scripts that make the POST binding forms of
// package saml submit themselves. Requests (AuthnRequest and LogoutRequest,
// with HTTP-POST or HTTP-POST-SimpleSign) share one script, and
// LogoutResponses use the other. TestScriptHashes checks them.
const (
	requestScriptHash  = "sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE="
	responseScriptHash = "sha256-ae3F9sw3MnGNUqmT+7gdyojm/I6ukOUOr9mHRkJJvCU="
)
