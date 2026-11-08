package samlidp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
)

// Message is a SAML protocol message that is ready to send to a service
// provider through the user's browser: for a Response, an HTML form that
// posts it to the SP's assertion consumer service and submits itself.
// Messages of other packages, such as the logout messages of
// x/samlidp/idpslo, may also be redirects or answers to the SP's own HTTP
// request.
type Message struct {
	// ID is the ID of the message.
	ID string

	// InResponseTo is the ID of the request it answers, or "" if it
	// answers none, such as the Response of an IdP-initiated login.
	InResponseTo string

	// Binding is the SAML binding that carries the message: for a
	// Response, saml.HTTPPostBinding or saml.HTTPPostSimpleSignBinding.
	Binding string

	// Destination is the SP endpoint the message is sent to.
	Destination string

	// RelayState is the RelayState that goes with it.
	RelayState string

	// Participant, for a Response that carries an assertion, describes
	// the session it gives the SP: the SP, and the NameID and SessionIndex
	// it was issued, as single logout must name them. Keep it with the
	// user's session to log them out of the SP later (see
	// x/samlidp/idpslo). It is nil for other messages.
	Participant *saml.SessionParticipant

	fields      []formField
	form        []byte
	redirectURL *url.URL
	write       func(http.ResponseWriter)
}

// NewMessage returns a Message whose Write calls write: for example, the
// answer to a request an SP made directly, with the SOAP binding.
func NewMessage(id, binding string, write func(w http.ResponseWriter)) *Message {
	return &Message{ID: id, Binding: binding, write: write}
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

// Write sends the message to the browser. With the POST bindings, it
// writes an HTML page with a form that submits itself, with a
// Content-Security-Policy that allows only the form's script; browsers
// without JavaScript show a button that submits it. With HTTP-Redirect, it
// writes a 302 redirect. Either way it sets headers that keep the message
// from being cached (saml-bindings §3.4.5.1, §3.5.5.1). A Message made
// with NewMessage writes what its function writes. Write must be called
// before anything else is written to w.
func (m *Message) Write(w http.ResponseWriter) {
	if m.write != nil {
		m.write(w)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Pragma", "no-cache")
	if m.redirectURL != nil {
		h.Set("Location", m.redirectURL.String())
		w.WriteHeader(http.StatusFound)
		return
	}
	h.Set("Content-Security-Policy", "default-src; script-src '"+postFormScriptHash+"'; referrer no-referrer;")
	h.Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml">` +
		`<head><title>Continue</title></head><body>`)
	buf.Write(m.form)
	buf.WriteString(`</body></html>`)
	_, _ = w.Write(buf.Bytes()) //nolint:gosec // the form is built with html/template
}

// ServeHTTP calls Write, so that a Message can be returned as an
// http.Handler.
func (m *Message) ServeHTTP(w http.ResponseWriter, _ *http.Request) { m.Write(w) }

// FormValues returns the fields the form posts, for an application that
// renders the form itself: SAMLResponse (or SAMLRequest), RelayState if it
// is not empty, and for HTTP-POST-SimpleSign SigAlg and Signature. It
// returns nil for a message that is not posted.
func (m *Message) FormValues() map[string]string {
	if m.fields == nil {
		return nil
	}
	out := make(map[string]string, len(m.fields))
	for _, f := range m.fields {
		out[f.Name] = f.Value
	}
	return out
}

type formField struct{ Name, Value string }

// postResponse returns the Message that posts the Response of ireq, which
// MakeResponse or MakeErrorResponse has made.
func postResponse(ireq *saml.IdpAuthnRequest, nonce string) (*Message, error) {
	m := &Message{
		ID:           ireq.ResponseEl.SelectAttrValue("ID", ""),
		InResponseTo: ireq.Request.ID,
		Binding:      ireq.ACSEndpoint.Binding,
		Destination:  ireq.ACSEndpoint.Location,
		RelayState:   ireq.RelayState,
	}
	switch m.Binding {
	case saml.HTTPPostSimpleSignBinding:
		form, err := ireq.SimpleSignBinding()
		if err != nil {
			return nil, err
		}
		m.fields = append(m.fields, formField{"SAMLResponse", form.SAMLResponse})
		if form.RelayState != "" {
			m.fields = append(m.fields, formField{"RelayState", form.RelayState})
		}
		m.fields = append(m.fields, formField{"SigAlg", form.SigAlg}, formField{"Signature", form.Signature})
	default:
		form, err := ireq.PostBinding()
		if err != nil {
			return nil, err
		}
		m.fields = append(m.fields, formField{"SAMLResponse", form.SAMLResponse})
		if form.RelayState != "" {
			m.fields = append(m.fields, formField{"RelayState", form.RelayState})
		}
	}
	if err := m.setForm(nonce); err != nil {
		return nil, err
	}
	return m, nil
}

// setForm renders the form that posts m.fields to m.Destination.
func (m *Message) setForm(nonce string) error {
	var buf bytes.Buffer
	err := postFormTemplate.Execute(&buf, struct {
		Action string
		Fields []formField
		Nonce  string
	}{m.Destination, m.fields, nonce})
	if err != nil {
		return err
	}
	m.form = buf.Bytes()
	return nil
}

// postFormScript submits the form of a Message, and hides its button.
const postFormScript = `document.getElementById('SAMLSubmitButton').style.visibility='hidden';` +
	`document.getElementById('SAMLForm').submit();`

// postFormScriptHash is the CSP source of postFormScript.
var postFormScriptHash = func() string {
	sum := sha256.Sum256([]byte(postFormScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}()

var postFormTemplate = template.Must(template.New("form").Parse(`` +
	`<form method="post" action="{{.Action}}" id="SAMLForm">` +
	`{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}" />{{end}}` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script{{with .Nonce}} nonce="{{.}}"{{end}}>` + postFormScript + `</script>`))
