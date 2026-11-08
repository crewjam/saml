package samlidp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"

	"github.com/crewjam/saml"
)

// Message is a SAML Response that is ready to send to a service provider
// through the user's browser: an HTML form that posts it to the SP's
// assertion consumer service and submits itself.
type Message struct {
	// ID is the ID of the Response.
	ID string

	// InResponseTo is the ID of the AuthnRequest it answers, or "" for an
	// IdP-initiated login.
	InResponseTo string

	// Binding is the SAML binding that carries the message:
	// saml.HTTPPostBinding or saml.HTTPPostSimpleSignBinding.
	Binding string

	// Destination is the assertion consumer service it is posted to.
	Destination string

	// RelayState is the RelayState that goes with it.
	RelayState string

	fields []formField
	form   []byte
}

// Write sends the message to the browser: an HTML page with a form that
// submits itself, with a Content-Security-Policy that allows only the
// form's script, and headers that keep it from being cached
// (saml-bindings §3.5.5.1). Browsers without JavaScript show a button that
// submits it. Write must be called before anything else is written to w.
func (m *Message) Write(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Pragma", "no-cache")
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
// renders the form itself: SAMLResponse, RelayState if it is not empty,
// and for HTTP-POST-SimpleSign SigAlg and Signature.
func (m *Message) FormValues() map[string]string {
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
	var buf bytes.Buffer
	err := postFormTemplate.Execute(&buf, struct {
		Action string
		Fields []formField
		Nonce  string
	}{m.Destination, m.fields, nonce})
	if err != nil {
		return nil, err
	}
	m.form = buf.Bytes()
	return m, nil
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
