package saml

import (
	"html/template"
	"net/http"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The forms and page of logout propagation can be replaced, for example to
// serve them under a strict Content-Security-Policy without inline scripts.
func TestIDPLogoutTemplates(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.LogoutRequestFormTemplate = template.Must(template.New("").Parse(
		`<form method="post" action="{{.URL}}"><input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" /><button>Continue logging out</button></form>`))
	pt.idp.LogoutCompleteTemplate = template.Must(template.New("").Parse(
		`<p>custom: bye</p>{{range .Failed}}<p>failed {{.}}</p>{{end}}`))
	postOnly := pt.sps[1] // HTTP-POST SingleLogoutService only
	pt.login(t, postOnly)

	w := pt.startLogout("")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Check(t, is.Contains(w.Body.String(), "Continue logging out"))
	assert.Check(t, !strings.Contains(w.Body.String(), "<script"))

	w = pt.run(t, w)
	assert.Check(t, is.Len(pt.received[postOnly.MetadataURL.String()], 1))
	assert.Check(t, is.Contains(w.Body.String(), "custom: bye"))
}
