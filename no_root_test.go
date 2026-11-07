package saml

import (
	"encoding/base64"
	"net/http"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The no-root checks added after the reports of nil pointer dereferences on
// a body with no root element, for the paths that had no test.
func TestValidateLogoutRequestFormWithoutRootElement(t *testing.T) {
	e := spcovSetup(t)
	_, err := e.sp.ValidateLogoutRequestForm(base64.StdEncoding.EncodeToString([]byte("<!-- nothing -->")))
	assert.Check(t, is.Error(spcovPrivateErr(t, err), "invalid xml: no root"))
}

func TestSimpleSignMessageWithoutRootElement(t *testing.T) {
	e := spcovSetup(t)
	m := simpleSignMsg{param: "SAMLResponse", xml: []byte("<!-- nothing -->"), sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
	req := simpleSignPost(t, e.sp.SloURL.String(), m.values(t))
	req.Method = http.MethodPost
	assert.Check(t, is.Error(spcovPrivateErr(t, e.sp.ValidateLogoutResponseRequest(req)), "invalid xml: no root"))
}
