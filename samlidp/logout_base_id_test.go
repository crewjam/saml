package samlidp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"

	"github.com/crewjam/saml"
)

// Sessions are stored by NameID, so a LogoutRequest whose principal is a
// BaseID ends no session and is answered with StatusResponder.
func TestSLOBaseID(t *testing.T) {
	test := newSLOServerTest(t)
	test.Server.IDP.AcceptLogoutRequestBaseID = true
	session, cookie := test.login(t, "alice", "alice@example.com")

	logoutRequest := test.logoutRequest(t, session.NameID, session.Index)
	logoutRequest.Signature = nil // signed again with a query string signature
	logoutRequest.NameID = nil
	logoutRequest.BaseID = etree.NewElement("saml:BaseID")
	logoutRequest.BaseID.CreateAttr("NameQualifier", "https://idp.example.com")
	u, err := test.SP.RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u.String(), nil)
	r.AddCookie(cookie)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Check(t, test.sessionExists(t, session.ID))

	_, err = test.SP.ParseLogoutResponse(httptest.NewRequest(http.MethodGet, w.Header().Get("Location"), nil), []string{logoutRequest.ID})
	var badStatus saml.ErrBadStatus
	assert.Assert(t, errors.As(err, &badStatus), "%v", err)
	assert.Check(t, badStatus.Status == saml.StatusResponder, badStatus.Status)
}
