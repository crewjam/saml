package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A service provider that the session was never used for cannot end it,
// or have the logout propagated to the SPs it was used for, by naming the
// user's NameID.
func TestSPInitiatedLogoutRefusesNonParticipant(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps[1], pt.sps[2])

	outsider := pt.sps[0]
	logoutRequest, err := outsider.MakeLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com")
	assert.NilError(t, err)
	u, err := outsider.RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)

	w := pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Check(t, !pt.sessions.ended)
	assert.Check(t, is.Len(pt.received[pt.sps[1].MetadataURL.String()], 0))
	assert.Check(t, is.Len(pt.received[pt.sps[2].MetadataURL.String()], 0))

	resp := decodeLogoutResponse(t, w)
	assert.Check(t, is.Equal(StatusRequester, resp.Status.StatusCode.Value))
	assert.Check(t, is.Equal(logoutRequest.ID, resp.InResponseTo))
}

// Without participants recorded for the session, nothing is known, and the
// request is honoured as before.
func TestSPInitiatedLogoutWithoutRecordedParticipants(t *testing.T) {
	pt := newPropagationTest(t)
	sp := pt.sps[0]
	logoutRequest, err := sp.MakeLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com")
	assert.NilError(t, err)
	u, err := sp.RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)

	w := pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Check(t, pt.sessions.ended)
	_, err = sp.ParseLogoutResponse(next(t, w), []string{logoutRequest.ID})
	assert.NilError(t, err)
}

// The same holds for a LogoutRequest sent over SOAP, where no browser, and
// so no session cookie, shows that the user is involved.
func TestIDPServeSLOOverSOAPRefusesNonParticipant(t *testing.T) {
	st := newSOAPLogoutTest(t)
	soapSP := st.addSOAPParticipant(t)
	st.login(t, soapSP.sp)

	resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))))
	checkStatus(t, resp, StatusRequester, "")
	assert.Check(t, !st.sessions.ended)
	assert.Check(t, is.Len(soapSP.requests(), 0))
}
