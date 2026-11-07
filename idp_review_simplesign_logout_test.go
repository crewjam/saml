package saml

import (
	"net/http"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A LogoutRequest from the SP with the HTTP-POST-SimpleSign binding, which
// ServiceProvider.MakeSimpleSignLogoutRequest makes and which carries no
// XML signature, is accepted by its SimpleSign signature, and answered with
// HTTP-POST.
func TestIDPServeSLOSimpleSignRequest(t *testing.T) {
	test := newSLOTest(t)
	test.SP.LogoutBindings = []string{HTTPPostSimpleSignBinding, HTTPPostBinding}

	req := test.logoutRequest()
	form, err := req.SimpleSign(sloTestRelayState, &test.SP)
	assert.NilError(t, err)
	w := test.serve(postForm(t, form))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Check(t, is.Len(test.sessions.invalidated, 1))

	r := spRequestForResponse(t, w)
	resp, err := test.SP.ParseLogoutResponse(r, []string{req.ID})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
	assert.Check(t, is.Equal(sloTestRelayState, r.PostForm.Get("RelayState")))
}

func TestIDPServeSLOSimpleSignRequestBadSignature(t *testing.T) {
	test := newSLOTest(t)
	req := test.logoutRequest()
	form, err := req.SimpleSign(sloTestRelayState, &test.SP)
	assert.NilError(t, err)
	action, fields := formFields(t, form)
	// The SimpleSign signature covers the RelayState.
	fields.Set("RelayState", "other")
	w := test.serve(simpleSignPost(t, action, fields))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, is.Len(test.sessions.invalidated, 0))
}

// An SP that answers the IdP's LogoutRequest with a SimpleSign
// LogoutResponse is understood.
func TestIDPPropagatedLogoutAcceptsSimpleSignResponse(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps[1])
	sp := pt.sps[1]
	pt.answer[sp.MetadataURL.String()] = func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) *http.Request {
		resp := sp.makeUnsignedLogoutResponse(pt.idp.LogoutURL.String(), req.ID)
		form, err := resp.SimpleSign("", sp)
		assert.NilError(t, err)
		action, fields := formFields(t, form)
		return simpleSignPost(t, action, fields)
	}

	w := pt.run(t, pt.startLogout(propagationReturnURL))
	assert.Check(t, is.Len(pt.received[sp.MetadataURL.String()], 1))
	assert.Check(t, is.Equal(http.StatusFound, w.Code), w.Body.String())
	assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
}
