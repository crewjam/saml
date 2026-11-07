package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// partialLogoutStatus is the status of a logout that ended the session it
// was sent with but not every session it names (saml-core-2.0-os §3.7.3.2).
func partialLogoutStatus() Status {
	return Status{StatusCode: StatusCode{
		Value:      StatusSuccess,
		StatusCode: &StatusCode{Value: StatusPartialLogout},
	}}
}

// logoutResponseStatus returns the status of the LogoutResponse in buf.
func logoutResponseStatus(t *testing.T, buf []byte) StatusCode {
	t.Helper()
	var resp LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &resp))
	assert.Check(t, is.Equal("id-req", resp.InResponseTo))
	return resp.Status.StatusCode
}

// checkPartialLogout checks that code is Success with the second-level
// status PartialLogout.
func checkPartialLogout(t *testing.T, code StatusCode) {
	t.Helper()
	assert.Check(t, is.Equal(StatusSuccess, code.Value))
	assert.Assert(t, code.StatusCode != nil)
	assert.Check(t, is.Equal(StatusPartialLogout, code.StatusCode.Value))
}

// checkPlainSuccess checks that code is Success without a second-level
// status.
func checkPlainSuccess(t *testing.T, code StatusCode) {
	t.Helper()
	assert.Check(t, is.Equal(StatusSuccess, code.Value))
	assert.Check(t, is.Nil(code.StatusCode))
}

// The status-taking LogoutResponse builders put the status in the response
// of each binding, signed as the binding requires, so that the signature
// covers it; the existing builders still answer a plain Success.
func TestServiceProviderLogoutResponseWithStatus(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = append(e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices,
		Endpoint{Binding: HTTPPostSimpleSignBinding, Location: "https://idp.example.com/slo/simplesign"})
	verifier := verifierFor(e.sp)

	// redirectStatus checks the query string signature of u and returns
	// the status of its LogoutResponse.
	redirectStatus := func(t *testing.T, u *url.URL) StatusCode {
		t.Helper()
		m, err := parseRedirectBindingQuery(u.RawQuery, "SAMLResponse")
		assert.NilError(t, err)
		assert.NilError(t, verifier.verifyRedirectBindingSignature(m))
		buf, err := base64.StdEncoding.DecodeString(m.Message)
		assert.NilError(t, err)
		return logoutResponseStatus(t, spcovInflate(t, buf))
	}
	// postStatus checks the enveloped XML signature of the LogoutResponse
	// in form and returns the status it covers.
	postStatus := func(t *testing.T, form []byte) StatusCode {
		t.Helper()
		_, v := formFields(t, form)
		buf, err := base64.StdEncoding.DecodeString(v.Get("SAMLResponse"))
		assert.NilError(t, err)
		return signedLogoutResponseStatus(t, verifier, buf)
	}
	// simpleSignStatus checks the SimpleSign signature of form and returns
	// the status of its LogoutResponse.
	simpleSignStatus := func(t *testing.T, form []byte) StatusCode {
		t.Helper()
		action, v := formFields(t, form)
		m, err := parseSimpleSignRequest(simpleSignPost(t, action, v), "SAMLResponse")
		assert.NilError(t, err)
		assert.NilError(t, verifier.verifySimpleSignSignature(m))
		return logoutResponseStatus(t, m.XML)
	}

	t.Run("MakeLogoutResponseWithStatus", func(t *testing.T) {
		resp, err := e.sp.MakeLogoutResponseWithStatus("https://idp.example.com/slo/post", "id-req", partialLogoutStatus())
		assert.NilError(t, err)
		assert.Assert(t, resp.Signature != nil)
		doc := etree.NewDocument()
		doc.SetRoot(resp.Element())
		buf, err := doc.WriteToBytes()
		assert.NilError(t, err)
		checkPartialLogout(t, signedLogoutResponseStatus(t, verifier, buf))

		// Changing the status breaks the signature.
		tampered := doc.Root().FindElement("./Status/StatusCode/StatusCode")
		assert.Assert(t, tampered != nil)
		tampered.CreateAttr("Value", StatusRequestDenied)
		_, err = verifier.verifySignedElement(doc.Root(), verifier.getIDPSigningCerts)
		assert.Check(t, err != nil)

		resp, err = e.sp.MakeLogoutResponse("https://idp.example.com/slo/post", "id-req")
		assert.NilError(t, err)
		checkPlainSuccess(t, resp.Status.StatusCode)
	})
	t.Run("HTTP-Redirect", func(t *testing.T) {
		u, err := e.sp.MakeRedirectLogoutResponseWithStatus("id-req", "relay", partialLogoutStatus())
		assert.NilError(t, err)
		checkPartialLogout(t, redirectStatus(t, u))

		u, err = e.sp.MakeRedirectLogoutResponse("id-req", "relay")
		assert.NilError(t, err)
		checkPlainSuccess(t, redirectStatus(t, u))
	})
	t.Run("HTTP-POST", func(t *testing.T) {
		form, err := e.sp.MakePostLogoutResponseWithStatus("id-req", "relay", partialLogoutStatus())
		assert.NilError(t, err)
		checkPartialLogout(t, postStatus(t, form))

		form, err = e.sp.MakePostLogoutResponse("id-req", "relay")
		assert.NilError(t, err)
		checkPlainSuccess(t, postStatus(t, form))
	})
	t.Run("HTTP-POST-SimpleSign", func(t *testing.T) {
		form, err := e.sp.MakeSimpleSignLogoutResponseWithStatus("id-req", "relay", partialLogoutStatus())
		assert.NilError(t, err)
		checkPartialLogout(t, simpleSignStatus(t, form))

		form, err = e.sp.MakeSimpleSignLogoutResponse("id-req", "relay")
		assert.NilError(t, err)
		checkPlainSuccess(t, simpleSignStatus(t, form))
	})
}

// signedLogoutResponseStatus checks the enveloped XML signature of the
// LogoutResponse in buf with verifier and returns the status it covers.
func signedLogoutResponseStatus(t *testing.T, verifier *ServiceProvider, buf []byte) StatusCode {
	t.Helper()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	signed, err := verifier.verifySignedElement(doc.Root(), verifier.getIDPSigningCerts)
	assert.NilError(t, err)
	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signed)
	signedBuf, err := signedDoc.WriteToBytes()
	assert.NilError(t, err)
	return logoutResponseStatus(t, signedBuf)
}

// The IdP accepts a LogoutResponse with Success and the second-level status
// PartialLogout, made by the status-taking builders, from a participant it
// propagates logout to. It counts it as a participant that logged out, as
// it checks only the top-level status: the participant's session with the
// browser has ended.
func TestIDPAcceptsPartialLogoutFromParticipant(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps...)
	answer := func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) *http.Request {
		t.Helper()
		if sp.LogoutBindings[0] == HTTPRedirectBinding {
			u, err := sp.MakeRedirectLogoutResponseWithStatus(req.ID, "", partialLogoutStatus())
			assert.NilError(t, err)
			return httptest.NewRequest(http.MethodGet, u.String(), nil)
		}
		form, err := sp.MakePostLogoutResponseWithStatus(req.ID, "", partialLogoutStatus())
		assert.NilError(t, err)
		action, v := formFields(t, form)
		return simpleSignPost(t, action, v)
	}
	// sp1 answers with HTTP-Redirect, sp2 with HTTP-POST.
	pt.answer[pt.sps[0].MetadataURL.String()] = answer
	pt.answer[pt.sps[1].MetadataURL.String()] = answer

	initiator := pt.sps[2]
	logoutRequest, err := initiator.MakeLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com", WithSessionIndex("idp-session-index"))
	assert.NilError(t, err)
	u, err := initiator.RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)

	w := pt.run(t, pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil)))
	assert.Check(t, pt.sessions.ended)
	assert.Check(t, is.Len(pt.received[pt.sps[0].MetadataURL.String()], 1))
	assert.Check(t, is.Len(pt.received[pt.sps[1].MetadataURL.String()], 1))

	r := next(t, w)
	assert.Check(t, is.Equal(initiator.SloURL.Host, r.URL.Host))
	resp, err := initiator.ParseLogoutResponse(r, []string{logoutRequest.ID})
	assert.NilError(t, err)
	checkPlainSuccess(t, resp.Status.StatusCode)
}
