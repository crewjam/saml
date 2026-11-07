package samlsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

func TestNewLogoutBindingOption(t *testing.T) {
	t.Run("default is unchanged", func(t *testing.T) {
		m, err := New(simpleSignTestOptions(t))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("", m.LogoutBinding))
	})
	t.Run("HTTP-Redirect and HTTP-POST", func(t *testing.T) {
		for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
			opts := simpleSignTestOptions(t)
			opts.LogoutBinding = binding
			m, err := New(opts)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(binding, m.LogoutBinding))
		}
	})
	t.Run("SimpleSign requires SignRequest", func(t *testing.T) {
		opts := simpleSignTestOptions(t)
		opts.LogoutBinding = saml.HTTPPostSimpleSignBinding
		_, err := New(opts)
		assert.ErrorContains(t, err, "requires SignRequest")
		opts.SignRequest = true
		m, err := New(opts)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(saml.HTTPPostSimpleSignBinding, m.LogoutBinding))
	})
	t.Run("unsupported binding", func(t *testing.T) {
		opts := simpleSignTestOptions(t)
		opts.LogoutBinding = saml.HTTPArtifactBinding
		_, err := New(opts)
		assert.ErrorContains(t, err, "unsupported LogoutBinding")
	})
}

// newSimpleSignLogoutTest returns a logoutTest whose middleware signs
// requests and prefers the HTTP-POST-SimpleSign binding for logout.
func newSimpleSignLogoutTest(t *testing.T, sloBindings ...string) *logoutTest {
	t.Helper()
	lt := newLogoutTest(t, sloBindings...)
	lt.m.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod
	lt.m.LogoutBinding = saml.HTTPPostSimpleSignBinding
	return lt
}

// simpleSignFormFields returns the values of the hidden fields of the form
// in body.
func simpleSignFormFields(body string) map[string]string {
	fields := map[string]string{}
	for _, m := range regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		fields[m[1]] = html.UnescapeString(m[2])
	}
	return fields
}

// checkSimpleSignForm checks that resp holds an auto-submitting
// HTTP-POST-SimpleSign form of messageParam (SAMLRequest or SAMLResponse),
// posted to the IDP's SimpleSign SLO endpoint and allowed by its CSP, whose
// message carries no XML signature and whose SimpleSign signature is made
// with cert's key. It returns the message's XML and the form fields.
func checkSimpleSignForm(t *testing.T, resp *httptest.ResponseRecorder, messageParam, formID string, cert *x509.Certificate) ([]byte, map[string]string) {
	t.Helper()
	assert.Assert(t, is.Equal(http.StatusOK, resp.Code))

	// The CSP hash is that of the form's script, which is the script of the
	// HTTP-POST form of the same message.
	scriptContent := "document.getElementById('SAMLSubmitButton').style.visibility=\"hidden\";document.getElementById('" + formID + "').submit();"
	scriptSum := sha256.Sum256([]byte(scriptContent))
	assert.Check(t, is.Equal("default-src; script-src 'sha256-"+base64.StdEncoding.EncodeToString(scriptSum[:])+"'; reflected-xss block; referrer no-referrer;",
		resp.Header().Get("Content-Security-Policy")))
	body := resp.Body.String()
	assert.Check(t, is.Contains(body, scriptContent+"</script>"))
	assert.Check(t, is.Contains(body, `action="`+logoutTestIDPPost+`"`))

	fields := simpleSignFormFields(body)
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, fields["SigAlg"]))
	message, err := base64.StdEncoding.DecodeString(fields[messageParam])
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(message), "Signature"), string(message))

	// Check the signature independently of the saml package.
	signature, err := base64.StdEncoding.DecodeString(fields["Signature"])
	assert.NilError(t, err)
	content := messageParam + "=" + string(message) + "&RelayState=" + fields["RelayState"] + "&SigAlg=" + fields["SigAlg"]
	assert.NilError(t, cert.CheckSignature(x509.SHA256WithRSA, []byte(content), signature))
	return message, fields
}

func TestHandleStartLogoutSimpleSignBinding(t *testing.T) {
	lt := newSimpleSignLogoutTest(t, saml.HTTPRedirectBinding, saml.HTTPPostSimpleSignBinding)
	lt.m.ScriptNonce = func(*http.Request) string { return "n0nce" }

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)

	assertSessionDeleted(t, lt, resp)
	assert.Check(t, is.Contains(resp.Header().Get("Content-Security-Policy"), postRequestScriptHash))
	assert.Check(t, is.Contains(resp.Body.String(), `nonce="n0nce"`))
	message, fields := checkSimpleSignForm(t, resp, "SAMLRequest", "SAMLRequestForm", lt.m.ServiceProvider.Certificate)

	var logoutRequest saml.LogoutRequest
	assert.NilError(t, xml.Unmarshal(message, &logoutRequest))
	assert.Check(t, is.Equal(logoutTestIDPPost, logoutRequest.Destination))
	assert.Check(t, is.Equal("alice@example.com", logoutRequest.NameID.Value))
	assert.Assert(t, logoutRequest.SessionIndex != nil)
	assert.Check(t, is.Equal("session-index-1", logoutRequest.SessionIndex.Value))

	// The request is tracked, and the RelayState is the tracking index.
	cookie := logoutTrackingCookie(t, resp)
	assert.Check(t, is.Equal("samlslo_"+fields["RelayState"], cookie.Name))
	sloReq := httptest.NewRequest(http.MethodGet, "https://sp.example.com/saml/slo", nil)
	sloReq.AddCookie(cookie)
	tracked := lt.m.LogoutRequestTracker.GetTrackedRequests(sloReq)
	assert.Assert(t, is.Len(tracked, 1))
	assert.Check(t, is.Equal(logoutRequest.ID, tracked[0].SAMLRequestID))
}

// When the IDP has no SimpleSign SLO endpoint, the default binding is used.
func TestHandleStartLogoutSimpleSignBindingUnsupportedByIDP(t *testing.T) {
	lt := newSimpleSignLogoutTest(t, saml.HTTPRedirectBinding, saml.HTTPPostBinding)

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, strings.HasPrefix(resp.Header().Get("Location"), logoutTestIDPRedirect+"?"), resp.Header().Get("Location"))
}

// An explicit LogoutBinding is preferred over the default HTTP-Redirect.
func TestHandleStartLogoutPostBindingPreferred(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	lt.m.LogoutBinding = saml.HTTPPostBinding

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)

	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assert.Check(t, is.Contains(resp.Body.String(), `action="`+logoutTestIDPPost+`"`))
	assert.Check(t, !strings.Contains(resp.Body.String(), `name="SigAlg"`))
}

func TestServeSLOLogoutRequestSimpleSignResponse(t *testing.T) {
	lt := newSimpleSignLogoutTest(t, saml.HTTPRedirectBinding, saml.HTTPPostSimpleSignBinding)

	resp := lt.postToSLO(url.Values{
		"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
		"RelayState":  {"idp-state"},
	}, lt.sessionCookie(t, "x"))

	assertSessionDeleted(t, lt, resp)
	assert.Check(t, is.Contains(resp.Header().Get("Content-Security-Policy"), postResponseScriptHash))
	message, fields := checkSimpleSignForm(t, resp, "SAMLResponse", "SAMLResponseForm", lt.m.ServiceProvider.Certificate)
	assert.Check(t, is.Equal("idp-state", fields["RelayState"]))

	var logoutResponse saml.LogoutResponse
	assert.NilError(t, xml.Unmarshal(message, &logoutResponse))
	assert.Check(t, is.Equal(logoutTestIDPPost, logoutResponse.Destination))
	assert.Check(t, is.Equal("id-idp-logout-request", logoutResponse.InResponseTo))
	assert.Check(t, is.Equal(saml.StatusSuccess, logoutResponse.Status.StatusCode.Value))
}

// simpleSignIDPForm returns the form of an HTTP-POST-SimpleSign message
// carrying el in messageParam, signed by the IDP's key.
func (lt *logoutTest) simpleSignIDPForm(t *testing.T, messageParam string, el *etree.Element, relayState string) url.Values {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	message, err := doc.WriteToBytes()
	assert.NilError(t, err)
	content := messageParam + "=" + string(message) + "&RelayState=" + relayState + "&SigAlg=" + dsig.RSASHA256SignatureMethod
	digest := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, lt.idpKey, crypto.SHA256, digest[:])
	assert.NilError(t, err)
	return url.Values{
		messageParam: {base64.StdEncoding.EncodeToString(message)},
		"RelayState": {relayState},
		"SigAlg":     {dsig.RSASHA256SignatureMethod},
		"Signature":  {base64.StdEncoding.EncodeToString(signature)},
	}
}

// ServeSLO accepts logout messages sent with the HTTP-POST-SimpleSign
// binding, whatever LogoutBinding is.
func TestServeSLOReceivesSimpleSign(t *testing.T) {
	t.Run("LogoutResponse", func(t *testing.T) {
		lt := newLogoutTest(t, saml.HTTPRedirectBinding)
		tracking := lt.trackLogoutRequest(t, "id-sp-logout-request")
		form := lt.simpleSignIDPForm(t, "SAMLResponse", lt.logoutResponse(saml.StatusSuccess).Element(), "state")
		resp := lt.postToSLO(form, lt.sessionCookie(t, "x"), tracking)
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
		assertSessionDeleted(t, lt, resp)

		// A bad signature is refused.
		form.Set("RelayState", "other")
		resp = lt.postToSLO(form, lt.trackLogoutRequest(t, "id-sp-logout-request"))
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})
	t.Run("LogoutRequest", func(t *testing.T) {
		lt := newLogoutTest(t, saml.HTTPRedirectBinding)
		form := lt.simpleSignIDPForm(t, "SAMLRequest", lt.logoutRequest().Element(), "idp-state")
		resp := lt.postToSLO(form, lt.sessionCookie(t, "x"))
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		assertSessionDeleted(t, lt, resp)
		assert.Check(t, strings.HasPrefix(resp.Header().Get("Location"), logoutTestIDPRedirect+"?"), resp.Header().Get("Location"))

		// A bad signature is refused.
		form.Set("RelayState", "other")
		resp = lt.postToSLO(form, lt.sessionCookie(t, "x"))
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})
}
