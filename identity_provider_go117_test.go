//go:build go1.17
// +build go1.17

package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestIDPHTTPCanHandleSSORequest(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w := httptest.NewRecorder()

	const validRequest = `lJJBayoxFIX%2FypC9JhnU5wszAz7lgWCLaNtFd5fMbQ1MkmnunVb%2FfUfbUqEgdhs%2BTr5zkmLW8S5s8KVD4mzvm0Cl6FIwEciRCeCRDFuznd2sTD5Upk2Ro42NyGZEmNjFMI%2BBOo9pi%2BnVWbzfrEqxY27JSEntEPfg2waHNnpJ4JtcgiWRLfoLXYBjwDfu6p%2B8JIoiWy5K4eqBUipXIzVRUwXKKtRK53qkJ3qqQVuNPUjU4TIQQ%2BBS5EqPBzofKH2ntBn%2FMervo8jWnyX%2BuVC78FwKkT1gopNKX1JUxSklXTMIfM0gsv8xeeDL%2BPGk7%2FF0Qg0GdnwQ1cW5PDLUwFDID6uquO1Dlot1bJw9%2FPLRmia%2BzRMCYyk4dSiq6205QSDXOxfy3KAq5Pkvqt4DAAD%2F%2Fw%3D%3D`

	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&"+
		"SAMLRequest="+validRequest, nil)
	test.IDP.Handler().ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))

	// rejects requests that are invalid
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&"+
		"SAMLRequest=PEF1dGhuUmVxdWVzdA%3D%3D", nil)
	test.IDP.Handler().ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))

	// rejects requests that contain malformed XML
	{
		a, _ := url.QueryUnescape(validRequest)
		b, _ := base64.StdEncoding.DecodeString(a)
		c, _ := ioutil.ReadAll(flate.NewReader(bytes.NewReader(b)))
		d := bytes.Replace(c, []byte("<AuthnRequest"), []byte("<AuthnRequest ::foo=\"bar\">]]"), 1)
		f := bytes.Buffer{}
		e, _ := flate.NewWriter(&f, flate.DefaultCompression)
		_, err := e.Write(d)
		assert.Check(t, err)
		err = e.Close()
		assert.Check(t, err)
		g := base64.StdEncoding.EncodeToString(f.Bytes())
		invalidRequest := url.QueryEscape(g)

		w = httptest.NewRecorder()
		r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&"+
			"SAMLRequest="+invalidRequest, nil)
		test.IDP.Handler().ServeHTTP(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	}
}
