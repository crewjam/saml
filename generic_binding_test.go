package saml

import (
	"html"
	"net/url"
	"regexp"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The generic RedirectBindingURL and SimpleSignValues give the same message
// and signature as the type-specific functions they generalize.
func TestGenericBindingEncoders(t *testing.T) {
	e := spcovSetup(t)
	e.sp.LogoutSignatureMethod = dsig.RSASHA256SignatureMethod
	req, err := e.sp.MakeLogoutRequest("https://idp.example.com/slo", "alice")
	assert.NilError(t, err)
	assert.Assert(t, req.Signature != nil)

	want, err := e.sp.RedirectLogoutRequestURL(req, "relay")
	assert.NilError(t, err)
	got, err := e.sp.RedirectBindingURL(req.Destination, "SAMLRequest", req.Element(), "relay", dsig.RSASHA256SignatureMethod)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(want.String(), got.String()))

	// Unsigned.
	got, err = e.sp.RedirectBindingURL(req.Destination, "SAMLRequest", req.Element(), "", "")
	assert.NilError(t, err)
	assert.Check(t, got.Query().Get("Signature") == "" && got.Query().Get("SigAlg") == "")

	values, err := e.sp.SimpleSignValues("SAMLRequest", req.Element(), "relay", dsig.RSASHA256SignatureMethod)
	assert.NilError(t, err)
	// The SimpleSign signature replaces the enveloped one, which callers of
	// SimpleSign remove first.
	unsigned := *req
	unsigned.Signature = nil
	form, err := unsigned.SimpleSign("relay", &ServiceProvider{
		Key: e.sp.Key, Certificate: e.sp.Certificate, SignatureMethod: dsig.RSASHA256SignatureMethod,
	})
	assert.NilError(t, err)
	fields := url.Values{}
	for _, m := range regexp.MustCompile(`name="([A-Za-z]+)" value="([^"]*)"`).FindAllStringSubmatch(string(form), -1) {
		fields.Set(m[1], html.UnescapeString(m[2]))
	}
	for _, name := range []string{"SAMLRequest", "RelayState", "SigAlg", "Signature"} {
		assert.Check(t, values.Get(name) != "", name)
		assert.Check(t, is.Equal(fields.Get(name), values.Get(name)), name)
	}

	_, err = e.sp.SimpleSignValues("SAMLRequest", req.Element(), "", "")
	assert.Check(t, err != nil)
}
