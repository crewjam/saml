package saml

import (
	"encoding/base64"
	"encoding/xml"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestLogoutRequestReason(t *testing.T) {
	req := &LogoutRequest{ID: "id-1", Version: "2.0", IssueInstant: spcovNow, Reason: LogoutReasonAdmin}
	buf, err := elementToBytes(req.Element())
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(buf), `Reason="urn:oasis:names:tc:SAML:2.0:logout:admin"`))

	var parsed LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &parsed))
	assert.Check(t, is.Equal(LogoutReasonAdmin, parsed.Reason))

	// Without a Reason, the attribute is left out.
	req.Reason = ""
	buf, err = elementToBytes(req.Element())
	assert.NilError(t, err)
	assert.Check(t, !is.Contains(string(buf), "Reason")().Success())
}

func TestRedirectLogoutResponseURL(t *testing.T) {
	e := spcovSetup(t)
	e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = []Endpoint{
		{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/slo"},
	}
	e.sp.LogoutSignatureMethod = dsig.RSASHA256SignatureMethod

	resp, err := e.sp.MakeLogoutResponseWithStatus("https://idp.example.com/slo", "id-request", successStatus())
	assert.NilError(t, err)
	assert.Assert(t, resp.Signature != nil)

	u, err := e.sp.RedirectLogoutResponseURL(resp, "relay")
	assert.NilError(t, err)
	q := u.Query()
	assert.Check(t, is.Equal("relay", q.Get("RelayState")))
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, q.Get("SigAlg")))
	assert.Check(t, q.Get("Signature") != "")

	deflated, err := base64.StdEncoding.DecodeString(q.Get("SAMLResponse"))
	assert.NilError(t, err)
	var sent LogoutResponse
	assert.NilError(t, xml.Unmarshal(spcovInflate(t, deflated), &sent))
	// The response sent is the one given, without its enveloped signature,
	// which the redirect binding replaces with the query string one.
	assert.Check(t, is.Equal(resp.ID, sent.ID))
	assert.Check(t, sent.Signature == nil)
	assert.Check(t, resp.Signature != nil, "resp was modified")
}
