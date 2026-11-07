package saml

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// newSimpleSignIDPTest returns an IdP test whose SP signs requests, accepts
// SimpleSign and HTTP-POST at its ACS, and trusts the IdP's (expired) test
// certificate.
func newSimpleSignIDPTest(t *testing.T) *IdentityProviderTest {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AdvertiseSimpleSignSSO = true
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", UserName: "alice"}
		},
	}
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.SP.AssertionConsumerServiceBindings = []string{HTTPPostSimpleSignBinding, HTTPPostBinding}
	test.SP.IgnoreCertificateExpiry = true
	test.SP.IDPMetadata = test.IDP.Metadata()
	return test
}

// assertionUID returns the value of the uid attribute DefaultAssertionMaker
// sets from Session.UserName.
func assertionUID(assertion *Assertion) string {
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if attr.FriendlyName == "uid" && len(attr.Values) == 1 {
				return attr.Values[0].Value
			}
		}
	}
	return ""
}

// postForm posts the hidden fields of form to its action and returns the
// parsed request.
func postForm(t *testing.T, form []byte) *http.Request {
	t.Helper()
	action, v := formFields(t, form)
	return simpleSignPost(t, action, v)
}

func TestSimpleSignSSORoundTrip(t *testing.T) {
	test := newSimpleSignIDPTest(t)
	const relayState = "ThisIsTheRelayState"

	authReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPPostSimpleSignBinding), HTTPPostSimpleSignBinding, HTTPPostSimpleSignBinding)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://idp.example.com/saml/sso", authReq.Destination))
	form, err := authReq.SimpleSign(relayState, &test.SP)
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, postForm(t, form))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	action, fields := formFields(t, w.Body.Bytes())
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
	assert.Check(t, is.Equal(relayState, fields.Get("RelayState")))
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, fields.Get("SigAlg")))
	assert.Check(t, fields.Get("Signature") != "")

	// The IdP keeps signing the Response with an XML signature.
	responseXML, err := base64.StdEncoding.DecodeString(fields.Get("SAMLResponse"))
	assert.NilError(t, err)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(responseXML))
	assert.Check(t, doc.Root().FindElement("./Signature") != nil)

	acsReq := simpleSignPost(t, action, fields)
	assertion, err := test.SP.ParseResponse(acsReq, []string{authReq.ID})
	if err != nil {
		t.Fatalf("ParseResponse: %v", spcovPrivateErr(t, err))
	}
	assert.Check(t, is.Equal("alice", assertionUID(assertion)))

	// The SimpleSign signature covers the RelayState.
	fields.Set("RelayState", "other")
	_, err = test.SP.ParseResponse(simpleSignPost(t, action, fields), []string{authReq.ID})
	assert.ErrorContains(t, spcovPrivateErr(t, err), "verification error")
}

func TestSimpleSignSSORoundTripWithoutRelayState(t *testing.T) {
	test := newSimpleSignIDPTest(t)
	form, err := test.SP.MakeSimpleSignAuthenticationRequest("")
	assert.NilError(t, err)

	r := postForm(t, form)
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	// MakeSimpleSignAuthenticationRequest asks for an HTTP-POST response,
	// and the SP lists HTTP-POST at the same URL, so that is what it gets.
	assert.Check(t, is.Equal(HTTPPostBinding, req.ACSEndpoint.Binding))
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", UserName: "alice"}))

	req.ACSEndpoint = &IndexedEndpoint{Binding: HTTPPostSimpleSignBinding, Location: test.SP.AcsURL.String()}
	w := httptest.NewRecorder()
	assert.NilError(t, DefaultResponseWriter{}.WriteResponse(w, req))
	assert.Check(t, !strings.Contains(w.Body.String(), `name="RelayState"`), w.Body.String())
	_, err = test.SP.ParseResponse(postForm(t, w.Body.Bytes()), []string{req.Request.ID})
	if err != nil {
		t.Fatalf("ParseResponse: %v", spcovPrivateErr(t, err))
	}
}

func TestSimpleSignIDPRejectsBadRequests(t *testing.T) {
	test := newSimpleSignIDPTest(t)
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostSimpleSignBinding, HTTPPostSimpleSignBinding)
	assert.NilError(t, err)
	requestXML := spcovSerialize(t, authReq.Element())
	valid := simpleSignMsg{param: "SAMLRequest", xml: requestXML, relayState: strPtr("rs"), sigAlg: dsig.RSASHA256SignatureMethod, key: test.SPKey}

	validate := func(t *testing.T, v url.Values) error {
		t.Helper()
		req, err := NewIdpAuthnRequest(&test.IDP, simpleSignPost(t, test.IDP.SSOURL.String(), v))
		if err != nil {
			return err
		}
		return req.Validate()
	}

	t.Run("valid", func(t *testing.T) {
		assert.NilError(t, validate(t, valid.values(t)))
	})
	t.Run("tampered request", func(t *testing.T) {
		v := valid.values(t)
		tampered := bytes.Replace(requestXML, []byte(authReq.ID), []byte("id-other"), 1)
		assert.Assert(t, !bytes.Equal(tampered, requestXML))
		v.Set("SAMLRequest", base64.StdEncoding.EncodeToString(tampered))
		assert.ErrorContains(t, validate(t, v), "verification error")
	})
	t.Run("tampered relay state", func(t *testing.T) {
		v := valid.values(t)
		v.Set("RelayState", "other")
		assert.ErrorContains(t, validate(t, v), "verification error")
	})
	t.Run("wrong key", func(t *testing.T) {
		m := valid
		m.key, _ = otherKey(t)
		assert.ErrorContains(t, validate(t, m.values(t)), "verification error")
	})
	t.Run("wrong SigAlg", func(t *testing.T) {
		v := valid.values(t)
		v.Set("SigAlg", dsig.RSASHA1SignatureMethod)
		assert.ErrorContains(t, validate(t, v), "verification error")
	})
	t.Run("duplicate Signature", func(t *testing.T) {
		v := valid.values(t)
		v.Add("Signature", "x")
		assert.ErrorContains(t, validate(t, v), "form field Signature appears more than once")
	})
	t.Run("duplicate SAMLRequest", func(t *testing.T) {
		v := valid.values(t)
		v.Add("SAMLRequest", v.Get("SAMLRequest"))
		assert.ErrorContains(t, validate(t, v), "form field SAMLRequest appears more than once")
	})
	t.Run("missing SigAlg", func(t *testing.T) {
		v := valid.values(t)
		v.Del("SigAlg")
		assert.ErrorContains(t, validate(t, v), "form must contain both SigAlg and Signature")
	})
	t.Run("missing Destination", func(t *testing.T) {
		r := *authReq
		r.Destination = ""
		m := valid
		m.xml = spcovSerialize(t, r.Element())
		assert.ErrorContains(t, validate(t, m.values(t)), "expected destination to be")
	})
	t.Run("SP without a signing certificate", func(t *testing.T) {
		test := newSimpleSignIDPTest(t)
		test.SP.Certificate = nil
		req, err := NewIdpAuthnRequest(&test.IDP, simpleSignPost(t, test.IDP.SSOURL.String(), valid.values(t)))
		assert.NilError(t, err)
		assert.ErrorContains(t, req.Validate(), "cannot find any signing certificate in the SP SSO descriptor")
	})
	t.Run("ServeSSO answers 400", func(t *testing.T) {
		v := valid.values(t)
		v.Set("RelayState", "other")
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, simpleSignPost(t, test.IDP.SSOURL.String(), v))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})
}

func TestSimpleSignIDPChoosesACSEndpoint(t *testing.T) {
	const acs = "https://sp.example.com/saml2/acs"
	isDefault := true
	simpleSign := IndexedEndpoint{Binding: HTTPPostSimpleSignBinding, Location: acs, Index: 1}
	post := IndexedEndpoint{Binding: HTTPPostBinding, Location: acs, Index: 2}
	defaultSimpleSign := simpleSign
	defaultSimpleSign.IsDefault = &isDefault

	for _, tc := range []struct {
		name      string
		endpoints []IndexedEndpoint
		request   AuthnRequest
		want      string // binding, or "" for no endpoint
	}{
		{"URL asks for SimpleSign", []IndexedEndpoint{post, simpleSign}, AuthnRequest{AssertionConsumerServiceURL: acs, ProtocolBinding: HTTPPostSimpleSignBinding}, HTTPPostSimpleSignBinding},
		{"URL asks for POST", []IndexedEndpoint{simpleSign, post}, AuthnRequest{AssertionConsumerServiceURL: acs, ProtocolBinding: HTTPPostBinding}, HTTPPostBinding},
		{"URL without binding prefers POST", []IndexedEndpoint{simpleSign, post}, AuthnRequest{AssertionConsumerServiceURL: acs}, HTTPPostBinding},
		{"URL without binding, only SimpleSign", []IndexedEndpoint{simpleSign}, AuthnRequest{AssertionConsumerServiceURL: acs}, HTTPPostSimpleSignBinding},
		{"URL asks for SimpleSign, only POST", []IndexedEndpoint{post}, AuthnRequest{AssertionConsumerServiceURL: acs, ProtocolBinding: HTTPPostSimpleSignBinding}, HTTPPostBinding},
		{"URL asks for POST, only SimpleSign", []IndexedEndpoint{simpleSign}, AuthnRequest{AssertionConsumerServiceURL: acs, ProtocolBinding: HTTPPostBinding}, ""},
		{"index", []IndexedEndpoint{simpleSign, post}, AuthnRequest{AssertionConsumerServiceIndex: "1"}, HTTPPostSimpleSignBinding},
		{"default SimpleSign", []IndexedEndpoint{post, defaultSimpleSign}, AuthnRequest{}, HTTPPostSimpleSignBinding},
		{"no default takes the first", []IndexedEndpoint{simpleSign, post}, AuthnRequest{}, HTTPPostSimpleSignBinding},
		{"no default takes the first POST", []IndexedEndpoint{post, simpleSign}, AuthnRequest{}, HTTPPostBinding},
		{"no default, only SimpleSign", []IndexedEndpoint{simpleSign}, AuthnRequest{}, HTTPPostSimpleSignBinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &IdpAuthnRequest{
				Request: tc.request,
				ServiceProviderMetadata: &EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{{
					AssertionConsumerServices: tc.endpoints,
				}}},
			}
			err := req.getACSEndpoint()
			if tc.want == "" {
				assert.Check(t, is.ErrorIs(err, os.ErrNotExist))
				return
			}
			assert.NilError(t, err)
			assert.Check(t, is.Equal(tc.want, req.ACSEndpoint.Binding))
		})
	}
}

func TestSimpleSignIDPResponseWriting(t *testing.T) {
	test := newSimpleSignIDPTest(t)
	makeReq := func(t *testing.T, binding string) *IdpAuthnRequest {
		t.Helper()
		authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostSimpleSignBinding, binding)
		assert.NilError(t, err)
		form, err := authReq.SimpleSign("rs", &test.SP)
		assert.NilError(t, err)
		req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, form))
		assert.NilError(t, err)
		assert.NilError(t, req.Validate())
		assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", UserName: "alice"}))
		return req
	}

	t.Run("SimpleSignBinding refuses an HTTP-POST endpoint", func(t *testing.T) {
		req := makeReq(t, HTTPPostBinding)
		_, err := req.SimpleSignBinding()
		assert.ErrorContains(t, err, "not HTTP-POST-SimpleSign")
	})
	t.Run("PostBinding refuses a SimpleSign endpoint", func(t *testing.T) {
		req := makeReq(t, HTTPPostSimpleSignBinding)
		_, err := req.PostBinding()
		assert.ErrorContains(t, err, "unsupported binding")
	})
	t.Run("custom template", func(t *testing.T) {
		req := makeReq(t, HTTPPostSimpleSignBinding)
		test.IDP.SimpleSignResponseFormTemplate = template.Must(template.New("x").Parse(`{{.URL}}|{{.RelayState}}|{{.SigAlg}}`))
		defer func() { test.IDP.SimpleSignResponseFormTemplate = nil }()
		w := httptest.NewRecorder()
		assert.NilError(t, req.WriteResponse(w))
		assert.Check(t, is.Equal(test.SP.AcsURL.String()+"|rs|"+dsig.RSASHA256SignatureMethod, w.Body.String()))
	})
	t.Run("HTTP-POST endpoint gets the HTTP-POST form", func(t *testing.T) {
		req := makeReq(t, HTTPPostBinding)
		w := httptest.NewRecorder()
		assert.NilError(t, req.WriteResponse(w))
		assert.Check(t, !strings.Contains(w.Body.String(), "SigAlg"), w.Body.String())
	})
	t.Run("IdP with a Signer", func(t *testing.T) {
		key := test.IDP.Key
		test.IDP.Signer, test.IDP.Key = key.(crypto.Signer), nil
		defer func() { test.IDP.Signer, test.IDP.Key = nil, key }()
		req := makeReq(t, HTTPPostSimpleSignBinding)
		w := httptest.NewRecorder()
		assert.NilError(t, req.WriteResponse(w))
		_, err := test.SP.ParseResponse(postForm(t, w.Body.Bytes()), []string{req.Request.ID})
		if err != nil {
			t.Fatalf("ParseResponse: %v", spcovPrivateErr(t, err))
		}
	})
}

func TestSimpleSignIDPInitiated(t *testing.T) {
	test := newSimpleSignIDPTest(t)
	test.SP.AssertionConsumerServiceBindings = []string{HTTPPostSimpleSignBinding}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "/after")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	_, fields := formFields(t, w.Body.Bytes())
	assert.Check(t, fields.Get("Signature") != "")

	test.SP.AllowIDPInitiated = true
	assertion, err := test.SP.ParseResponse(postForm(t, w.Body.Bytes()), nil)
	if err != nil {
		t.Fatalf("ParseResponse: %v", spcovPrivateErr(t, err))
	}
	assert.Check(t, is.Equal("alice", assertionUID(assertion)))

	// With HTTP-POST listed first, and neither marked isDefault, it is the
	// default endpoint (saml-metadata §2.2.3), so IdP-initiated responses
	// use it.
	test.SP.AssertionConsumerServiceBindings = []string{HTTPPostBinding, HTTPPostSimpleSignBinding}
	w = httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "/after")
	assert.Check(t, !strings.Contains(w.Body.String(), "SigAlg"), w.Body.String())
}

func TestSimpleSignIDPMetadata(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	assert.Check(t, is.Len(test.IDP.Metadata().IDPSSODescriptors[0].SingleSignOnServices, 2))
	test.IDP.AdvertiseSimpleSignSSO = true
	sso := test.IDP.Metadata().IDPSSODescriptors[0].SingleSignOnServices
	assert.Assert(t, is.Len(sso, 3))
	assert.Check(t, is.Equal(HTTPPostSimpleSignBinding, sso[2].Binding))
	assert.Check(t, is.Equal(test.IDP.SSOURL.String(), sso[2].Location))
}
