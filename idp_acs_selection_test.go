package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Tests for how the IdP chooses the assertion consumer service a Response
// goes to (issue #806): the saml-metadata §2.2.3 default-endpoint rule,
// used for SP-initiated requests that name no ACS and for IdP-initiated
// SSO, and matching on ProtocolBinding.

const (
	acsselURL     = "https://sp.example.com/saml2/acs"
	acsselPostURL = "https://sp.example.com/saml2/acs-post"
)

func acsselBool(b bool) *bool { return &b }

// acsselMetadata returns SP metadata whose only SPSSODescriptor has acs as
// its assertion consumer services.
func acsselMetadata(acs ...IndexedEndpoint) *EntityDescriptor {
	return &EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{{AssertionConsumerServices: acs}}}
}

// acsselNewTest returns an IdP test whose service provider's metadata lists
// acs as its assertion consumer services, and a pointer that is set to true
// when the SessionProvider is asked for a session.
func acsselNewTest(t *testing.T, acs ...IndexedEndpoint) (*IdentityProviderTest, *bool) {
	t.Helper()
	test := idpErrNewTest(t)
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].AssertionConsumerServices = acs
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == test.SP.MetadataURL.String() {
				return metadata, nil
			}
			return nil, errors.New("unknown service provider")
		},
	}
	sessionAsked := new(bool)
	test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
		*sessionAsked = true
		return idpcovAliceSession(w, r, req)
	}}
	return test, sessionAsked
}

// acsselRequest returns an HTTP-Redirect AuthnRequest from test.SP for the
// ACS at acsURL with protocolBinding, after mutate (if not nil) has changed
// it.
func acsselRequest(t *testing.T, test *IdentityProviderTest, acsURL, protocolBinding string, mutate func(*AuthnRequest)) *http.Request {
	t.Helper()
	authnReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	authnReq.AssertionConsumerServiceURL = acsURL
	authnReq.ProtocolBinding = protocolBinding
	if mutate != nil {
		mutate(authnReq)
	}
	u, err := authnReq.Redirect("relay", &test.SP)
	assert.NilError(t, err)
	return httptest.NewRequest("GET", u.String(), nil)
}

// acsselCheckUnsupportedBinding checks that w holds an error Response with
// the status Requester / UnsupportedBinding, posted to location, and that
// the user was not asked to log in.
func acsselCheckUnsupportedBinding(t *testing.T, w *httptest.ResponseRecorder, sessionAsked bool, location string) {
	t.Helper()
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	assert.Check(t, !sessionAsked, "the user was asked to log in")
	el, action, fields := idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, is.Equal(location, action))
	assert.Check(t, is.Equal(location, el.SelectAttrValue("Destination", "")))
	assert.Check(t, is.DeepEqual([]string{"relay"}, fields["RelayState"]))
	assert.Check(t, el.SelectAttrValue("InResponseTo", "") != "")
	assert.Check(t, el.FindElement("./Assertion") == nil)
	assert.Check(t, el.FindElement("./Signature") != nil)
	code := el.FindElement("./Status/StatusCode")
	assert.Assert(t, code != nil)
	assert.Check(t, is.Equal(StatusRequester, code.SelectAttrValue("Value", "")))
	nested := code.FindElement("./StatusCode")
	if assert.Check(t, nested != nil) {
		assert.Check(t, is.Equal(StatusUnsupportedBinding, nested.SelectAttrValue("Value", "")))
	}
}

// acsselCheckSuccess checks that w holds a Response with an assertion,
// posted to location.
func acsselCheckSuccess(t *testing.T, w *httptest.ResponseRecorder, location string) {
	t.Helper()
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	el, action, _ := idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, is.Equal(location, action))
	code := el.FindElement("./Status/StatusCode")
	assert.Assert(t, code != nil)
	assert.Check(t, is.Equal(StatusSuccess, code.SelectAttrValue("Value", "")))
	assert.Check(t, el.FindElement("./Assertion") != nil || el.FindElement("./EncryptedAssertion") != nil)
}

var acsselDefaultCases = []struct {
	name string
	acs  []IndexedEndpoint
	want string // "" when there is no default endpoint
}{
	{
		name: "first isDefault=true",
		acs: []IndexedEndpoint{
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-first", Index: 0},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-default", Index: 1, IsDefault: acsselBool(true)},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-default-2", Index: 2, IsDefault: acsselBool(true)},
		},
		want: "https://sp.example.com/acs-default",
	},
	{
		name: "skips isDefault=false",
		acs: []IndexedEndpoint{
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-not-default", Index: 0, IsDefault: acsselBool(false)},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-default", Index: 1},
		},
		want: "https://sp.example.com/acs-default",
	},
	{
		name: "first when all are isDefault=false",
		acs: []IndexedEndpoint{
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-1", Index: 0, IsDefault: acsselBool(false)},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-2", Index: 1, IsDefault: acsselBool(false)},
		},
		want: "https://sp.example.com/acs-1",
	},
	{
		name: "first unmarked endpoint whatever its sendable binding",
		acs: []IndexedEndpoint{
			{Binding: HTTPPostSimpleSignBinding, Location: "https://sp.example.com/acs-simplesign", Index: 0},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-post", Index: 1},
		},
		want: "https://sp.example.com/acs-simplesign",
	},
	{
		name: "first isDefault=false endpoint whatever its sendable binding",
		acs: []IndexedEndpoint{
			{Binding: HTTPPostSimpleSignBinding, Location: "https://sp.example.com/acs-simplesign", Index: 0, IsDefault: acsselBool(false)},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-post", Index: 1, IsDefault: acsselBool(false)},
		},
		want: "https://sp.example.com/acs-simplesign",
	},
	{
		name: "ignores HTTP-Redirect, which cannot carry a Response",
		acs: []IndexedEndpoint{
			{Binding: HTTPRedirectBinding, Location: "https://sp.example.com/acs-redirect", Index: 0},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-post", Index: 1},
		},
		want: "https://sp.example.com/acs-post",
	},
	{
		name: "ignores an HTTP-Artifact isDefault=true endpoint",
		acs: []IndexedEndpoint{
			{Binding: HTTPArtifactBinding, Location: "https://sp.example.com/acs-artifact", Index: 0, IsDefault: acsselBool(true)},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs-post", Index: 1, IsDefault: acsselBool(false)},
		},
		want: "https://sp.example.com/acs-post",
	},
	{
		name: "none when no endpoint has a sendable binding",
		acs: []IndexedEndpoint{
			{Binding: HTTPRedirectBinding, Location: "https://sp.example.com/acs-redirect", Index: 0, IsDefault: acsselBool(true)},
			{Binding: HTTPArtifactBinding, Location: "https://sp.example.com/acs-artifact", Index: 1},
		},
	},
}

// saml-core §3.4.1 (errata): without an ACS index or URL the IdP "MUST
// return the <Response> message to the default location associated with the
// requester", chosen by saml-metadata §2.2.3 among the endpoints the IdP can
// send a Response to.
func TestIDPACSSelectionDefaultEndpoint(t *testing.T) {
	for _, tc := range acsselDefaultCases {
		t.Run(tc.name, func(t *testing.T) {
			req := IdpAuthnRequest{ServiceProviderMetadata: acsselMetadata(tc.acs...)}
			err := req.getACSEndpoint()
			if tc.want == "" {
				assert.Check(t, err != nil)
				return
			}
			assert.NilError(t, err)
			assert.Check(t, is.Equal(tc.want, req.ACSEndpoint.Location))
		})
	}
}

// saml-profiles §4.1.5: an unsolicited Response "SHOULD be delivered to the
// <md:AssertionConsumerService> endpoint of the service provider designated
// as the default", by the same rule.
func TestIDPACSSelectionIdpInitiatedDefaultEndpoint(t *testing.T) {
	for _, tc := range acsselDefaultCases {
		t.Run(tc.name, func(t *testing.T) {
			test, _ := acsselNewTest(t, tc.acs...)
			r := httptest.NewRequest("GET", "https://idp.example.com/login", nil)
			req, err := test.IDP.NewIdpInitiatedRequest(r, test.SP.MetadataURL.String(), "")
			if tc.want == "" {
				assert.Check(t, errors.Is(err, ErrUnknownAssertionConsumerService), "got %v", err)
				return
			}
			assert.NilError(t, err)
			assert.Check(t, is.Equal(tc.want, req.ACSEndpoint.Location))
		})
	}
}

// With only an HTTP-Artifact endpoint at the requested URL, the IdP cannot
// send the Response there: it answers with UnsupportedBinding, sent to the
// default endpoint from the metadata, before asking the user to log in,
// instead of failing with HTTP 500 after the login.
func TestIDPACSSelectionUnsendableEndpointAtURL(t *testing.T) {
	for _, binding := range []string{HTTPArtifactBinding, HTTPPostBinding, ""} {
		t.Run("ProtocolBinding="+binding, func(t *testing.T) {
			test, sessionAsked := acsselNewTest(t,
				IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 0},
				IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselPostURL, Index: 1},
			)
			w := httptest.NewRecorder()
			test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, binding, nil))
			acsselCheckUnsupportedBinding(t, w, *sessionAsked, acsselPostURL)
		})
	}
}

// Validate still resolves an endpoint with a binding the IdP cannot send,
// for callers that send the Response themselves; ServeSSO refuses it with
// the default ResponseWriter. With StrictACSBinding, Validate reports a URL
// without the requested binding as ErrUnsupported.
func TestIDPACSSelectionValidateUnsupportedBinding(t *testing.T) {
	test, _ := acsselNewTest(t, IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 0})
	req, err := NewIdpAuthnRequest(&test.IDP, acsselRequest(t, test, acsselURL, HTTPArtifactBinding, nil))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	assert.Check(t, is.Equal(HTTPArtifactBinding, req.ACSEndpoint.Binding))
	err = req.checkSendableACS()
	assert.Check(t, errors.Is(err, ErrUnsupported), "got %v", err)
	assert.Check(t, errors.Is(err, errUnsupportedACSBinding), "got %v", err)

	test.IDP.StrictACSBinding = true
	req, err = NewIdpAuthnRequest(&test.IDP, acsselRequest(t, test, acsselURL, HTTPPostBinding, nil))
	assert.NilError(t, err)
	err = req.Validate()
	assert.Check(t, errors.Is(err, ErrUnsupported), "got %v", err)
	assert.Check(t, errors.Is(err, errUnsupportedACSBinding), "got %v", err)
	assert.Check(t, !errors.Is(err, ErrUnknownAssertionConsumerService), "got %v", err)
}

// An endpoint named by index with a binding the IdP cannot send gets
// UnsupportedBinding too.
func TestIDPACSSelectionUnsendableEndpointByIndex(t *testing.T) {
	test, sessionAsked := acsselNewTest(t,
		IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselPostURL, Index: 0},
		IndexedEndpoint{Binding: HTTPRedirectBinding, Location: acsselURL, Index: 1},
	)
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, acsselRequest(t, test, "", "", func(r *AuthnRequest) {
		r.AssertionConsumerServiceIndex = "1"
	}))
	acsselCheckUnsupportedBinding(t, w, *sessionAsked, acsselPostURL)
}

// An HTTP-POST endpoint at the requested URL is used even when an
// HTTP-Artifact one at the same URL is listed first.
func TestIDPACSSelectionPrefersPostAtURL(t *testing.T) {
	test, _ := acsselNewTest(t,
		IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 0},
		IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselURL, Index: 1},
	)
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, HTTPPostBinding, nil))
	acsselCheckSuccess(t, w, acsselURL)
}

// Without StrictACSBinding, an endpoint is matched on Location as before, so
// a request for HTTP-Artifact at a URL that also has an HTTP-POST endpoint
// still gets an HTTP-POST Response.
func TestIDPACSSelectionProtocolBindingNotStrict(t *testing.T) {
	test, _ := acsselNewTest(t,
		IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselURL, Index: 0},
		IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 1},
	)
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, HTTPArtifactBinding, nil))
	acsselCheckSuccess(t, w, acsselURL)
}

// saml-core §3.4.1: ProtocolBinding "identifies a SAML protocol binding to be
// used when returning the <Response> message". With StrictACSBinding the
// endpoint must have both the requested Location and Binding.
func TestIDPACSSelectionStrictACSBinding(t *testing.T) {
	t.Run("HTTP-Artifact requested where HTTP-POST shares the URL", func(t *testing.T) {
		test, sessionAsked := acsselNewTest(t,
			IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselURL, Index: 0},
			IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 1},
		)
		test.IDP.StrictACSBinding = true
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, HTTPArtifactBinding, nil))
		acsselCheckUnsupportedBinding(t, w, *sessionAsked, acsselURL)
	})

	t.Run("no endpoint with the requested binding at the URL", func(t *testing.T) {
		test, sessionAsked := acsselNewTest(t,
			IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselURL, Index: 0},
		)
		test.IDP.StrictACSBinding = true
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, HTTPRedirectBinding, nil))
		acsselCheckUnsupportedBinding(t, w, *sessionAsked, acsselURL)
	})

	t.Run("matching binding listed after another at the URL", func(t *testing.T) {
		test, _ := acsselNewTest(t,
			IndexedEndpoint{Binding: HTTPPostSimpleSignBinding, Location: acsselURL, Index: 0},
			IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselURL, Index: 1},
		)
		test.IDP.StrictACSBinding = true
		req, err := NewIdpAuthnRequest(&test.IDP, acsselRequest(t, test, acsselURL, HTTPPostBinding, nil))
		assert.NilError(t, err)
		assert.NilError(t, req.Validate())
		assert.Check(t, is.Equal(HTTPPostBinding, req.ACSEndpoint.Binding))
		assert.Check(t, is.Equal(1, req.ACSEndpoint.Index))
	})

	t.Run("without ProtocolBinding the URL is matched as before", func(t *testing.T) {
		test, _ := acsselNewTest(t,
			IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselURL, Index: 0},
		)
		test.IDP.StrictACSBinding = true
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, "", nil))
		acsselCheckSuccess(t, w, acsselURL)
	})

	t.Run("HTTP 400 for a URL not in the metadata", func(t *testing.T) {
		test, sessionAsked := acsselNewTest(t,
			IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselURL, Index: 0},
		)
		test.IDP.StrictACSBinding = true
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, acsselRequest(t, test, "https://evil.example.com/acs", HTTPPostBinding, nil))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
		assert.Check(t, !*sessionAsked)
	})
}

// The error Response is only sent to an endpoint from the metadata that the
// IdP can send to; without one the request gets HTTP 400.
func TestIDPACSSelectionUnsupportedBindingWithoutDefault(t *testing.T) {
	test, sessionAsked := acsselNewTest(t,
		IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 0},
		IndexedEndpoint{Binding: HTTPRedirectBinding, Location: acsselPostURL, Index: 1},
	)
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, HTTPArtifactBinding, nil))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, !*sessionAsked)
}

// A request from an unknown service provider gets HTTP 400, not a Response.
func TestIDPACSSelectionUnsupportedBindingUnknownSP(t *testing.T) {
	test, sessionAsked := acsselNewTest(t,
		IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 0},
		IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselPostURL, Index: 1},
	)
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, HTTPArtifactBinding, func(r *AuthnRequest) {
		r.Issuer.Value = "https://unknown.example.com/saml2/metadata"
	}))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, !*sessionAsked)
}

// A custom ResponseWriter may support other bindings, so without
// StrictACSBinding the endpoint the request names is passed on to it.
func TestIDPACSSelectionCustomResponseWriterGetsEndpoint(t *testing.T) {
	test, _ := acsselNewTest(t,
		IndexedEndpoint{Binding: HTTPArtifactBinding, Location: acsselURL, Index: 0},
		IndexedEndpoint{Binding: HTTPPostBinding, Location: acsselPostURL, Index: 1},
	)
	var gotBinding string
	test.IDP.ResponseWriter = idpErrResponseWriterFunc(func(w http.ResponseWriter, req *IdpAuthnRequest) error {
		gotBinding = req.ACSEndpoint.Binding
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, acsselRequest(t, test, acsselURL, HTTPArtifactBinding, nil))
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code), w.Body.String())
	assert.Check(t, is.Equal(HTTPArtifactBinding, gotBinding))
}
