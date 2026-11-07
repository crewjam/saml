package samlsp

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml"
)

func simpleSignTestOptions(t *testing.T) Options {
	t.Helper()
	var metadata saml.EntityDescriptor
	assert.NilError(t, xml.Unmarshal(golden.Get(t, "idp_metadata.xml"), &metadata))
	return Options{
		URL:         mustParseURL("https://15661444.ngrok.io/"),
		Key:         mustParsePrivateKey(golden.Get(t, "key.pem")).(crypto.Signer),
		Certificate: mustParseCertificate(golden.Get(t, "cert.pem")),
		IDPMetadata: &metadata,
	}
}

func TestNewSimpleSignOptions(t *testing.T) {
	t.Run("defaults are unchanged", func(t *testing.T) {
		m, err := New(simpleSignTestOptions(t))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("", m.Binding))
		assert.Check(t, is.Equal(saml.HTTPPostBinding, m.ResponseBinding))
		acs := m.ServiceProvider.Metadata().SPSSODescriptors[0].AssertionConsumerServices
		assert.Check(t, is.Equal(saml.HTTPPostBinding, acs[0].Binding))
		assert.Check(t, is.Equal(saml.HTTPArtifactBinding, acs[1].Binding))
	})
	t.Run("SimpleSign requests require SignRequest", func(t *testing.T) {
		opts := simpleSignTestOptions(t)
		opts.Binding = saml.HTTPPostSimpleSignBinding
		_, err := New(opts)
		assert.ErrorContains(t, err, "requires SignRequest")
		opts.SignRequest = true
		m, err := New(opts)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(saml.HTTPPostSimpleSignBinding, m.Binding))
	})
	t.Run("unsupported binding", func(t *testing.T) {
		opts := simpleSignTestOptions(t)
		opts.Binding = saml.HTTPArtifactBinding
		_, err := New(opts)
		assert.ErrorContains(t, err, "unsupported Binding")
	})
	t.Run("SimpleSign responses", func(t *testing.T) {
		opts := simpleSignTestOptions(t)
		opts.UseSimpleSignResponse = true
		m, err := New(opts)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(saml.HTTPPostSimpleSignBinding, m.ResponseBinding))
		acs := m.ServiceProvider.Metadata().SPSSODescriptors[0].AssertionConsumerServices
		assert.Assert(t, is.Len(acs, 2))
		assert.Check(t, is.Equal(saml.HTTPPostSimpleSignBinding, acs[0].Binding))
		assert.Check(t, is.Equal(saml.HTTPPostBinding, acs[1].Binding))

		opts.UseArtifactResponse = true
		_, err = New(opts)
		assert.ErrorContains(t, err, "cannot both be set")

		opts.UseArtifactResponse = false
		opts.AssertionConsumerServiceBindings = []string{saml.HTTPPostBinding}
		_, err = New(opts)
		assert.ErrorContains(t, err, "must include the response binding")
	})
}

func TestMiddlewareRequireAccountNoCredsSimpleSignBinding(t *testing.T) {
	test := NewMiddlewareTest(t)
	sp := &test.Middleware.ServiceProvider
	sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	idpSSO := &sp.IDPMetadata.IDPSSODescriptors[0]
	idpSSO.SingleSignOnServices = append(idpSSO.SingleSignOnServices, saml.Endpoint{
		Binding:  saml.HTTPPostSimpleSignBinding,
		Location: "https://idp.testshib.org/idp/profile/SAML2/POST-SimpleSign/SSO",
	})
	test.Middleware.Binding = saml.HTTPPostSimpleSignBinding
	test.Middleware.ResponseBinding = saml.HTTPPostSimpleSignBinding

	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			panic("not reached")
		}))
	req, _ := http.NewRequest("GET", "/frob", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusOK, resp.Code))

	// Same script, so the same CSP hash, as the HTTP-POST form.
	scriptContent := "document.getElementById('SAMLSubmitButton').style.visibility=\"hidden\";document.getElementById('SAMLRequestForm').submit();"
	scriptSum := sha256.Sum256([]byte(scriptContent))
	assert.Check(t, is.Equal("default-src; script-src 'sha256-"+base64.StdEncoding.EncodeToString(scriptSum[:])+"'; reflected-xss block; referrer no-referrer;",
		resp.Header().Get("Content-Security-Policy")))
	body := resp.Body.String()
	assert.Check(t, strings.Contains(body, "<script>"+scriptContent+"</script>"), body)
	assert.Check(t, strings.Contains(body, `action="https://idp.testshib.org/idp/profile/SAML2/POST-SimpleSign/SSO"`), body)

	fields := map[string]string{}
	for _, m := range regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		fields[m[1]] = html.UnescapeString(m[2])
	}
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, fields["SigAlg"]))
	requestXML, err := base64.StdEncoding.DecodeString(fields["SAMLRequest"])
	assert.NilError(t, err)
	assert.Check(t, strings.Contains(string(requestXML), `ProtocolBinding="`+saml.HTTPPostSimpleSignBinding+`"`), string(requestXML))
	assert.Check(t, !strings.Contains(string(requestXML), "<ds:Signature"), string(requestXML))

	// Check the signature independently of the saml package: RSA-SHA256
	// over SAMLRequest=<xml>&RelayState=<relay state>&SigAlg=<sigalg>.
	signature, err := base64.StdEncoding.DecodeString(fields["Signature"])
	assert.NilError(t, err)
	content := "SAMLRequest=" + string(requestXML) + "&RelayState=" + fields["RelayState"] + "&SigAlg=" + fields["SigAlg"]
	assert.NilError(t, test.Certificate.CheckSignature(x509.SHA256WithRSA, []byte(content), signature))
}
