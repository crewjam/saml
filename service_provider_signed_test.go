package saml

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	"gotest.tools/golden"
)

// Given a SAMLRequest query string, sign the query and validate signature
// Using same Cert for SP and IdP in order to test
func TestSigningAndValidation(t *testing.T) {
	type testCase struct {
		desc         string
		relayState   string
		requestType  reqType
		wantErr      bool
		wantRawQuery string
	}

	testCases := []testCase{
		{
			desc:         "validate signature of SAMLRequest with relayState",
			relayState:   "AAAAAAAAAAAA",
			requestType:  samlRequest,
			wantRawQuery: "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iaWQtMDAwMjA0MDYwODBhMGMwZTEwMTIxNDE2MTgxYTFjMWUyMDIyMjQyNiIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTUtMTItMDFUMDE6NTc6MDlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vc2FtbC9zc28iIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9zYW1sMi9hY3MiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCI%2BPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL3NwLmV4YW1wbGUuY29tL3NhbWwyL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50IiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg%3D%3D&RelayState=AAAAAAAAAAAA&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=zWAF4S%2FIs7tfmEriOsT5Fm8EFOGS3iCq6OxP5i7hM%2BMPwAoXwdDz6fKH8euS1gQ3sGOZBdHD588FZLvnO1OeCxLaEsxHMVKsAZSZFLBmPPwqB6e%2B84cCwX2szOeoMROaR%2B36mdoBDRQz36JIvyBBG%2FND9x41k%2FGQuAuwk%2B9fkuE%3D",
		},
		{
			desc:         "validate signature of SAML request without relay state",
			relayState:   "",
			requestType:  samlRequest,
			wantRawQuery: "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iaWQtMDAwMjA0MDYwODBhMGMwZTEwMTIxNDE2MTgxYTFjMWUyMDIyMjQyNiIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTUtMTItMDFUMDE6NTc6MDlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vc2FtbC9zc28iIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9zYW1sMi9hY3MiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCI%2BPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL3NwLmV4YW1wbGUuY29tL3NhbWwyL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50IiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=HDdoHJSdkYh9%2BmE7RZ1LXcsAWIMJ6LuzKJgwLxH%2BQ4sKFlh8b5moFuQ%2B7rPEwoTcg9SjgCGV5rW9v8PrSU7WGKcLfAbeVwXWyU94ghjFZHEj%2BFCDpsfTD750ZPAPVnhVr0GogFZZ7c%2BEWX4NAqL4CYxDvsg56o%2BpOjw62G%2FyPDc%3D",
		},
		{
			desc:         "validate signature of SAML response with relay state",
			relayState:   "AAAAAAAAAAAA",
			requestType:  samlResponse,
			wantRawQuery: "SAMLResponse=PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iaWQtMDAwMjA0MDYwODBhMGMwZTEwMTIxNDE2MTgxYTFjMWUyMDIyMjQyNiIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTUtMTItMDFUMDE6NTc6MDlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vc2FtbC9zc28iIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9zYW1sMi9hY3MiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCI%2BPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL3NwLmV4YW1wbGUuY29tL3NhbWwyL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50IiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg%3D%3D&RelayState=AAAAAAAAAAAA&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=JDeiWfLgV7SZqgqU64wgtAHS%2FqtF2c3c%2B9g1vdfRHn03tm5jrgsvJtIYg1BD8HoejCoyruH3xgDz1i2qqecVcUiAdaVgVvhn0JWJ%2BzeN9YpUFTEQ4Ah1pwezlSArzuz5esgYzSkemViox313HePWZ%2Fd0FAmtdXuGHA8O0Lp%2F4Ws%3D",
		},
	}

	idpMetadata := golden.Get(t, "SP_IDPMetadata_signing")
	s := ServiceProvider{
		Key:             mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey),
		Certificate:     mustParseCertificate(golden.Get(t, "idp_cert.pem")),
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		SignatureMethod: dsig.RSASHA1SignatureMethod,
	}

	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	idpCert, err := s.getIDPSigningCerts()

	assert.Check(t, err == nil)
	assert.Check(t,
		s.Certificate.Issuer.CommonName == idpCert[0].Issuer.CommonName, "expected %s, got %s",
		s.Certificate.Issuer.CommonName, idpCert[0].Issuer.CommonName)

	req := golden.Get(t, "idp_authn_request.xml")
	reqString := base64.StdEncoding.EncodeToString(req)

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			relayState := tc.relayState

			rawQuery := string(tc.requestType) + "=" + url.QueryEscape(reqString)

			if relayState != "" {
				rawQuery += "&RelayState=" + relayState
			}

			rawQuery, err = s.signQuery(tc.requestType, rawQuery, reqString, relayState)
			assert.NilError(t, err, "error signing query: %s", err)

			assert.Equal(t, tc.wantRawQuery, rawQuery)

			query, err := url.ParseQuery(rawQuery)
			assert.NilError(t, err, "error parsing query: %s", err)

			err = s.validateQuerySig(query)
			assert.NilError(t, err, "error validating query: %s", err)
		})
	}
}

// Given a raw query with an unsupported signature method, the signature should be rejected.
func TestInvalidSignatureAlgorithm(t *testing.T) {
	rawQuery := "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iaWQtMDAwMjA0MDYwODBhMGMwZTEwMTIxNDE2MTgxYTFjMWUyMDIyMjQyNiIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTUtMTItMDFUMDE6NTc6MDlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vc2FtbC9zc28iIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9zYW1sMi9hY3MiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCI%2BPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL3NwLmV4YW1wbGUuY29tL3NhbWwyL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50IiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg%3D%3D&RelayState=AAAAAAAAAAAA&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha384&Signature=zWAF4S%2FIs7tfmEriOsT5Fm8EFOGS3iCq6OxP5i7hM%2BMPwAoXwdDz6fKH8euS1gQ3sGOZBdHD588FZLvnO1OeCxLaEsxHMVKsAZSZFLBmPPwqB6e%2B84cCwX2szOeoMROaR%2B36mdoBDRQz36JIvyBBG%2FND9x41k%2FGQuAuwk%2B9fkuE%3D"

	idpMetadata := golden.Get(t, "SP_IDPMetadata_signing")
	s := ServiceProvider{
		Key:             mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey),
		Certificate:     mustParseCertificate(golden.Get(t, "idp_cert.pem")),
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		SignatureMethod: dsig.RSASHA1SignatureMethod,
	}

	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	idpCert, err := s.getIDPSigningCerts()

	assert.Check(t, err == nil)
	assert.Check(t,
		s.Certificate.Issuer.CommonName == idpCert[0].Issuer.CommonName, "expected %s, got %s",
		s.Certificate.Issuer.CommonName, idpCert[0].Issuer.CommonName)

	query, err := url.ParseQuery(rawQuery)
	assert.NilError(t, err, "error parsing query: %s", err)

	err = s.validateQuerySig(query)
	assert.Error(t, err, "unsupported signature algorithm: http://www.w3.org/2000/09/xmldsig#rsa-sha384")
}
