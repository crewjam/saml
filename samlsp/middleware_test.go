package samlsp

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/testsaml"
)

type MiddlewareTest struct {
	AuthnRequest          []byte
	SamlResponse          []byte
	Key                   *rsa.PrivateKey
	Certificate           *x509.Certificate
	IDPMetadata           []byte
	Middleware            *Middleware
	expectedSessionCookie string
}

type testRandomReader struct {
	Next byte
}

func (tr *testRandomReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = tr.Next
		tr.Next += 2
	}
	return len(p), nil
}

func NewMiddlewareTest(t *testing.T) *MiddlewareTest {
	test := MiddlewareTest{}
	saml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Mon Dec 1 01:57:09.123456789 UTC 2015")
		return rv
	}
	jwt.TimeFunc = saml.TimeNow
	saml.Clock = dsig.NewFakeClockAt(saml.TimeNow())
	saml.RandReader = &testRandomReader{}

	test.AuthnRequest = golden.Get(t, "authn_request.url")
	test.SamlResponse = golden.Get(t, "saml_response.xml")
	test.Key = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	test.IDPMetadata = golden.Get(t, "idp_metadata.xml")

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(test.IDPMetadata, &metadata); err != nil {
		panic(err)
	}

	opts := Options{
		URL:         mustParseURL("https://15661444.ngrok.io/"),
		Key:         test.Key,
		Certificate: test.Certificate,
		IDPMetadata: &metadata,
	}

	var err error
	test.Middleware, err = New(opts)
	if err != nil {
		panic(err)
	}

	sessionProvider := DefaultSessionProvider(opts)
	sessionProvider.Name = "ttt"
	sessionProvider.MaxAge = 7200 * time.Second

	sessionCodec := sessionProvider.Codec.(JWTSessionCodec)
	sessionCodec.MaxAge = 7200 * time.Second
	sessionProvider.Codec = sessionCodec

	test.Middleware.Session = sessionProvider

	test.Middleware.ServiceProvider.MetadataURL.Path = "/saml2/metadata"
	test.Middleware.ServiceProvider.AcsURL.Path = "/saml2/acs"
	test.Middleware.ServiceProvider.SloURL.Path = "/saml2/slo"

	var tc JWTSessionClaims
	if err := json.Unmarshal(golden.Get(t, "token.json"), &tc); err != nil {
		panic(err)
	}
	test.expectedSessionCookie, err = sessionProvider.Codec.Encode(tc)
	if err != nil {
		panic(err)
	}

	return &test
}

func (test *MiddlewareTest) makeTrackedRequest(id string) string {
	codec := test.Middleware.RequestTracker.(CookieRequestTracker).Codec
	token, err := codec.Encode(TrackedRequest{
		Index:         "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6",
		SAMLRequestID: id,
		URI:           "/frob",
	})
	if err != nil {
		panic(err)
	}
	return token
}

func TestMiddlewareCanProduceMetadata(t *testing.T) {
	test := NewMiddlewareTest(t)
	req, _ := http.NewRequest("GET", "/saml2/metadata", nil)

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assert.Check(t, is.Equal("application/samlmetadata+xml",
		resp.Header().Get("Content-type")))
	golden.Assert(t, resp.Body.String(), "expected_middleware_metadata.xml")
}

func TestMiddlewareFourOhFour(t *testing.T) {
	test := NewMiddlewareTest(t)
	req, _ := http.NewRequest("GET", "/this/is/not/a/supported/uri", nil)

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusNotFound, resp.Code))
	respBuf, _ := io.ReadAll(resp.Body)
	assert.Check(t, is.Equal("404 page not found\n", string(respBuf)))
}

func TestMiddlewareRequireAccountNoCreds(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.Middleware.ServiceProvider.AcsURL.Scheme = "http"

	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("not reached")
		}))

	req, _ := http.NewRequest("GET", "/frob", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+
		test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly",
		resp.Header().Get("Set-Cookie")))

	redirectURL, err := url.Parse(resp.Header().Get("Location"))
	assert.Check(t, err)
	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	golden.Assert(t, string(decodedRequest), "expected_authn_request.xml")
}

func TestMiddlewareRequireAccountNoCredsSecure(t *testing.T) {
	test := NewMiddlewareTest(t)

	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("not reached")
		}))

	req, _ := http.NewRequest("GET", "/frob", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
		resp.Header().Get("Set-Cookie")))

	redirectURL, err := url.Parse(resp.Header().Get("Location"))
	assert.Check(t, err)
	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	golden.Assert(t, string(decodedRequest), "expected_authn_request_secure.xml")
}

func TestMiddlewareRequireAccountNoCredsPostBinding(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.Middleware.ServiceProvider.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices = test.Middleware.ServiceProvider.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices[1:2]
	assert.Check(t, is.Equal("",
		test.Middleware.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding)))

	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("not reached")
		}))

	req, _ := http.NewRequest("GET", "/frob", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
		resp.Header().Get("Set-Cookie")))

	golden.Assert(t, resp.Body.String(), "expected_post_binding_response.html")

	// check that the CSP script hash is set correctly
	scriptContent := "document.getElementById('SAMLSubmitButton').style.visibility=\"hidden\";document.getElementById('SAMLRequestForm').submit();"
	scriptSum := sha256.Sum256([]byte(scriptContent))
	scriptHash := base64.StdEncoding.EncodeToString(scriptSum[:])
	assert.Check(t, is.Equal("default-src; script-src 'sha256-"+scriptHash+"'; reflected-xss block; referrer no-referrer;",
		resp.Header().Get("Content-Security-Policy")))

	assert.Check(t, is.Equal("text/html", resp.Header().Get("Content-type")))
}

func TestMiddlewareRequireAccountCreds(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			genericSession := SessionFromContext(r.Context())
			jwtSession := genericSession.(JWTSessionClaims)
			assert.Check(t, is.Equal("555-5555", jwtSession.Attributes.Get("telephoneNumber")))
			assert.Check(t, is.Equal("And I", jwtSession.Attributes.Get("sn")))
			assert.Check(t, is.Equal("urn:mace:dir:entitlement:common-lib-terms", jwtSession.Attributes.Get("eduPersonEntitlement")))
			assert.Check(t, is.Equal("", jwtSession.Attributes.Get("eduPersonTargetedID")))
			assert.Check(t, is.Equal("Me Myself", jwtSession.Attributes.Get("givenName")))
			assert.Check(t, is.Equal("Me Myself And I", jwtSession.Attributes.Get("cn")))
			assert.Check(t, is.Equal("myself", jwtSession.Attributes.Get("uid")))
			assert.Check(t, is.Equal("myself@testshib.org", jwtSession.Attributes.Get("eduPersonPrincipalName")))
			assert.Check(t, is.DeepEqual([]string{"Member@testshib.org", "Staff@testshib.org"}, jwtSession.Attributes["eduPersonScopedAffiliation"]))
			assert.Check(t, is.DeepEqual([]string{"Member", "Staff"}, jwtSession.Attributes["eduPersonAffiliation"]))
			w.WriteHeader(http.StatusTeapot)
		}))

	req, _ := http.NewRequest("GET", "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusTeapot, resp.Code))
}

func TestMiddlewareRequireAccountBadCreds(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("not reached")
		}))

	req, _ := http.NewRequest("GET", "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.yejJbiI6Ik1lIE15c2VsZiBBbmQgSSIsImVkdVBlcnNvbkFmZmlsaWF0aW9uIjoiU3RhZmYiLCJlZHVQZXJzb25FbnRpdGxlbWVudCI6InVybjptYWNlOmRpcjplbnRpdGxlbWVudDpjb21tb24tbGliLXRlcm1zIiwiZWR1UGVyc29uUHJpbmNpcGFsTmFtZSI6Im15c2VsZkB0ZXN0c2hpYi5vcmciLCJlZHVQZXJzb25TY29wZWRBZmZpbGlhdGlvbiI6IlN0YWZmQHRlc3RzaGliLm9yZyIsImVkdVBlcnNvblRhcmdldGVkSUQiOiIiLCJleHAiOjE0NDg5Mzg2MjksImdpdmVuTmFtZSI6Ik1lIE15c2VsZiIsInNuIjoiQW5kIEkiLCJ0ZWxlcGhvbmVOdW1iZXIiOiI1NTUtNTU1NSIsInVpZCI6Im15c2VsZiJ9.SqeTkbGG35oFj_9H-d9oVdV-Hb7Vqam6LvZLcmia7FY; "+
		"Path=/; Max-Age=7200; Secure")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))

	assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
		resp.Header().Get("Set-Cookie")))

	redirectURL, err := url.Parse(resp.Header().Get("Location"))
	assert.Check(t, err)
	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	golden.Assert(t, string(decodedRequest), "expected_authn_request_secure.xml")
}

func TestMiddlewareRequireAccountExpiredCreds(t *testing.T) {
	test := NewMiddlewareTest(t)
	jwt.TimeFunc = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Mon Dec 1 01:31:21 UTC 2115")
		return rv
	}

	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("not reached")
		}))

	req, _ := http.NewRequest("GET", "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
		resp.Header().Get("Set-Cookie")))

	redirectURL, err := url.Parse(resp.Header().Get("Location"))
	assert.Check(t, err)
	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	golden.Assert(t, string(decodedRequest), "expected_authn_request_secure.xml")
}

func TestMiddlewareRequireAccountPanicOnRequestToACS(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("not reached")
		}))

	req, _ := http.NewRequest("POST", "https://15661444.ngrok.io/saml2/acs", nil)
	resp := httptest.NewRecorder()

	assert.Check(t, is.Panics(func() { handler.ServeHTTP(resp, req) }))
}

func TestMiddlewareRequireAttribute(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount(
		RequireAttribute("eduPersonAffiliation", "Staff")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTeapot)
			})))

	req, _ := http.NewRequest("GET", "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusTeapot, resp.Code))
}

func TestMiddlewareRequireAttributeWrongValue(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount(
		RequireAttribute("eduPersonAffiliation", "DomainAdmins")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("not reached")
			})))

	req, _ := http.NewRequest("GET", "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
}

func TestMiddlewareRequireAttributeNotPresent(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount(
		RequireAttribute("valueThatDoesntExist", "doesntMatter")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("not reached")
			})))

	req, _ := http.NewRequest("GET", "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
}

func TestMiddlewareRequireAttributeMissingAccount(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := RequireAttribute("eduPersonAffiliation", "DomainAdmins")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("not reached")
		}))

	req, _ := http.NewRequest("GET", "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
}

func TestMiddlewareCanParseResponse(t *testing.T) {
	test := NewMiddlewareTest(t)
	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
	req, _ := http.NewRequest("POST", "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9"))

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))

	assert.Check(t, is.Equal("/frob", resp.Header().Get("Location")))
	assert.Check(t, is.DeepEqual([]string{
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6=; Domain=15661444.ngrok.io; Expires=Thu, 01 Jan 1970 00:00:01 GMT",
		"ttt=" + test.expectedSessionCookie + "; " +
			"Path=/; Domain=15661444.ngrok.io; Max-Age=7200; HttpOnly; Secure"},
		resp.Header()["Set-Cookie"]))
}

func TestMiddlewareDefaultCookieDomainIPv4(t *testing.T) {
	test := NewMiddlewareTest(t)
	ipv4Loopback := net.IP{127, 0, 0, 1}

	sp := DefaultSessionProvider(Options{
		URL: mustParseURL("https://" + net.JoinHostPort(ipv4Loopback.String(), "54321")),
		Key: test.Key,
	})

	req, _ := http.NewRequest("GET", "/", nil)
	resp := httptest.NewRecorder()
	assert.Check(t, sp.CreateSession(resp, req, &saml.Assertion{}))

	assert.Check(t,
		strings.Contains(resp.Header().Get("Set-Cookie"), "Domain=127.0.0.1;"),
		"Cookie domain must not contain a port or the cookie cannot be set properly: %v", resp.Header().Get("Set-Cookie"))
}

func TestMiddlewareDefaultCookieDomainIPv6(t *testing.T) {
	t.Skip("fails") // TODO(ross): fix this test

	test := NewMiddlewareTest(t)

	sp := DefaultSessionProvider(Options{
		URL: mustParseURL("https://" + net.JoinHostPort(net.IPv6loopback.String(), "54321")),
		Key: test.Key,
	})

	req, _ := http.NewRequest("GET", "/", nil)
	resp := httptest.NewRecorder()
	assert.Check(t, sp.CreateSession(resp, req, &saml.Assertion{}))

	assert.Check(t,
		strings.Contains(resp.Header().Get("Set-Cookie"), "Domain=::1;"),
		"Cookie domain must not contain a port or the cookie cannot be set properly: %v", resp.Header().Get("Set-Cookie"))
}

func TestMiddlewareRejectsInvalidRelayState(t *testing.T) {
	test := NewMiddlewareTest(t)

	test.Middleware.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		assert.Check(t, is.Error(err, http.ErrNoCookie.Error()))
		http.Error(w, "forbidden", http.StatusTeapot)
	}

	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "ICIkJigqLC4wMjQ2ODo8PkBCREZISkxOUFJUVlhaXF5gYmRmaGpsbnBy")
	req, _ := http.NewRequest("POST", "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9"))

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusTeapot, resp.Code))
	assert.Check(t, is.Equal("", resp.Header().Get("Location")))
	assert.Check(t, is.Equal("", resp.Header().Get("Set-Cookie")))
}

func TestMiddlewareRejectsInvalidCookie(t *testing.T) {
	test := NewMiddlewareTest(t)

	test.Middleware.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		assert.Check(t, is.Error(err, "Authentication failed"))
		http.Error(w, "forbidden", http.StatusTeapot)
	}

	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
	req, _ := http.NewRequest("POST", "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("wrong"))

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusTeapot, resp.Code))
	assert.Check(t, is.Equal("", resp.Header().Get("Location")))
	assert.Check(t, is.Equal("", resp.Header().Get("Set-Cookie")))
}

func TestMiddlewareHandlesInvalidResponse(t *testing.T) {
	test := NewMiddlewareTest(t)
	v := &url.Values{}
	v.Set("SAMLResponse", "this is not a valid saml response")
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")

	req, _ := http.NewRequest("POST", "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("wrong"))

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)

	// note: it is important that when presented with an invalid request,
	// the ACS handles DOES NOT reveal detailed error information in the
	// HTTP response.
	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	respBody, _ := io.ReadAll(resp.Body)
	assert.Check(t, is.Equal("Forbidden\n", string(respBody)))
	assert.Check(t, is.Equal("", resp.Header().Get("Location")))
	assert.Check(t, is.Equal("", resp.Header().Get("Set-Cookie")))
}
