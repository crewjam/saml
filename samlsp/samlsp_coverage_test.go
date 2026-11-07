package samlsp

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml"
)

// covSaveGlobals records the package globals mutated by NewMiddlewareTest and
// restores them when the test finishes.
func covSaveGlobals(t *testing.T) {
	t.Helper()
	timeNow, clock, randReader := saml.TimeNow, saml.Clock, saml.RandReader
	t.Cleanup(func() {
		saml.TimeNow, saml.Clock, saml.RandReader = timeNow, clock, randReader
	})
}

// covNewMiddlewareTest wraps NewMiddlewareTest, restoring globals afterwards.
func covNewMiddlewareTest(t *testing.T) *MiddlewareTest {
	t.Helper()
	covSaveGlobals(t)
	return NewMiddlewareTest(t)
}

func covRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	return mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
}

func covECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.Assert(t, err)
	return key
}

type covErrReader struct{}

func (covErrReader) Read([]byte) (int, error) { return 0, errors.New("cov: read failed") }

type covBody struct {
	io.Reader
	closeErr error
}

func (b covBody) Close() error { return b.closeErr }

// --- error.go ---

func TestCovDefaultOnError(t *testing.T) {
	for _, err := range []error{
		&saml.InvalidResponseError{PrivateErr: errors.New("secret detail"), Response: "resp", Now: time.Unix(0, 0)},
		errors.New("plain error"),
	} {
		rec := httptest.NewRecorder()
		DefaultOnError(rec, httptest.NewRequest(http.MethodGet, "/", nil), err)
		assert.Check(t, is.Equal(http.StatusForbidden, rec.Code))
		assert.Check(t, is.Equal("Forbidden\n", rec.Body.String()))
		assert.Check(t, !strings.Contains(rec.Body.String(), "secret"))
	}
}

// --- fetch_metadata.go ---

func TestCovParseMetadata(t *testing.T) {
	t.Run("not an entity descriptor", func(t *testing.T) {
		_, err := ParseMetadata([]byte(`<Foo/>`))
		assert.Check(t, is.ErrorContains(err, "expected element type <EntityDescriptor> but have <Foo>"))
	})
	t.Run("invalid entities descriptor", func(t *testing.T) {
		_, err := ParseMetadata([]byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="not-a-time"/>`))
		assert.Check(t, err != nil)
	})
	t.Run("entities without idp", func(t *testing.T) {
		_, err := ParseMetadata([]byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
			`<EntityDescriptor entityID="https://sp.example.com/"></EntityDescriptor></EntitiesDescriptor>`))
		assert.Check(t, is.Error(err, "no entity found with IDPSSODescriptor"))
	})
	t.Run("entity descriptor", func(t *testing.T) {
		ed, err := ParseMetadata(golden.Get(t, "idp_metadata.xml"))
		assert.Assert(t, err)
		assert.Check(t, is.Equal("https://idp.testshib.org/idp/shibboleth", ed.EntityID))
	})
}

func TestCovFetchMetadata(t *testing.T) {
	metadata := golden.Get(t, "idp_metadata.xml")
	ctx := context.Background()

	t.Run("bad url", func(t *testing.T) {
		_, err := FetchMetadata(ctx, http.DefaultClient, url.URL{Scheme: "ht tp", Host: "idp.example.com"})
		assert.Check(t, err != nil)
	})

	t.Run("transport error", func(t *testing.T) {
		client := &http.Client{Transport: mockTransport(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("cov: dial failed")
		})}
		_, err := FetchMetadata(ctx, client, mustParseURL("http://idp.example.com/metadata"))
		assert.Check(t, is.ErrorContains(err, "cov: dial failed"))
	})

	t.Run("status code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusNotFound)
		}))
		defer srv.Close()
		_, err := FetchMetadata(ctx, srv.Client(), mustParseURL(srv.URL+"/metadata"))
		assert.Check(t, is.Error(err, "failed to fetch metadata: unexpected status code 404"))
	})

	t.Run("read error and close error", func(t *testing.T) {
		client := &http.Client{Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Request:    req,
				Body:       covBody{Reader: covErrReader{}, closeErr: errors.New("cov: close failed")},
			}, nil
		})}
		_, err := FetchMetadata(ctx, client, mustParseURL("http://idp.example.com/metadata"))
		assert.Check(t, is.ErrorContains(err, "cov: read failed"))
	})

	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(metadata)
		}))
		defer srv.Close()
		ed, err := FetchMetadata(ctx, srv.Client(), mustParseURL(srv.URL+"/metadata"))
		assert.Assert(t, err)
		assert.Check(t, is.Equal("https://idp.testshib.org/idp/shibboleth", ed.EntityID))
	})
}

// --- new.go ---

func TestCovGetDefaultSigningMethod(t *testing.T) {
	assert.Check(t, is.Equal(jwt.SigningMethodRS256, getDefaultSigningMethod(nil)))
	assert.Check(t, is.Equal(jwt.SigningMethodRS256, getDefaultSigningMethod(covRSAKey(t))))
	assert.Check(t, is.Equal(jwt.SigningMethodES256, getDefaultSigningMethod(covECDSAKey(t, elliptic.P256()))))
	assert.Check(t, is.Equal(jwt.SigningMethodES384, getDefaultSigningMethod(covECDSAKey(t, elliptic.P384()))))
	assert.Check(t, is.Equal(jwt.SigningMethodES512, getDefaultSigningMethod(covECDSAKey(t, elliptic.P521()))))
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	assert.Assert(t, err)
	assert.Check(t, is.Equal(jwt.SigningMethodRS256, getDefaultSigningMethod(edKey)))
}

// TestCovSessionWithECDSAKeys checks that sessions can be created and read back
// with every supported ECDSA curve. Before the fix, ES256 was used for every
// ECDSA key, so P-384 and P-521 keys failed to sign any session.
func TestCovSessionWithECDSAKeys(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			codec := DefaultSessionCodec(Options{URL: mustParseURL("https://sp.example.com/"), Key: covECDSAKey(t, curve)})
			s, err := codec.New(&saml.Assertion{})
			assert.Assert(t, err)
			token, err := codec.Encode(s)
			assert.Assert(t, err)
			_, err = codec.Decode(token)
			assert.Check(t, err)
		})
	}
}

func TestCovDefaultSigningMethodForKey(t *testing.T) {
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, defaultSigningMethodForKey(covRSAKey(t))))
	assert.Check(t, is.Equal(dsig.ECDSASHA256SignatureMethod, defaultSigningMethodForKey(covECDSAKey(t, elliptic.P256()))))
	assert.Check(t, is.Equal("", defaultSigningMethodForKey(nil)))
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	assert.Assert(t, err)
	assert.Check(t, is.Panics(func() { defaultSigningMethodForKey(edKey) }))
}

func TestCovDefaultServiceProvider(t *testing.T) {
	key := covRSAKey(t)
	sp := DefaultServiceProvider(Options{
		URL:            mustParseURL("https://sp.example.com/app/"),
		Key:            key,
		ForceAuthn:     true,
		SignRequest:    true,
		LogoutBindings: []string{saml.HTTPRedirectBinding},
	})
	assert.Assert(t, sp.ForceAuthn != nil)
	assert.Check(t, *sp.ForceAuthn)
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, sp.SignatureMethod))
	assert.Check(t, is.DeepEqual([]string{saml.HTTPRedirectBinding}, sp.LogoutBindings))
	assert.Check(t, is.Equal("https://sp.example.com/app/saml/acs", sp.AcsURL.String()))
	assert.Check(t, is.Equal("/", sp.DefaultRedirectURI))

	sp = DefaultServiceProvider(Options{URL: mustParseURL("https://sp.example.com/"), Key: key, DefaultRedirectURI: "/home"})
	assert.Check(t, is.Nil(sp.ForceAuthn))
	assert.Check(t, is.Equal("", sp.SignatureMethod))
	assert.Check(t, is.Equal("/home", sp.DefaultRedirectURI))
	assert.Check(t, is.DeepEqual([]string{saml.HTTPPostBinding}, sp.LogoutBindings))
	assert.Check(t, is.Nil(sp.AssertionConsumerServiceBindings))
	assert.Check(t, !sp.IgnoreCertificateExpiry)

	sp = DefaultServiceProvider(Options{URL: mustParseURL("https://sp.example.com/"), Key: key, IgnoreCertificateExpiry: true})
	assert.Check(t, sp.IgnoreCertificateExpiry)

	sp = DefaultServiceProvider(Options{
		URL:                              mustParseURL("https://sp.example.com/"),
		Key:                              key,
		AssertionConsumerServiceBindings: []string{saml.HTTPPostBinding},
	})
	assert.Check(t, is.DeepEqual([]string{saml.HTTPPostBinding}, sp.AssertionConsumerServiceBindings))
	acs := sp.Metadata().SPSSODescriptors[0].AssertionConsumerServices
	assert.Check(t, is.Len(acs, 1))
	assert.Check(t, is.Equal(saml.HTTPPostBinding, acs[0].Binding))
}

func TestCovNewAssertionConsumerServiceBindings(t *testing.T) {
	url := mustParseURL("https://sp.example.com/")
	key := covRSAKey(t)

	// artifact response requested but artifact binding not advertised
	_, err := New(Options{URL: url, Key: key, UseArtifactResponse: true,
		AssertionConsumerServiceBindings: []string{saml.HTTPPostBinding}})
	assert.Check(t, is.ErrorContains(err, saml.HTTPArtifactBinding))

	// POST response requested but POST binding not advertised
	_, err = New(Options{URL: url, Key: key,
		AssertionConsumerServiceBindings: []string{saml.HTTPArtifactBinding}})
	assert.Check(t, is.ErrorContains(err, saml.HTTPPostBinding))

	// consistent configurations
	_, err = New(Options{URL: url, Key: key,
		AssertionConsumerServiceBindings: []string{saml.HTTPPostBinding}})
	assert.Check(t, err)
	_, err = New(Options{URL: url, Key: key, UseArtifactResponse: true,
		AssertionConsumerServiceBindings: []string{saml.HTTPArtifactBinding}})
	assert.Check(t, err)
}

func TestCovNew(t *testing.T) {
	m, err := New(Options{URL: mustParseURL("https://sp.example.com/"), Key: covRSAKey(t), UseArtifactResponse: true})
	assert.Assert(t, err)
	assert.Check(t, is.Equal(saml.HTTPArtifactBinding, m.ResponseBinding))
	tracker := m.RequestTracker.(CookieRequestTracker)
	assert.Check(t, tracker.ServiceProvider == &m.ServiceProvider)

	m, err = New(Options{URL: mustParseURL("https://sp.example.com/"), Key: covRSAKey(t)})
	assert.Assert(t, err)
	assert.Check(t, is.Equal(saml.HTTPPostBinding, m.ResponseBinding))
	provider := m.Session.(CookieSessionProvider)
	assert.Check(t, provider.HTTPOnly)
	assert.Check(t, provider.Secure)
	assert.Check(t, is.Equal("sp.example.com", provider.Domain))
}

// --- util.go ---

func TestCovRandomBytesPanics(t *testing.T) {
	covSaveGlobals(t)
	saml.RandReader = covErrReader{}
	assert.Check(t, is.Panics(func() { randomBytes(8) }))
}
