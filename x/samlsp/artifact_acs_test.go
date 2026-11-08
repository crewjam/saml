package samlsp_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // type 0x0004 artifacts name their source by SHA-1
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// artifactFixture is an IdP whose ArtifactResolutionService counts the
// ArtifactResolves it is sent, and a type 0x0004 artifact from it.
type artifactFixture struct {
	ti       *testIDP
	idp      samlsp.MetadataFunc
	resolves atomic.Int32
	server   *httptest.Server
	artifact string
}

func newArtifactFixture(t *testing.T) *artifactFixture {
	f := &artifactFixture{ti: newTestIDP(t)}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.resolves.Add(1)
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	t.Cleanup(f.server.Close)
	f.idp = func(context.Context) (*saml.EntityDescriptor, error) {
		md := f.ti.idp.Metadata()
		md.IDPSSODescriptors[0].SSODescriptor.ArtifactResolutionServices = []saml.IndexedEndpoint{
			{Binding: saml.SOAPBinding, Location: f.server.URL, Index: 1},
		}
		return md, nil
	}
	source := sha1.Sum([]byte(f.ti.idp.MetadataURL.String())) //nolint:gosec // see the import
	art := append([]byte{0, 4, 0, 1}, source[:]...)
	art = append(art, make([]byte, 20)...)
	f.artifact = base64.StdEncoding.EncodeToString(art)
	return f
}

func (f *artifactFixture) config(t *testing.T, opts ...samlsp.Option) *samlsp.Config {
	t.Helper()
	opts = append(opts, samlsp.WithHTTPClient(f.server.Client()))
	return newTestConfigWithIDP(t, f.ti, f.idp, opts...)
}

func (f *artifactFixture) acsRequest(method string) *http.Request {
	v := url.Values{"SAMLart": {f.artifact}, "RelayState": {"s"}}
	if method == http.MethodGet {
		return httptest.NewRequest(http.MethodGet, spACSURL+"?"+v.Encode(), nil)
	}
	r := httptest.NewRequest(http.MethodPost, spACSURL, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// Without AcceptArtifactResponses, the SP metadata lists the ACS with
// HTTP-POST only, and ParseResponse refuses a SAMLart, in the query or the
// form, without sending the IdP an ArtifactResolve.
func TestArtifactACSOptIn(t *testing.T) {
	f := newArtifactFixture(t)
	cfg := f.config(t)
	for _, acs := range cfg.Metadata(t.Context()).SPSSODescriptors[0].AssertionConsumerServices {
		if acs.Binding == saml.HTTPArtifactBinding {
			t.Error("the SP metadata lists the HTTP-Artifact ACS by default")
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		_, err := cfg.ParseResponse(t.Context(), f.acsRequest(method), samlsp.WithRequestID("id-1"))
		if !errors.Is(err, samlsp.ErrArtifactNotAccepted) {
			t.Errorf("%s SAMLart: %v, want ErrArtifactNotAccepted", method, err)
		}
	}
	if n := f.resolves.Load(); n != 0 {
		t.Errorf("the SP sent %d ArtifactResolves", n)
	}

	// With the option, the ACS is listed and the artifact resolved.
	cfg = f.config(t, samlsp.AcceptArtifactResponses)
	bindings := make([]string, 0, 2)
	for _, acs := range cfg.Metadata(t.Context()).SPSSODescriptors[0].AssertionConsumerServices {
		bindings = append(bindings, acs.Binding)
	}
	if !slices.Equal(bindings, []string{saml.HTTPPostBinding, saml.HTTPArtifactBinding}) {
		t.Errorf("ACS bindings = %v", bindings)
	}
	if _, err := cfg.ParseResponse(t.Context(), f.acsRequest(http.MethodPost), samlsp.WithRequestID("id-1")); errors.Is(err, samlsp.ErrArtifactNotAccepted) || err == nil {
		t.Errorf("SAMLart with AcceptArtifactResponses: %v", err)
	}
	if n := f.resolves.Load(); n != 1 {
		t.Errorf("the SP sent %d ArtifactResolves, want 1", n)
	}

	// AssertionConsumerServiceBindings, set with WithServiceProvider,
	// decides both ways.
	cfg = f.config(t, samlsp.AcceptArtifactResponses, samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.AssertionConsumerServiceBindings = []string{saml.HTTPPostBinding}
	}))
	if _, err := cfg.ParseResponse(t.Context(), f.acsRequest(http.MethodPost), samlsp.WithRequestID("id-1")); !errors.Is(err, samlsp.ErrArtifactNotAccepted) {
		t.Errorf("SAMLart with the bindings set to HTTP-POST: %v", err)
	}
	cfg = f.config(t, samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.AssertionConsumerServiceBindings = []string{saml.HTTPArtifactBinding}
	}))
	if _, err := cfg.ParseResponse(t.Context(), f.acsRequest(http.MethodPost), samlsp.WithRequestID("id-1")); errors.Is(err, samlsp.ErrArtifactNotAccepted) {
		t.Errorf("SAMLart with the bindings set to HTTP-Artifact: %v", err)
	}
}
