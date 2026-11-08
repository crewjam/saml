package saml

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A SOAP message must not be re-sent in the clear because an https
// endpoint redirected to an http one.
func TestSOAPHTTPClientRefusesDowngradeRedirect(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	sp := &ServiceProvider{HTTPClient: secure.Client()}
	_, err := sp.postSOAP(context.Background(), secure.URL, etree.NewElement("x"), 1024)
	assert.Check(t, errors.Is(err, errSOAPRedirect), "%v", err)
	assert.Check(t, is.Equal(int32(0), plainHits.Load()))
}

// The SOAP binding has no redirects (saml-bindings §3.2): even between
// https locations, and even with a caller's client whose own policy would
// follow it, a redirect is not followed, so that neither the message nor
// the client's TLS certificate goes to a location the metadata never named.
func TestSOAPHTTPClientNeverFollowsRedirects(t *testing.T) {
	var endHits atomic.Int32
	var target *httptest.Server
	target = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, target.URL+"/end", http.StatusTemporaryRedirect)
			return
		}
		endHits.Add(1)
		_, _ = w.Write([]byte("<ok/>"))
	}))
	defer target.Close()

	client := target.Client()
	var callerPolicyCalled bool
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		callerPolicyCalled = true
		return nil // would follow
	}
	sp := &ServiceProvider{HTTPClient: client}
	_, err := sp.postSOAP(context.Background(), target.URL+"/start", etree.NewElement("x"), 1024)
	assert.Check(t, errors.Is(err, errSOAPRedirect), "%v", err)
	assert.Check(t, is.Equal(int32(0), endHits.Load()))
	assert.Check(t, !callerPolicyCalled)
	// The caller's client is not changed.
	assert.Check(t, client.CheckRedirect != nil)
	assert.NilError(t, client.CheckRedirect(nil, nil))

	// Artifact resolution, which builds its own request, refuses it too.
	e := spcovSetup(t)
	e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = target.URL + "/start"
	e.sp.HTTPClient = client
	_, err = e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
	assert.Check(t, errors.Is(err, ErrArtifactResolution), "%v", err)
	assert.Check(t, errors.Is(spcovPrivateErr(t, err), errSOAPRedirect), "%v", err)
	assert.Check(t, is.Equal(int32(0), endHits.Load()))

	// And so does the IdP's client for SOAP logout.
	idp := &IdentityProvider{HTTPClient: client}
	_, err = postSOAPMessage(context.Background(), idp.httpClient(), target.URL+"/start", etree.NewElement("x"), 1024)
	assert.Check(t, errors.Is(err, errSOAPRedirect), "%v", err)
	assert.Check(t, is.Equal(int32(0), endHits.Load()))
}

func TestSOAPHTTPClientDefault(t *testing.T) {
	c := soapHTTPClient(nil)
	assert.Check(t, c == defaultSOAPHTTPClient)
	assert.Check(t, c.Timeout > 0)
	assert.Check(t, c.CheckRedirect != nil)
	req, err := http.NewRequest(http.MethodPost, "https://elsewhere.example.com/", nil)
	assert.NilError(t, err)
	assert.Check(t, errors.Is(c.CheckRedirect(req, nil), errSOAPRedirect))
}
