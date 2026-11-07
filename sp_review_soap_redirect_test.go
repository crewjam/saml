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
	assert.Check(t, errors.Is(err, ErrInsecureSOAPEndpoint), "%v", err)
	assert.Check(t, is.Equal(int32(0), plainHits.Load()))
}

// A redirect between https locations is still followed with a caller's
// client, and the caller's own redirect policy still applies.
func TestSOAPHTTPClientKeepsCallerRedirectPolicy(t *testing.T) {
	var target *httptest.Server
	target = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, target.URL+"/end", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte("<ok/>"))
	}))
	defer target.Close()

	client := target.Client()
	sp := &ServiceProvider{HTTPClient: client}
	body, err := sp.postSOAP(context.Background(), target.URL+"/start", etree.NewElement("x"), 1024)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("<ok/>", string(body)))

	stop := errors.New("caller says stop")
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return stop }
	_, err = sp.postSOAP(context.Background(), target.URL+"/start", etree.NewElement("x"), 1024)
	assert.Check(t, errors.Is(err, stop), "%v", err)
}

func TestSOAPHTTPClientDefault(t *testing.T) {
	c := soapHTTPClient(nil, false)
	assert.Check(t, c == defaultSOAPHTTPClient)
	assert.Check(t, c.Timeout > 0)
	assert.Check(t, c.CheckRedirect != nil)
}
