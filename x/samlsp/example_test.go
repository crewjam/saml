package samlsp_test

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/crewjam/saml/x/samlsp"
)

// pendingRequests is a toy store of pending AuthnRequest IDs by RelayState.
// A real application would keep them in a signed, short-lived cookie or in
// its session store.
type pendingRequests struct {
	mu  sync.Mutex
	ids map[string]string
}

func (p *pendingRequests) put(relayState, id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ids[relayState] = id
}

func (p *pendingRequests) take(relayState string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := p.ids[relayState]
	delete(p.ids, relayState)
	return id
}

func Example() {
	var (
		key  *rsa.PrivateKey   // the SP's key
		cert *x509.Certificate // and certificate
	)

	config, err := samlsp.New(
		samlsp.RemoteMetadata("https://idp.example.com/metadata"),
		"https://sp.example.com/saml/metadata", // the ACS is at https://sp.example.com/saml/acs
		samlsp.WithKey(key, cert),
	)
	if err != nil {
		log.Fatal(err)
	}
	pending := &pendingRequests{ids: map[string]string{}}

	http.HandleFunc("/saml/metadata", config.ServeMetadata)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		relayState := randomString()
		req, err := config.AuthnRequest(r.Context(), relayState)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		pending.put(relayState, req.ID)
		req.Write(w)
	})

	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		requestID := pending.take(r.FormValue("RelayState"))
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(requestID))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}

		var user struct {
			Email  string   `saml:"mail"`
			Groups []string `saml:"memberOf"`
		}
		if err := assertion.DecodeAttributes(&user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Start the application's own session here.
		_, _ = fmt.Fprintf(w, "hello %s (%s)", assertion.Subject, strings.Join(user.Groups, ", "))
	})
}

func randomString() string { return "relay-state" }
