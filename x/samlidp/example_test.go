package samlidp_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
)

// user is a user of the application, as its own session knows them.
type user struct {
	ID, Email string
	LoginTime time.Time
}

// pendingLogins keeps AuthnRequests while their users log in. A real
// application keeps them in its session store.
type pendingLogins struct {
	mu sync.Mutex
	m  map[string]*samlidp.AuthnRequest
}

func (p *pendingLogins) put(req *samlidp.AuthnRequest) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := rand.Text()
	p.m[id] = req
	return id
}

func (p *pendingLogins) take(id string) *samlidp.AuthnRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	req := p.m[id]
	delete(p.m, id)
	return req
}

// This example serves an IdP whose users log in with the application's
// own login page. The AuthnRequest waits server-side, under a random key
// in a cookie, while the user logs in.
func Example() {
	var (
		key        crypto.Signer
		cert       *x509.Certificate
		spMetadata []*saml.EntityDescriptor
		// currentUser returns the user logged in to the application, or nil.
		currentUser func(r *http.Request) *user
	)

	config, err := samlidp.New("https://idp.example.com/saml/metadata",
		samlidp.StaticServiceProviders(spMetadata...),
		samlidp.WithSigningKey(key, cert),
		samlidp.WithNameIDFormats(saml.PersistentNameIDFormat))
	if err != nil {
		log.Print(err)
		return
	}
	pending := &pendingLogins{m: map[string]*samlidp.AuthnRequest{}}

	// answer sends the Response for req, once the user is logged in.
	answer := func(w http.ResponseWriter, r *http.Request, req *samlidp.AuthnRequest, u *user) {
		msg, err := config.Response(r.Context(), req, samlidp.Subject{
			NameID:       u.ID,
			NameIDFormat: saml.PersistentNameIDFormat,
			AuthnInstant: u.LoginTime,
			Attributes: []samlidp.Attribute{{
				Name:         "urn:oid:0.9.2342.19200300.100.1.3",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				FriendlyName: "mail",
				Values:       []string{u.Email},
			}},
		})
		var status *saml.StatusError
		if errors.As(err, &status) {
			// The SP asked for what the IdP will not assert.
			msg, err = config.ErrorResponse(r.Context(), req, status)
		}
		if err != nil {
			http.Error(w, "cannot answer the login request", http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	}

	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)

	http.HandleFunc(config.SSOPath(), func(w http.ResponseWriter, r *http.Request) {
		req, err := config.ParseAuthnRequest(r.Context(), r)
		var status *saml.StatusError
		if errors.As(err, &status) && req != nil {
			msg, err := config.ErrorResponse(r.Context(), req, status)
			if err != nil {
				http.Error(w, "cannot answer the login request", http.StatusInternalServerError)
				return
			}
			msg.Write(w)
			return
		}
		if err != nil {
			http.Error(w, "invalid login request", http.StatusBadRequest)
			return
		}

		u := currentUser(r)
		if u != nil && !req.ForceAuthn {
			answer(w, r, req, u)
			return
		}
		if req.IsPassive {
			msg, err := config.ErrorResponse(r.Context(), req, &saml.StatusError{
				TopLevel: saml.StatusResponder, SecondLevel: saml.StatusNoPassive,
			})
			if err != nil {
				http.Error(w, "cannot answer the login request", http.StatusInternalServerError)
				return
			}
			msg.Write(w)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "saml_login", Value: pending.put(req), Path: "/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/login?next=/saml/continue", http.StatusFound)
	})

	// The login page sends the user here once they have logged in.
	http.HandleFunc("/saml/continue", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("saml_login")
		if err != nil {
			http.Error(w, "no login in progress", http.StatusBadRequest)
			return
		}
		req := pending.take(c.Value)
		u := currentUser(r)
		if req == nil || u == nil {
			http.Error(w, "no login in progress", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "saml_login", Path: "/", MaxAge: -1})
		answer(w, r, req, u)
	})
}
