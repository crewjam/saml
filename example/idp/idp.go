package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idppending"
	"github.com/crewjam/saml/x/samlidp/idpslo"
)

// identityProvider is the example IdP: the samlidp.Config and
// idpslo.Service that speak SAML, and what x/samlidp leaves to the
// application: users, sessions, logins waiting for the user to log in,
// and logouts in progress.
type identityProvider struct {
	config  *samlidp.Config
	logout  *idpslo.Service
	pending *idppending.Tracker // AuthnRequests waiting for the user to log in, by the p parameter of /login
	users   map[string]*user
	sps     []string // the trusted SPs, for the portal
	secure  bool     // the IdP is served over https

	mu       sync.Mutex
	sessions map[string]*session        // by the value of the session cookie
	logouts  map[string]*logoutProgress // by RelayState
}

// user is a user of the IdP.
type user struct {
	ID, Name, Email, GivenName, Surname string
	Groups                              []string
	passwordHash                        []byte
}

// session is a user's IdP session, and the service providers it was used
// to log in to: its session participants, which single logout visits.
type session struct {
	id           string
	user         *user
	authTime     time.Time
	index        string // the SessionIndex given to SPs
	expires      time.Time
	participants []saml.SessionParticipant
}

const (
	sessionCookie   = "idp_session"
	loginCSRFCookie = "idp_login"
	sessionLifetime = 8 * time.Hour
	loginLifetime   = 10 * time.Minute
)

func newIdentityProvider(baseURL string, key *rsa.PrivateKey, cert *x509.Certificate, sps *remoteServiceProviders, users map[string]*user) (*identityProvider, error) {
	base := strings.TrimSuffix(baseURL, "/")
	config, err := samlidp.New(base+"/metadata", sps.lookup,
		samlidp.WithSigningKey(key, cert),
		samlidp.WithSSOURL(base+"/sso"),
		samlidp.WithNameIDFormats(saml.TransientNameIDFormat, saml.PersistentNameIDFormat, saml.EmailAddressNameIDFormat),
		samlidp.SignMetadata,
		idpslo.Endpoint(base+"/slo"))
	if err != nil {
		return nil, err
	}
	logout, err := idpslo.New(config)
	if err != nil {
		return nil, err
	}
	// The cookies of pending logins are encrypted with a key derived from
	// the IdP's own; an IdP served by several processes needs the same key
	// in each.
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	cookieKey, err := idppending.DeriveKey(der, "example IdP pending login")
	if err != nil {
		return nil, err
	}
	pending, err := idppending.New(config, cookieKey)
	if err != nil {
		return nil, err
	}
	return &identityProvider{
		config:   config,
		logout:   logout,
		pending:  pending,
		users:    users,
		sps:      sps.trusted,
		secure:   strings.HasPrefix(base, "https:"),
		sessions: map[string]*session{},
		logouts:  map[string]*logoutProgress{},
	}, nil
}

func (p *identityProvider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+p.config.MetadataPath(), p.config.ServeMetadata)
	mux.HandleFunc(p.config.SSOPath(), p.sso)
	mux.HandleFunc(p.logout.Path(), p.slo)
	mux.HandleFunc("GET /login", p.loginForm)
	mux.HandleFunc("POST /login", p.login)
	mux.HandleFunc("POST /idp-initiated", p.idpInitiated)
	mux.HandleFunc("POST /logout", p.startLogout)
	mux.HandleFunc("GET /{$}", p.portal)
	return mux
}

// exampleUsers returns the users of the example: alice and bob, whose
// password is hunter2.
func exampleUsers() map[string]*user {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return map[string]*user{
		"alice": {ID: "u-1", Name: "alice", Email: "alice@example.com", GivenName: "Alice", Surname: "Smith",
			Groups: []string{"Administrators", "Users"}, passwordHash: hash},
		"bob": {ID: "u-2", Name: "bob", Email: "bob@example.com", GivenName: "Bob", Surname: "Smith",
			Groups: []string{"Users"}, passwordHash: hash},
	}
}

// sso is the single sign-on service: it verifies the SP's AuthnRequest,
// and answers it at once if the user has a session, or after they log in.
func (p *identityProvider) sso(w http.ResponseWriter, r *http.Request) {
	req, err := p.config.ParseAuthnRequest(r.Context(), r)
	var status *saml.StatusError
	if errors.As(err, &status) && req != nil {
		p.sendError(w, r, req, status)
		return
	}
	if err != nil {
		log.Printf("refused an AuthnRequest: %v", err)
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	p.continueLogin(w, r, req)
}

// idpInitiated starts a login to the SP chosen on the portal. The
// session cookie is SameSite=Lax, so another site cannot make the browser
// post this form with it.
func (p *identityProvider) idpInitiated(w http.ResponseWriter, r *http.Request) {
	req, err := p.config.IDPInitiated(r.Context(), r.PostFormValue("sp"), "")
	if err != nil {
		log.Printf("cannot start an IdP-initiated login: %v", err)
		http.Error(w, "cannot log in to this service", http.StatusBadRequest)
		return
	}
	p.continueLogin(w, r, req)
}

// continueLogin answers req if the user has a session it can use, and
// otherwise keeps it and sends the user to log in.
func (p *identityProvider) continueLogin(w http.ResponseWriter, r *http.Request, req *samlidp.AuthnRequest) {
	if s := p.currentSession(r); s != nil && !req.ForceAuthn {
		p.answer(w, r, req, s)
		return
	}
	if req.IsPassive {
		p.sendError(w, r, req, &saml.StatusError{TopLevel: saml.StatusResponder, SecondLevel: saml.StatusNoPassive})
		return
	}
	handle, err := p.pending.Remember(w, r, req)
	if err != nil {
		log.Printf("cannot keep an AuthnRequest: %v", err)
		http.Error(w, "cannot log in to this service", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/login?"+url.Values{"p": {handle}}.Encode(), http.StatusFound)
}

// answer sends the Response to req for the user of s, and records the SP
// as a participant of s, for single logout.
func (p *identityProvider) answer(w http.ResponseWriter, r *http.Request, req *samlidp.AuthnRequest, s *session) {
	p.mu.Lock()
	u, authTime, index, expires := s.user, s.authTime, s.index, s.expires
	p.mu.Unlock()
	nameID, format := nameIDFor(req, u)
	msg, err := p.config.Response(r.Context(), req, samlidp.Subject{
		NameID:               nameID,
		NameIDFormat:         format,
		AuthnInstant:         authTime,
		AuthnContextClassRef: saml.AuthnContextPasswordProtectedTransport,
		SessionIndex:         index,
		SessionNotOnOrAfter:  expires,
		Attributes:           u.attributes(),
	})
	var status *saml.StatusError
	if errors.As(err, &status) {
		// The SP asked for what the IdP will not assert, such as another
		// user than the one logged in.
		p.sendError(w, r, req, status)
		return
	}
	if err != nil {
		log.Printf("cannot answer an AuthnRequest: %v", err)
		http.Error(w, "cannot log in to this service", http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	// One participant per SP: a new login replaces the previous one.
	s.participants = slices.DeleteFunc(s.participants, func(sp saml.SessionParticipant) bool {
		return sp.ServiceProviderID == msg.Participant.ServiceProviderID
	})
	s.participants = append(s.participants, *msg.Participant)
	p.mu.Unlock()
	msg.Write(w)
}

// nameIDFor returns the NameID that identifies u to the SP of req, in the format the SP asked for: their email address, a persistent
// identifier that is the same at each login but different for each SP, or
// by default a transient identifier, new at each login.
func nameIDFor(req *samlidp.AuthnRequest, u *user) (string, saml.NameIDFormat) {
	switch req.NameIDFormat {
	case saml.EmailAddressNameIDFormat:
		return u.Email, saml.EmailAddressNameIDFormat
	case saml.PersistentNameIDFormat:
		// A real IdP would keep a random identifier for each user and SP
		// in its database; a hash keeps the example free of state.
		sum := sha256.Sum256([]byte(req.ServiceProvider + "\x00" + u.ID))
		return base64.RawURLEncoding.EncodeToString(sum[:18]), saml.PersistentNameIDFormat
	default:
		return rand.Text(), saml.TransientNameIDFormat
	}
}

// attributes returns the attributes the IdP sends about u, named by their
// OIDs as the SAML V2.0 X.500/LDAP attribute profile has it.
func (u *user) attributes() []samlidp.Attribute {
	const uri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	attr := func(oid, friendly string, values ...string) samlidp.Attribute {
		return samlidp.Attribute{Name: "urn:oid:" + oid, NameFormat: uri, FriendlyName: friendly, Values: values}
	}
	return []samlidp.Attribute{
		attr("0.9.2342.19200300.100.1.1", "uid", u.Name),
		attr("0.9.2342.19200300.100.1.3", "mail", u.Email),
		attr("2.5.4.42", "givenName", u.GivenName),
		attr("2.5.4.4", "sn", u.Surname),
		attr("2.5.4.3", "cn", u.GivenName+" "+u.Surname),
		attr("1.3.6.1.4.1.5923.1.5.1.1", "isMemberOf", u.Groups...),
	}
}

// sendError sends the SP an error Response to req.
func (p *identityProvider) sendError(w http.ResponseWriter, r *http.Request, req *samlidp.AuthnRequest, status *saml.StatusError) {
	msg, err := p.config.ErrorResponse(r.Context(), req, status)
	if err != nil {
		log.Printf("cannot answer an AuthnRequest: %v", err)
		http.Error(w, "cannot answer the login request", http.StatusInternalServerError)
		return
	}
	msg.Write(w)
}

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html><head><title>Log in</title></head><body>
<h1>Log in</h1>
{{with .Error}}<p>{{.}}</p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="p" value="{{.Pending}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label>Username <input name="user" autocomplete="username"></label></p>
<p><label>Password <input name="password" type="password" autocomplete="current-password"></label></p>
<p><button>Log in</button></p>
</form>
<p>Try alice or bob, with the password hunter2.</p>
</body></html>`))

// loginForm shows the login page. The form carries a token that must match
// a cookie (double-submit), so that another site cannot log the browser in
// as someone else.
func (p *identityProvider) loginForm(w http.ResponseWriter, r *http.Request) {
	p.renderLogin(w, r.URL.Query().Get("p"), "")
}

func (p *identityProvider) renderLogin(w http.ResponseWriter, pending, message string) {
	csrf := rand.Text()
	p.setCookie(w, loginCSRFCookie, csrf, int(loginLifetime/time.Second))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loginTemplate.Execute(w, struct{ Pending, CSRF, Error string }{pending, csrf, message})
}

// dummyHash is compared against when the username is unknown, so that the
// time taken does not tell which usernames exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

// login checks the username and password, starts a session, and goes on
// with the pending login, if there is one.
func (p *identityProvider) login(w http.ResponseWriter, r *http.Request) {
	// ParseForm, unlike PostFormValue, does not read multipart bodies.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostForm.Get("csrf"))) != 1 {
		http.Error(w, "the login form has expired; go back and try again", http.StatusForbidden)
		return
	}
	pendingKey := r.PostForm.Get("p")
	u, ok := p.users[r.PostForm.Get("user")]
	hash := dummyHash
	if ok {
		hash = u.passwordHash
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(r.PostForm.Get("password"))) != nil || !ok {
		p.renderLogin(w, pendingKey, "Wrong username or password.")
		return
	}
	p.deleteCookie(w, loginCSRFCookie)

	s := p.startSession(w, r, u)
	if pendingKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// Take clears the request, so that it is answered once.
	req, err := p.pending.Take(w, r, pendingKey)
	if err != nil {
		http.Error(w, "the login request has expired; go back to the service and try again", http.StatusBadRequest)
		return
	}
	p.answer(w, r, req, s)
}

// startSession starts a session for u, or, if the browser already has one
// for u, renews its authentication time and keeps its participants.
func (p *identityProvider) startSession(w http.ResponseWriter, r *http.Request, u *user) *session {
	now := time.Now()
	if s := p.currentSession(r); s != nil {
		if s.user == u {
			p.mu.Lock()
			s.authTime = now
			p.mu.Unlock()
			return s
		}
		p.endSession(w, s)
	}
	s := &session{id: rand.Text(), user: u, authTime: now, index: rand.Text(), expires: now.Add(sessionLifetime)}
	p.mu.Lock()
	p.sessions[s.id] = s
	p.mu.Unlock()
	p.setCookie(w, sessionCookie, s.id, int(sessionLifetime/time.Second))
	return s
}

// currentSession returns the session of the browser of r, or nil.
func (p *identityProvider) currentSession(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[c.Value]
	if s == nil || time.Now().After(s.expires) {
		delete(p.sessions, c.Value)
		return nil
	}
	return s
}

// endSession ends s, and expires the session cookie of the browser.
func (p *identityProvider) endSession(w http.ResponseWriter, s *session) {
	p.mu.Lock()
	delete(p.sessions, s.id)
	p.mu.Unlock()
	p.deleteCookie(w, sessionCookie)
}

// setCookie sets a cookie for the IdP. It is SameSite=Lax: the browser
// sends it when it is sent to the IdP with a redirect, as with the
// HTTP-Redirect binding, but not with a form that another site posts. So
// an SP that sends its AuthnRequests with the HTTP-POST binding always
// gets the login page; an IdP served over https could make the session
// cookie SameSite=None to avoid that.
func (p *identityProvider) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	// Secure is off only when the IdP is served over plain http, as for
	// local development.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: see above
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: p.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (p *identityProvider) deleteCookie(w http.ResponseWriter, name string) {
	p.setCookie(w, name, "", -1)
}

var portalTemplate = template.Must(template.New("portal").Parse(`<!DOCTYPE html>
<html><head><title>Example IdP</title></head><body>
<h1>Example IdP</h1>
{{if .User}}
<p>Logged in as {{.User.Name}} ({{.User.Email}}).</p>
{{with .Participants}}<p>Logged in to:</p><ul>{{range .}}<li>{{.ServiceProviderID}}</li>{{end}}</ul>{{end}}
<form method="post" action="/logout"><button>Log out of everything</button></form>
{{else}}
<p>Not logged in. <a href="/login">Log in</a></p>
{{end}}
<h2>Services</h2>
<ul>{{range .ServiceProviders}}
<li><form method="post" action="/idp-initiated"><input type="hidden" name="sp" value="{{.}}">{{.}} <button>Log in</button></form></li>
{{end}}</ul>
</body></html>`))

// portal lists the services the user can log in to from the IdP.
func (p *identityProvider) portal(w http.ResponseWriter, r *http.Request) {
	data := struct {
		User             *user
		Participants     []saml.SessionParticipant
		ServiceProviders []string
	}{ServiceProviders: p.sps}
	if s := p.currentSession(r); s != nil {
		p.mu.Lock()
		data.User, data.Participants = s.user, slices.Clone(s.participants)
		p.mu.Unlock()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = portalTemplate.Execute(w, data)
}
