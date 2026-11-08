package main

import (
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/attrname"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/saferedirect"
	"github.com/crewjam/saml/x/samlsp/slo"
)

// App is a multi-tenant service provider, in the manner of Supabase Auth:
// each tenant registers its own IdP, and users log in through the IdP of
// their email domain. One samlsp.Config serves every tenant; each call
// names the tenant's IdP. Logins and logouts in progress, the replay
// record and the sessions are kept in the database, so any server can
// handle any step.
type App struct {
	db     *DB
	config *samlsp.Config
	logout *slo.Service
	secure bool // served over https, so cookies are Secure
}

const (
	sessionCookie = "session"
	// flowCookie ties a login to the browser that started it, so that a
	// Response for an attacker's own login cannot be posted from a
	// victim's browser (login CSRF).
	flowCookie      = "saml_flow"
	sessionLifetime = 8 * time.Hour
)

// Handler returns the App's HTTP handler.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("POST /admin/providers", a.addProvider)
	mux.HandleFunc("GET /sso", a.startLogin)
	mux.HandleFunc(a.config.MetadataPath(), a.config.ServeMetadata)
	mux.HandleFunc(a.config.ACSPath(), a.acs)
	mux.HandleFunc("POST /logout", a.startLogout)
	mux.HandleFunc(a.logout.Path(), a.slo)
	return mux
}

// idp names p's IdP for a samlsp call.
func idp(p *Provider) samlsp.IdentityProviderOption {
	return samlsp.WithIdentityProvider(p.IdentityProvider())
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if s, ok := a.session(r); ok {
		_, _ = fmt.Fprintf(w, `<p>Hello, %s!</p><form method="post" action="/logout"><button>Log out</button></form>`,
			html.EscapeString(s.Email))
		return
	}
	_, _ = fmt.Fprint(w, `<form action="/sso"><input name="domain" placeholder="example.com"><button>Log in with SSO</button></form>`)
}

// addProvider registers a tenant's IdP from an uploaded metadata document.
// A real application would check that the caller administers the tenant.
func (a *App) addProvider(w http.ResponseWriter, r *http.Request) {
	metadataXML := []byte(r.FormValue("metadata"))
	md, err := samlsp.ParseMetadata(metadataXML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p := &Provider{
		Domain:            r.FormValue("domain"),
		EntityID:          md.EntityID,
		MetadataXML:       metadataXML,
		AllowIDPInitiated: r.FormValue("allow_idp_initiated") == "true",
	}
	if err := a.db.AddProvider(p); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintln(w, p.ID)
}

// startLogin sends the browser to the IdP of the domain's tenant.
func (a *App) startLogin(w http.ResponseWriter, r *http.Request) {
	p, err := a.db.ProviderByDomain(r.FormValue("domain"))
	if err != nil {
		http.Error(w, "no SSO provider for this domain", http.StatusNotFound)
		return
	}
	relayState := newID()
	msg, err := a.config.AuthnRequest(r.Context(), relayState, idp(p))
	if err != nil {
		log.Printf("AuthnRequest for provider %s: %v", p.ID, err)
		http.Error(w, "cannot start SSO", http.StatusBadGateway)
		return
	}
	a.db.AddRelayState(RelayState{
		ID:         relayState,
		ProviderID: p.ID,
		RequestID:  msg.ID,
		RedirectTo: r.FormValue("redirect_to"),
		CreatedAt:  time.Now(),
	})
	a.setCookie(w, flowCookie, relayState, a.config.ACSPath(), int(relayStateLifetime/time.Second), true)
	msg.Write(w)
}

// acs verifies a Response: one to a login this browser started, found by
// its RelayState, or an unsolicited one, whose IdP is found by its Issuer.
func (a *App) acs(w http.ResponseWriter, r *http.Request) {
	opts, p, redirectTo, err := a.loginInProgress(w, r)
	if err != nil {
		log.Printf("ACS: %v", err)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	assertion, err := a.config.ParseResponse(r.Context(), r, append(opts, idp(p))...)
	if err != nil {
		// errors.Is(err, saml.ErrAssertionReplayed) for a replay.
		log.Printf("ACS, provider %s: %v (%v)", p.ID, err, errors.Unwrap(err))
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}

	email := assertion.Attributes.Get(attrname.Mail)
	if email == "" && assertion.NameID.Format == string(saml.EmailAddressNameIDFormat) {
		email = assertion.Subject
	}
	if !strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(p.Domain)) {
		// A tenant's IdP vouches only for its own domain.
		log.Printf("ACS, provider %s: email %q is not in its domain", p.ID, email) //nolint:gosec // G706: %q quotes the email
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}

	expires := time.Now().Add(sessionLifetime)
	if !assertion.SessionNotOnOrAfter.IsZero() && assertion.SessionNotOnOrAfter.Before(expires) {
		expires = assertion.SessionNotOnOrAfter
	}
	s := Session{
		ID:             newID(),
		ProviderID:     p.ID,
		NameID:         assertion.NameID,
		SessionIndexes: assertion.SessionIndexes,
		Email:          email,
		ExpiresAt:      expires,
	}
	a.db.AddSession(s)
	a.setCookie(w, sessionCookie, s.ID, "/", int(time.Until(expires)/time.Second), false)

	if !isLocalPath(redirectTo) {
		redirectTo = "/"
	}
	http.Redirect(w, r, redirectTo, http.StatusFound) //nolint:gosec // G710: redirectTo passed isLocalPath
}

// loginInProgress returns the options that ParseResponse needs for the
// Response in r, its provider, and where to go after login.
func (a *App) loginInProgress(w http.ResponseWriter, r *http.Request) ([]samlsp.ResponseOption, *Provider, string, error) {
	relayState := r.FormValue("RelayState")
	if rs, err := a.db.TakeRelayState(relayState); err == nil {
		a.setCookie(w, flowCookie, "", a.config.ACSPath(), -1, true)
		if c, err := r.Cookie(flowCookie); err != nil || c.Value != relayState {
			return nil, nil, "", errors.New("the login was started in another browser")
		}
		p, err := a.db.ProviderByID(rs.ProviderID)
		if err != nil {
			return nil, nil, "", err
		}
		return []samlsp.ResponseOption{samlsp.WithRequestID(rs.RequestID)}, p, rs.RedirectTo, nil
	}

	// Not a login of ours: an IdP-initiated one, if the provider allows
	// them. Its RelayState, if any, is the IdP's (or an attacker's). The
	// unverified Issuer only chooses the IdP to verify the Response with.
	issuer, err := samlsp.PeekUnverifiedIssuer(r)
	if err != nil {
		return nil, nil, "", err
	}
	p, err := a.db.ProviderByEntityID(issuer)
	if err != nil {
		return nil, nil, "", fmt.Errorf("no provider for IdP %q", issuer)
	}
	if !p.AllowIDPInitiated {
		return nil, nil, "", fmt.Errorf("provider %s does not allow IdP-initiated login", p.ID)
	}
	return []samlsp.ResponseOption{samlsp.AllowUnsolicited}, p, relayState, nil
}

// startLogout ends the local session, then sends the browser to the IdP to
// end the user's session there too.
func (a *App) startLogout(w http.ResponseWriter, r *http.Request) {
	s, ok := a.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.db.DeleteSession(s.ID)
	a.setCookie(w, sessionCookie, "", "/", -1, false)

	p, err := a.db.ProviderByID(s.ProviderID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	relayState := newID()
	msg, err := a.logout.Request(r.Context(), s.NameID, relayState,
		slo.WithSessionIndex(s.SessionIndexes...), idp(p))
	if err != nil {
		// samlsp.ErrNoEndpoint: the IdP does not do single logout.
		log.Printf("LogoutRequest for provider %s: %v", p.ID, err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.db.AddRelayState(RelayState{
		ID: relayState, ProviderID: p.ID, RequestID: msg.ID, RedirectTo: "/", CreatedAt: time.Now(),
	})
	msg.Write(w)
}

// slo serves the single logout service: LogoutRequests from an IdP, and
// the LogoutResponses that answer ours.
func (a *App) slo(w http.ResponseWriter, r *http.Request) {
	switch {
	case slo.IsRequest(r):
		a.idpLogout(w, r)
	case slo.IsResponse(r):
		a.logoutDone(w, r)
	default:
		http.Error(w, "not a SAML logout message", http.StatusBadRequest)
	}
}

// idpLogout ends the sessions an IdP's LogoutRequest names. The request
// carries no state of ours, so its IdP is found by its unverified Issuer
// (samlsp.PeekUnverifiedIssuer), then the request is verified against that IdP's
// metadata.
func (a *App) idpLogout(w http.ResponseWriter, r *http.Request) {
	issuer, err := samlsp.PeekUnverifiedIssuer(r)
	if err != nil {
		slo.WriteRequestError(w, r)
		return
	}
	p, err := a.db.ProviderByEntityID(issuer)
	if err != nil {
		slo.WriteRequestError(w, r)
		return
	}
	// ParseRequest takes no IdP option; name it in the context.
	ctx := samlsp.IdentityProviderContext(r.Context(), p.IdentityProvider())
	req, err := a.logout.ParseRequest(ctx, r)
	if err != nil {
		log.Printf("LogoutRequest from provider %s: %v (%v)", p.ID, err, errors.Unwrap(err))
		slo.WriteRequestError(w, r)
		return
	}
	n := a.db.DeleteSessionsFor(p.ID, req.NameID, req.SessionIndexes)
	log.Printf("provider %s logged out %d session(s)", p.ID, n)

	msg, err := a.logout.Response(ctx, req)
	if err != nil {
		http.Error(w, "cannot answer the LogoutRequest", http.StatusInternalServerError)
		return
	}
	msg.Write(w)
}

// logoutDone checks the IdP's answer to our LogoutRequest.
func (a *App) logoutDone(w http.ResponseWriter, r *http.Request) {
	rs, err := a.db.TakeRelayState(r.FormValue("RelayState"))
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	p, err := a.db.ProviderByID(rs.ProviderID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	ctx := samlsp.IdentityProviderContext(r.Context(), p.IdentityProvider())
	if _, err := a.logout.ParseResponse(ctx, r, rs.RequestID); err != nil {
		// The local session is gone anyway; the IdP's may remain.
		log.Printf("LogoutResponse from provider %s: %v", p.ID, err)
	}
	http.Redirect(w, r, rs.RedirectTo, http.StatusFound)
}

func (a *App) session(r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return Session{}, false
	}
	s, err := a.db.SessionByID(c.Value)
	return s, err == nil
}

// setCookie sets an HttpOnly cookie. A crossSite one must reach the ACS
// with the IdP's cross-site POST: over https it is SameSite=None; over
// plain http, for development, browsers send a cookie without SameSite on
// a cross-site POST shortly after it was set. The others are SameSite=Lax.
func (a *App) setCookie(w http.ResponseWriter, name, value, path string, maxAge int, crossSite bool) {
	c := &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge, HttpOnly: true}
	switch {
	case a.secure && crossSite:
		c.Secure, c.SameSite = true, http.SameSiteNoneMode
	case a.secure:
		c.Secure, c.SameSite = true, http.SameSiteLaxMode
	case !crossSite:
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
}

// isLocalPath reports whether p, a return path from the request, is safe
// to redirect to (see saferedirect.IsSafe). It repeats the checks of the
// start of p that saferedirect.IsSafe makes, so that static analyzers,
// which may not look into another package, see the redirect guarded.
func isLocalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return false
	}
	return saferedirect.IsSafe(p)
}

// mustParseURL parses a URL known to be valid.
func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
