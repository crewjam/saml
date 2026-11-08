package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml/x/samlsp"
)

// This file holds what x/samlsp leaves to the application: remembering the
// pending AuthnRequest, and keeping sessions. Sessions are kept in memory,
// under a random ID in a cookie; a real application would use its own
// session store.

type session struct {
	assertion *samlsp.Assertion
	expires   time.Time
}

var sessions = struct {
	sync.Mutex
	m map[string]*session
}{m: map[string]*session{}}

const sessionCookie = "session"

type sessionKey struct{}

func contextWithSession(ctx context.Context, s *session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

func sessionFromContext(ctx context.Context) *session {
	s, _ := ctx.Value(sessionKey{}).(*session)
	return s
}

// requireLogin serves next to users with a session, with the session in
// the request's context, and sends the others to the IdP to log in.
func requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := sessionFrom(r)
		if s == nil {
			startLogin(w, r, r.URL.RequestURI())
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithSession(r.Context(), s)))
	})
}

// startLogin sends the browser to the IdP with an AuthnRequest. The
// request's ID, and where to go after login, wait in a cookie named after
// the RelayState, so that the Response is accepted only in the browser
// that asked for it.
func startLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	relayState := rand.Text()
	msg, err := config.AuthnRequest(r.Context(), relayState)
	if err != nil {
		log.Printf("cannot start login: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	setTempCookie(w, "saml_"+relayState, config.ACSPath(), url.Values{"id": {msg.ID}, "to": {returnTo}}.Encode())
	msg.Write(w)
}

// acs is the assertion consumer service: it verifies the IdP's Response
// and starts a session.
func acs(w http.ResponseWriter, r *http.Request) {
	name := "saml_" + r.FormValue("RelayState")
	cookie, err := r.Cookie(name)
	if err != nil {
		http.Error(w, "no login in progress", http.StatusForbidden)
		return
	}
	deleteCookie(w, name, config.ACSPath())
	pending, err := url.ParseQuery(cookie.Value)
	if err != nil {
		http.Error(w, "no login in progress", http.StatusForbidden)
		return
	}

	assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(pending.Get("id")))
	if err != nil {
		log.Printf("login failed: %v", errors.Unwrap(err))
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	startSession(w, assertion)

	returnTo := pending.Get("to")
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func startSession(w http.ResponseWriter, a *samlsp.Assertion) {
	expires := time.Now().Add(8 * time.Hour)
	if !a.SessionNotOnOrAfter.IsZero() && a.SessionNotOnOrAfter.Before(expires) {
		expires = a.SessionNotOnOrAfter
	}
	id := rand.Text()
	sessions.Lock()
	sessions.m[id] = &session{assertion: a, expires: expires}
	sessions.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", Expires: expires,
		HttpOnly: true, Secure: secure(), SameSite: http.SameSiteLaxMode,
	})
}

func sessionFrom(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	sessions.Lock()
	defer sessions.Unlock()
	s := sessions.m[c.Value]
	if s != nil && time.Now().After(s.expires) {
		delete(sessions.m, c.Value)
		return nil
	}
	return s
}

// secure reports whether the SP is served over https, so that its cookies
// can be Secure.
func secure() bool { return strings.HasPrefix(config.ACSURL(), "https:") }

// setTempCookie sets a cookie that lasts for one exchange with the IdP. The
// IdP's answer is a cross-site request, so over https the cookie is
// SameSite=None; over plain http, which is for development, browsers send
// a cookie without SameSite on a cross-site POST shortly after it was set.
func setTempCookie(w http.ResponseWriter, name, path, value string) {
	c := &http.Cookie{Name: name, Value: value, Path: path, MaxAge: 300, HttpOnly: true}
	if secure() {
		c.Secure, c.SameSite = true, http.SameSiteNoneMode
	}
	http.SetCookie(w, c)
}

func deleteCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: path, MaxAge: -1, HttpOnly: true, Secure: secure()})
}
