package pending_test

import (
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

// A login handler remembers each AuthnRequest in a cookie, with where to
// send the user afterwards, and the ACS finds it by the Response's
// RelayState. It forgets the login only once the Response is verified, so
// that a junk Response does not cancel it.
func Example() {
	config, err := samlsp.New(
		"https://sp.example.com/saml/metadata",
		samlsp.RemoteMetadata("https://idp.example.com/metadata"),
	)
	if err != nil {
		log.Fatal(err)
	}
	// 32 or more random bytes, the same on every server.
	tracker, err := pending.New(config, []byte(os.Getenv("SAML_COOKIE_KEY")))
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		msg, err := config.AuthnRequest(r.Context(), rand.Text())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tracker.Remember(w, msg, r.URL.Query().Get("next")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	})

	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		login, err := tracker.Find(w, r)
		if err != nil {
			http.Error(w, "no login in progress; please sign in again", http.StatusBadRequest)
			return
		}
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID))
		if err != nil {
			// The login stays in progress, for the real Response.
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		tracker.Forget(w, login)
		startSession(w, assertion)

		// The data came from the login request, so check it as such: a
		// path on this site, not one that browsers read as another host.
		next := login.Data
		if !isLocalPath(next) {
			next = "/"
		}
		http.Redirect(w, r, next, http.StatusFound) //nolint:gosec // G710: next is checked by isLocalPath
	})
}

// An ACS that also accepts IdP-initiated logins requires a matching request
// only when the browser has a login in progress.
func ExampleTracker_Find_unsolicited() {
	var (
		config  *samlsp.Config
		tracker *pending.Tracker
	)
	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		opts := []samlsp.ResponseOption{samlsp.AllowUnsolicited}
		login, err := tracker.Find(w, r)
		switch {
		case err == nil:
			opts = append(opts, samlsp.WithRequestID(login.ID))
		case errors.Is(err, pending.ErrNotFound):
			// IdP-initiated, or the login took too long.
		default:
			http.Error(w, "login failed", http.StatusBadRequest)
			return
		}
		assertion, err := config.ParseResponse(r.Context(), r, opts...)
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		tracker.Forget(w, login) // does nothing for an unsolicited login
		startSession(w, assertion)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func startSession(http.ResponseWriter, *samlsp.Assertion) {}

// isLocalPath reports whether p is a path on this site, safe to redirect
// to: it starts with "/", but not with "//" or "/\", which browsers read as
// another host.
func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\")
}
