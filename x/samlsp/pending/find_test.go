package pending_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

// TestFindForget checks that a junk Response posted with the user's
// RelayState does not cancel the login in progress when the ACS uses Find,
// and clears the slot with Forget only once the real Response is accepted.
func TestFindForget(t *testing.T) {
	cfg, ti := newConfig(t)
	tr := newTracker(t, cfg)
	msg, w := remember(t, cfg, tr, "state-1", "/next")
	browser := jar{}
	browser.set(w)

	// A site that knows the RelayState makes the browser post junk.
	junk := browser.request("state-1")
	login, err := tr.Find(httptest.NewRecorder(), junk)
	if err != nil || login.ID != msg.ID || login.Data != "/next" {
		t.Fatalf("Find = %+v, %v; want ID %q", login, err, msg.ID)
	}
	if _, err := cfg.ParseResponse(t.Context(), junk, samlsp.WithRequestID(login.ID)); err == nil {
		t.Fatal("the junk Response was accepted")
	}

	// The real Response then arrives, and the login is still in progress.
	idpW := httptest.NewRecorder()
	ti.idp.ServeSSO(idpW, httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), nil))
	form := formValues(idpW.Body.String())
	r := acsRequest(form, w)
	login, err = tr.Find(httptest.NewRecorder(), r)
	if err != nil {
		t.Fatalf("Find after the junk Response: %v", err)
	}
	if _, err := cfg.ParseResponse(t.Context(), r, samlsp.WithRequestID(login.ID)); err != nil {
		t.Fatal(err)
	}
	acsW := httptest.NewRecorder()
	tr.Forget(acsW, login)
	cleared := onlyCookie(t, acsW)
	if cleared.MaxAge >= 0 || cleared.Value != "" || cleared.Path != "/saml/acs" || cleared.Name != onlyCookie(t, w).Name {
		t.Errorf("Forget did not clear the slot: %+v", cleared)
	}
	browser.set(acsW)
	if _, err := tr.Find(httptest.NewRecorder(), browser.request("state-1")); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("Find after Forget: err = %v, want ErrNotFound", err)
	}

	// Forget of nil does nothing.
	w = httptest.NewRecorder()
	tr.Forget(w, nil)
	if len(w.Result().Cookies()) != 0 {
		t.Error("Forget(nil) set a cookie")
	}
}

// TestFindErrors checks the errors of Find.
func TestFindErrors(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	r := acsRequest(url.Values{"RelayState": {"s"}}, httptest.NewRecorder())
	if _, err := tr.Find(httptest.NewRecorder(), r); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("no cookie: err = %v, want ErrNotFound", err)
	}
	browser := jar{slotName(t, cfg, tr, "s"): {Name: slotName(t, cfg, tr, "s"), Value: "x.y"}} //nolint:gosec // G124: a request cookie carries no attributes
	if _, err := tr.Find(httptest.NewRecorder(), browser.request("s")); !errors.Is(err, pending.ErrInvalid) {
		t.Errorf("invalid cookie: err = %v, want ErrInvalid", err)
	}
}

// TestFindClearsStaleOnly checks that Find clears the slots of expired and
// invalid logins, but never the slot of the login it finds, even when the
// browser also sends an invalid cookie of that name.
func TestFindClearsStaleOnly(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	msg, w := remember(t, cfg, tr, "live", "")
	own := onlyCookie(t, w)
	r := acsRequest(url.Values{"RelayState": {"live"}}, w)
	// A tossed cookie of the same name, and an invalid one in another slot.
	r.AddCookie(&http.Cookie{Name: own.Name, Value: "x.y"}) //nolint:gosec // G124: a request cookie carries no attributes
	other := pending.DefaultCookiePrefix + "63"
	if other == own.Name {
		other = pending.DefaultCookiePrefix + "62"
	}
	r.AddCookie(&http.Cookie{Name: other, Value: "x.y"}) //nolint:gosec // G124: a request cookie carries no attributes

	rec := httptest.NewRecorder()
	login, err := tr.Find(rec, r)
	if err != nil || login.ID != msg.ID {
		t.Fatalf("Find = %+v, %v; want ID %q", login, err, msg.ID)
	}
	cleared := map[string]bool{}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge >= 0 {
			t.Errorf("Find set %+v", c)
		}
		cleared[c.Name] = true
	}
	if cleared[own.Name] || !cleared[other] || len(cleared) != 1 {
		t.Errorf("Find cleared %v, want only %s", cleared, other)
	}
}
