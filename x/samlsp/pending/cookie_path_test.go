package pending_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml/x/samlsp"
)

// The cookie's Path is the ACS path as the browser requests it, with its
// escapes, which is what browsers match it against (RFC 6265 §5.1.4).
func TestCookiePathEscaped(t *testing.T) {
	for _, acs := range []string{"/saml%20acs", "/s%C3%A1ml/acs", "/a%2Fb/acs"} {
		cfg, _ := newConfig(t, samlsp.WithACSURL("https://sp.example.com"+acs))
		tr := newTracker(t, cfg)
		msg, err := cfg.AuthnRequest(t.Context(), "relay")
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		if err := tr.Remember(w, msg, ""); err != nil {
			t.Fatal(err)
		}
		cookie := w.Header().Get("Set-Cookie")
		if !strings.Contains(cookie, "Path="+acs+";") && !strings.HasSuffix(cookie, "Path="+acs) {
			t.Errorf("ACS %s: cookie %s", acs, cookie)
		}
	}
}
