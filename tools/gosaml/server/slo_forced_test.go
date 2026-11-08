package server

import (
	"net/http"
	"testing"
)

// A LogoutRequest that names another user does not log out the browser
// that delivers it: anyone can make a browser deliver one.
func TestSingleLogoutOtherBrowser(t *testing.T) {
	alice := newHarness(t)
	_, idpID, spSecrets, spIDs := pair(alice, 1)
	alice.loginAs(idpID, spIDs[0], "alice")

	bob := alice.newBrowser()
	bob.loginAs(idpID, spIDs[0], "bob")
	// Bob starts a logout at the IdP, stops at the redirect that carries
	// its LogoutRequest to the SP, and has Alice's browser follow it
	// instead.
	slo := "/sp/" + spIDs[0] + "/slo"
	bob.client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == slo {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, _ := bob.do(http.MethodPost, "/idp/"+idpID+"/logout", nil)
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout at the IdP: %d, Location %q", resp.StatusCode, location)
	}
	alice.do(http.MethodGet, location, nil)

	// Bob's session at the SP has ended, but not Alice's.
	_, body := alice.do(http.MethodGet, "/sp/"+spIDs[0]+"/", nil)
	mustContain(t, body, "alice@example.com")
	mustContain(t, alice.logEntries(spSecrets[0]), "Ended bob")
}
