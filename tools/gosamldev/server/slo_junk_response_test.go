package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A junk LogoutResponse posted with the RelayState of a logout in progress
// does not cancel it: the IdP's real LogoutResponse, arriving after it, is
// still accepted.
func TestSingleLogoutJunkResponseKeepsLogout(t *testing.T) {
	h := newHarness(t)
	_, idpID, _, spIDs := pair(h, 1)
	h.loginAs(idpID, spIDs[0], "alice")

	// Start an SP-initiated logout and stop where the IdP's answer would
	// reach the SP's single logout service.
	slo := "/sp/" + spIDs[0] + "/slo"
	h.client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == slo {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, body := h.do(http.MethodPost, "/sp/"+spIDs[0]+"/logout", nil)
	h.client.CheckRedirect = nil

	// The real answer, by redirect or by self-submitting form.
	var relayState string
	var deliver func() string
	if loc := resp.Header.Get("Location"); loc != "" && strings.Contains(loc, slo) {
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		relayState = u.Query().Get("RelayState")
		deliver = func() string { _, b := h.do(http.MethodGet, loc, nil); return b }
	} else {
		m := hiddenRe.FindAllStringSubmatch(body, -1)
		for _, in := range m {
			if in[1] == "RelayState" {
				relayState = in[2]
			}
		}
		saved := body
		deliver = func() string { _, b := h.submitAutoForm(saved); return b }
	}
	if relayState == "" {
		t.Fatalf("no RelayState in the IdP's answer: %d %q\n%s", resp.StatusCode, resp.Header.Get("Location"), body)
	}

	// A junk response with the same RelayState is refused...
	_, junk := h.do(http.MethodPost, slo, url.Values{"SAMLResponse": {"bm90IGEgbG9nb3V0IHJlc3BvbnNl"}, "RelayState": {relayState}})
	mustContain(t, junk, "refused or reports a failure")

	// ...and the logout is still waiting for the real one.
	mustContain(t, h.follow(deliver()), "Logged out everywhere")
}
