package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// follow submits self-submitting SAML forms until a page without one is
// reached, as a browser with scripts would.
func (h *harness) follow(body string) string {
	h.t.Helper()
	for i := 0; i < 10 && (strings.Contains(body, `name="SAMLRequest"`) || strings.Contains(body, `name="SAMLResponse"`) || strings.Contains(body, `name="SAMLart"`)); i++ {
		_, body = h.submitAutoForm(body)
	}
	return body
}

// pair makes an IdP and n SPs that trust it.
func pair(h *harness, n int) (idpSecret, idpID string, spSecrets, spIDs []string) {
	idpSecret, idpID = h.create("idp")
	for range n {
		secret, id := h.create("sp")
		_, body := h.do(http.MethodPost, "/manage/"+secret+"/idp-set", url.Values{"metadata_url": {h.base + "/idp/" + idpID + "/metadata"}})
		mustContain(h.t, body, "saved")
		spSecrets, spIDs = append(spSecrets, secret), append(spIDs, id)
	}
	return
}

// loginAs logs in to the SP spID as user, at the IdP's login page if it
// shows one, or by single sign-on.
func (h *harness) loginAs(idpID, spID, user string) string {
	h.t.Helper()
	_, body := h.do(http.MethodPost, "/sp/"+spID+"/login", nil)
	if strings.Contains(body, `name="pending"`) {
		_, body = h.loginAt(idpID, body, url.Values{"user": {user}, "action": {"login"}})
	}
	body = h.follow(body)
	mustContain(h.t, body, "Logged in as")
	return body
}

func TestSingleLogout(t *testing.T) {
	h := newHarness(t)
	idpSecret, idpID, spSecrets, spIDs := pair(h, 2)

	h.loginAs(idpID, spIDs[0], "alice")
	h.loginAs(idpID, spIDs[1], "alice") // single sign-on
	_, body := h.do(http.MethodGet, "/sp/"+spIDs[1]+"/", nil)
	mustContain(t, body, "alice@example.com", "Log out everywhere")
	_, body = h.do(http.MethodGet, "/manage/"+idpSecret, nil)
	mustContain(t, body, "/sp/"+spIDs[0]+"/metadata", "/sp/"+spIDs[1]+"/metadata", "session-logout",
		"This browser is logged in as <strong>alice</strong>", "Log out everywhere")
	// The SP's management page offers logout next to login.
	_, body = h.do(http.MethodGet, "/manage/"+spSecrets[0], nil)
	mustContain(t, body, "This browser is logged in as", "Log out everywhere", "This SP only")

	// SP-initiated: SP 0 → IdP → SP 1 → IdP → SP 0, all through the browser.
	_, body = h.do(http.MethodPost, "/sp/"+spIDs[0]+"/logout", nil)
	body = h.follow(body)
	mustContain(t, body, "Logged out everywhere")
	for _, id := range spIDs {
		_, body = h.do(http.MethodGet, "/sp/"+id+"/", nil)
		mustContain(t, body, "Not logged in")
	}
	_, body = h.do(http.MethodGet, "/manage/"+idpSecret, nil)
	mustContain(t, body, "No sessions", "LogoutRequest from", "LogoutResponse from")
	mustContain(t, h.logEntries(idpSecret), "samlp:LogoutRequest")
	_, body = h.do(http.MethodGet, "/manage/"+spSecrets[1], nil)
	mustContain(t, body, "LogoutRequest from the IdP")
	mustContain(t, h.logEntries(spSecrets[1]), "Ended")

	// The next login asks again.
	_, body = h.do(http.MethodPost, "/sp/"+spIDs[0]+"/login", nil)
	mustContain(t, body, "Log in as")

	// IdP-initiated, from the IdP's session page.
	h.loginAs(idpID, spIDs[0], "bob")
	h.loginAs(idpID, spIDs[1], "bob")
	_, body = h.do(http.MethodGet, "/idp/"+idpID+"/session", nil)
	mustContain(t, body, "bob", "/sp/"+spIDs[1]+"/metadata")
	_, body = h.do(http.MethodPost, "/idp/"+idpID+"/logout", nil)
	body = h.follow(body)
	mustContain(t, body, "Logged out of 2 of 2")
	for _, id := range spIDs {
		_, body = h.do(http.MethodGet, "/sp/"+id+"/", nil)
		mustContain(t, body, "Not logged in")
	}

	// Back-channel: SP 1 is logged out over SOAP, without the browser.
	h.do(http.MethodPost, "/manage/"+idpSecret+"/settings", url.Values{
		"name": {"IdP"}, "auto_fetch": {"on"}, "remember_sessions": {"on"}, "back_channel": {"on"}, "signature_method": {"sha256"}, "encryption": {"auto"}})
	h.do(http.MethodPost, "/manage/"+spSecrets[1]+"/settings", url.Values{
		"name": {"SP"}, "sign_requests": {"on"}, "encryption_key": {"on"}, "allow_unsolicited": {"on"}, "back_channel": {"on"}})
	h.loginAs(idpID, spIDs[0], "carol")
	h.loginAs(idpID, spIDs[1], "carol")
	_, body = h.do(http.MethodPost, "/sp/"+spIDs[0]+"/logout", nil)
	body = h.follow(body)
	mustContain(t, body, "Logged out everywhere")
	_, body = h.do(http.MethodGet, "/manage/"+spSecrets[1], nil)
	mustContain(t, body, "LogoutRequest (SOAP)", "No sessions")
	_, body = h.do(http.MethodGet, "/manage/"+idpSecret, nil)
	mustContain(t, body, "Back-channel LogoutRequest to")

	// Logging out of the SP only leaves the IdP session.
	h.loginAs(idpID, spIDs[0], "alice")
	_, body = h.do(http.MethodPost, "/sp/"+spIDs[0]+"/logout", url.Values{"mode": {"local"}})
	mustContain(t, body, "Logged out of this SP only")
	_, body = h.do(http.MethodGet, "/idp/"+idpID+"/session", nil)
	mustContain(t, body, "alice")
}

func TestArtifactBinding(t *testing.T) {
	h := newHarness(t)
	idpSecret, idpID, spSecrets, spIDs := pair(h, 1)
	spSecret, spID := spSecrets[0], spIDs[0]

	// The SP asks for the Response by artifact: the browser is
	// redirected to the ACS with a SAMLart, which the SP resolves at the
	// IdP, server to server.
	_, body := h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"response_binding": {"artifact"}})
	resp, body := h.loginAt(idpID, body, url.Values{"user": {"alice"}, "action": {"login"}})
	if resp.Request.URL.Query().Get("SAMLart") == "" {
		t.Fatalf("not an artifact redirect: %s\n%s", resp.Request.URL, body)
	}
	mustContain(t, body, "Logged in as", "alice@example.com")
	_, body = h.do(http.MethodGet, "/manage/"+idpSecret, nil)
	mustContain(t, body, "Message kept for artifact resolution", "ArtifactResolve (SOAP)")
	mustContain(t, h.logEntries(idpSecret), "samlp:ArtifactResponse", "by SOAP")
	_, body = h.do(http.MethodGet, "/manage/"+spSecret, nil)
	mustContain(t, body, "Resolved artifact")

	// With the IdP's form setting, the artifact is posted instead.
	h.do(http.MethodPost, "/manage/"+idpSecret+"/settings", url.Values{
		"name": {"IdP"}, "auto_fetch": {"on"}, "remember_sessions": {"on"}, "artifact_form": {"on"}, "signature_method": {"sha256"}, "encryption": {"auto"}})
	_, body = h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"response_binding": {"artifact"}})
	mustContain(t, body, `name="SAMLart"`)
	body = h.follow(body)
	mustContain(t, body, "Logged in as", "alice@example.com")

	// Sending the AuthnRequest by artifact needs an IdP that offers it in
	// its metadata, which the test IdPs do not.
	_, body = h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"binding": {"artifact"}, "force_authn": {"on"}})
	mustContain(t, body, "no endpoint for the binding", "HTTP-Artifact")
}

// logEntries returns the log entry pages of an instance, one after the
// other.
func (h *harness) logEntries(secret string) string {
	h.t.Helper()
	_, body := h.do(http.MethodGet, "/manage/"+secret, nil)
	var all strings.Builder
	for _, m := range regexp.MustCompile(`href="(/manage/`+regexp.QuoteMeta(secret)+`/log/\d+)"`).FindAllStringSubmatch(body, -1) {
		resp, page := h.do(http.MethodGet, m[1], nil)
		if resp.StatusCode != http.StatusOK {
			h.t.Fatalf("%s: %d", m[1], resp.StatusCode)
		}
		all.WriteString(page)
	}
	return all.String()
}

// The log entry page shows the HTTP exchange of an event, with cookie
// values shortened, its parameters decoded, and the message.
func TestLogEntry(t *testing.T) {
	h := newHarness(t)
	_, idpID, spSecrets, spIDs := pair(h, 1)
	h.loginAs(idpID, spIDs[0], "alice")

	_, body := h.do(http.MethodGet, "/manage/"+spSecrets[0], nil)
	m := regexp.MustCompile(`href="(/manage/[^"]+/log/(\d+))">\s*<time[^>]*>[^<]*</time>\s*<span class="log-title">Logged in alice@example.com`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no log row for the login:\n%s", body)
	}
	// The rows' links are boosted by htmx: the list must not hand them its
	// hx-swap="afterbegin", or the entry would be put in front of this page.
	mustContain(t, body, `hx-swap="afterbegin" hx-disinherit="*"`)
	_, page := h.do(http.MethodGet, m[1], nil)
	mustContain(t, page,
		"<h1>Logged in alice@example.com</h1>",
		"Received at", "by HTTP-POST", "It was accepted.",
		"POST "+h.base+"/sp/"+spIDs[0]+"/acs", // the request line
		"HTTP/1.1 200 OK", // the answer
		"Form parameters, decoded", "SAMLResponse=", "RelayState=",
		"Copy as cURL", "Open in the inspector",
		"✓ Accepted", "Response <span class=\"decoded-sub\">", "✓ Response signed")
	// Decoded from the raw request, not the indented copy, so the
	// signature of an accepted Response is not reported broken.
	if strings.Contains(page, "signature broken") {
		t.Error("an accepted Response's signature is shown as broken")
	}
	// The browser sent the pending-login cookie; its value is shortened.
	if c := regexp.MustCompile(`Cookie: ([^\n]*)`).FindStringSubmatch(page); c == nil || !strings.Contains(c[1], "…") {
		t.Errorf("cookie not redacted: %v", c)
	}
	// Older and newer entries link to each other.
	if !strings.Contains(page, "← Older") {
		t.Error("no link to the older entry")
	}
	// Another instance's secret cannot read it.
	other := regexp.MustCompile(`/manage/[^/]+/log/`).ReplaceAllString(m[1], "/manage/nope/log/")
	if resp, _ := h.do(http.MethodGet, other, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("other secret: %d", resp.StatusCode)
	}
}
