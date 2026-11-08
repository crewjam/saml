package server

import (
	"net/http"
	"net/url"
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
	mustContain(t, body, "/sp/"+spIDs[0]+"/metadata", "/sp/"+spIDs[1]+"/metadata", "IdP-initiated logout",
		"This browser is logged in to this IdP as <strong>alice</strong>", "Log out everywhere")
	// The SP's management page offers logout next to login.
	_, body = h.do(http.MethodGet, "/manage/"+spSecrets[0], nil)
	mustContain(t, body, "This browser is logged in to this SP as", "Log out everywhere", "Log out of this SP only")

	// SP-initiated: SP 0 → IdP → SP 1 → IdP → SP 0, all through the browser.
	_, body = h.do(http.MethodPost, "/sp/"+spIDs[0]+"/logout", nil)
	body = h.follow(body)
	mustContain(t, body, "Logged out everywhere")
	for _, id := range spIDs {
		_, body = h.do(http.MethodGet, "/sp/"+id+"/", nil)
		mustContain(t, body, "Not logged in")
	}
	_, body = h.do(http.MethodGet, "/manage/"+idpSecret, nil)
	mustContain(t, body, "No sessions", "LogoutRequest from", "LogoutResponse from", "samlp:LogoutRequest")
	_, body = h.do(http.MethodGet, "/manage/"+spSecrets[1], nil)
	mustContain(t, body, "LogoutRequest from the IdP", "Ended")

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
	mustContain(t, body, "Message kept for artifact resolution", "ArtifactResolve (SOAP)", "samlp:ArtifactResponse")
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
