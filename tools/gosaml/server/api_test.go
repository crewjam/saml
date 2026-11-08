package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// api makes a JSON API request and decodes the response into out, if
// it is not nil. It returns the status.
func (h *harness) api(method, path, body string, out any) int {
	h.t.Helper()
	req, err := http.NewRequest(method, h.base+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	b, _ := io.ReadAll(resp.Body)
	if len(b) > 0 && !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		h.t.Fatalf("%s %s: %s is not JSON:\n%s", method, path, resp.Header.Get("Content-Type"), b)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			h.t.Fatalf("%s %s: %v\n%s", method, path, err, b)
		}
	}
	return resp.StatusCode
}

func (h *harness) apiOK(want int, method, path, body string, out any) {
	h.t.Helper()
	var raw json.RawMessage
	if got := h.api(method, path, body, &raw); got != want {
		h.t.Fatalf("%s %s: %d, want %d\n%s", method, path, got, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatal(err)
		}
	}
}

func TestAPI(t *testing.T) {
	h := newHarness(t)

	resp, body := h.do(http.MethodGet, "/api", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api: %d", resp.StatusCode)
	}
	mustContain(t, body, "<h1>API</h1>", h.base+"/api/idps", `aria-current="page">API`)

	var idp APIInstance
	h.apiOK(http.StatusCreated, http.MethodPost, "/api/idps", `{"name": "CI IdP", "remember_sessions": false}`, &idp)
	if idp.Kind != "idp" || idp.IdP == nil || *idp.IdP.Settings.Name != "CI IdP" || *idp.IdP.Settings.RememberSessions ||
		len(idp.IdP.Users) != 3 || idp.EntityID != h.base+"/idp/"+idp.ID+"/metadata" || idp.SP != nil {
		t.Fatalf("new IdP: %+v", idp)
	}
	idpAPI := "/api/manage/" + idp.Secret

	// The management page shows what the API made.
	_, body = h.do(http.MethodGet, "/manage/"+idp.Secret, nil)
	mustContain(t, body, "CI IdP")

	var sp APIInstance
	h.apiOK(http.StatusCreated, http.MethodPost, "/api/sps", `{"idp": {"metadata_url": "`+idp.MetadataURL+`"}, "binding": "post"}`, &sp)
	if sp.SP == nil || sp.SP.IdP == nil || sp.SP.IdP.EntityID != idp.EntityID || *sp.SP.Settings.Binding != "post" {
		t.Fatalf("new SP: %+v", sp)
	}
	spAPI := "/api/manage/" + sp.Secret

	// Settings: a partial change, and refusals that change nothing.
	var got APIInstance
	h.apiOK(http.StatusOK, http.MethodPatch, spAPI, `{"allow_sha1": true, "nameid_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}`, &got)
	if s := got.SP.Settings; !*s.AllowSHA1 || *s.Binding != "post" || *s.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		t.Fatalf("patched: %+v", s)
	}
	var apiErr APIError
	h.apiOK(http.StatusBadRequest, http.MethodPatch, idpAPI, `{"encryption": "aes", "remember_sessions": true}`, &apiErr)
	mustContain(t, apiErr.Error, "encryption must be one of")
	h.apiOK(http.StatusBadRequest, http.MethodPatch, idpAPI, `{"remember_session": true}`, &apiErr)
	mustContain(t, apiErr.Error, "unknown field")
	h.apiOK(http.StatusOK, http.MethodGet, idpAPI, "", &got)
	if *got.IdP.Settings.RememberSessions {
		t.Fatal("a refused PATCH changed a setting")
	}
	h.apiOK(http.StatusBadRequest, http.MethodPost, "/api/idps", `{"profile": "ping"}`, &apiErr)
	h.apiOK(http.StatusConflict, http.MethodPut, spAPI+"/users/dave", `{}`, &apiErr)
	h.apiOK(http.StatusConflict, http.MethodPut, idpAPI+"/idp", `{}`, &apiErr)
	h.apiOK(http.StatusNotFound, http.MethodGet, "/api/manage/no-such-secret", "", &apiErr)
	h.apiOK(http.StatusNotFound, http.MethodGet, "/api/nothing", "", &apiErr)

	// Users.
	var user APIUser
	h.apiOK(http.StatusOK, http.MethodPut, idpAPI+"/users/dave", `{
		"nameid": "dave@example.com",
		"nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"attributes": [{"name": "groups", "values": ["ops", "users"]}]
	}`, &user)
	if user.Username != "dave" || user.NameID != "dave@example.com" || len(user.Attributes) != 1 {
		t.Fatalf("user: %+v", user)
	}
	h.apiOK(http.StatusOK, http.MethodDelete, idpAPI+"/users/carol", "", &got)
	if n := len(got.IdP.Users); n != 3 {
		t.Fatalf("%d users", n)
	}
	h.apiOK(http.StatusNotFound, http.MethodDelete, idpAPI+"/users/carol", "", &apiErr)

	// Register the SP explicitly.
	var reg APIRegisteredSP
	h.apiOK(http.StatusOK, http.MethodPost, idpAPI+"/service-providers", `{"metadata_url": "`+sp.MetadataURL+`"}`, &reg)
	if reg.EntityID != sp.EntityID || !strings.Contains(reg.Metadata, "SPSSODescriptor") {
		t.Fatalf("registered: %+v", reg)
	}
	h.apiOK(http.StatusBadRequest, http.MethodPost, idpAPI+"/service-providers", `{}`, &apiErr)

	// Log in as the new user through a browser, then read both logs.
	var before []APIEvent
	h.apiOK(http.StatusOK, http.MethodGet, spAPI+"/events", "", &before)
	after := int64(0)
	if len(before) > 0 {
		after = before[0].ID
	}
	_, body = h.do(http.MethodGet, sp.SP.LoginURL, nil)
	_, body = h.submitAutoForm(body) // the AuthnRequest, by HTTP-POST
	_, body = h.loginAt(idp.ID, body, url.Values{"user": {"dave"}, "action": {"login"}})
	_, body = h.submitAutoForm(body)
	mustContain(t, body, "Logged in as", "dave@example.com", "ops")

	var events []APIEvent
	h.apiOK(http.StatusOK, http.MethodGet, spAPI+"/events?after="+strconv.FormatInt(after, 10), "", &events)
	if len(events) != 2 || events[0].Title != "Logged in dave@example.com" || !events[0].OK || events[0].Direction != "in" ||
		!strings.Contains(events[0].XML, "Response") || !strings.HasPrefix(events[1].Title, "AuthnRequest to ") {
		t.Fatalf("events: %+v", events)
	}
	if resp, _ := h.do(http.MethodGet, events[0].URL, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d", events[0].URL, resp.StatusCode)
	}
	if h.api(http.MethodDelete, idpAPI+"/events", "", nil) != http.StatusNoContent {
		t.Fatal("clear events")
	}
	h.apiOK(http.StatusOK, http.MethodGet, idpAPI+"/events", "", &events)
	if len(events) != 0 {
		t.Fatalf("events after clearing: %+v", events)
	}

	// A profile, then deletion.
	h.apiOK(http.StatusOK, http.MethodPost, idpAPI+"/profile", `{"profile": "okta"}`, &got)
	if got.IdP.Profile != "okta" || !strings.HasPrefix(got.EntityID, "http://www.okta.com/exk") {
		t.Fatalf("profile: %+v", got)
	}
	h.apiOK(http.StatusOK, http.MethodDelete, idpAPI+"/service-providers?entity_id="+url.QueryEscape(sp.EntityID), "", &got)
	if len(got.IdP.ServiceProviders) != 0 {
		t.Fatalf("SPs: %+v", got.IdP.ServiceProviders)
	}
	if h.api(http.MethodDelete, idpAPI, "", nil) != http.StatusNoContent {
		t.Fatal("delete")
	}
	h.apiOK(http.StatusNotFound, http.MethodGet, idpAPI, "", &apiErr)
}
