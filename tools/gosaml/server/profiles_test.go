package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/crewjam/saml/x/samlidp"
)

func TestProfiles(t *testing.T) {
	for _, tc := range []struct {
		profile string
		issuer  *regexp.Regexp
		id      *regexp.Regexp
		want    []string
		cipher  string
	}{
		{
			profile: "okta",
			issuer:  regexp.MustCompile(`http://www\.okta\.com/exk[A-Za-z0-9]{16}`),
			id:      regexp.MustCompile(`id\d{26}`),
			want:    []string{"alice@example.com", "nameid-format:unspecified", ">firstName<", ">groups<", "attrname-format:unspecified"},
			cipher:  "xmlenc#aes256-cbc",
		},
		{
			profile: "entra",
			issuer:  regexp.MustCompile(`https://sts\.windows\.net/[0-9a-f-]{36}/`),
			id:      regexp.MustCompile(`_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`),
			want: []string{"alice@contoso.example", "nameid-format:emailAddress",
				"http://schemas.microsoft.com/identity/claims/tenantid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"},
			cipher: "xmlenc#aes256-cbc",
		},
		{
			profile: "shibboleth",
			issuer:  regexp.MustCompile(`http://127\.0\.0\.1:\d+/idp/[a-z0-9-]+/idp/shibboleth`),
			id:      regexp.MustCompile(`_[0-9a-f]{32}`),
			want: []string{"nameid-format:transient", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName",
				"urn:oasis:names:tc:SAML:attribute:pairwise-id", "member@"},
			cipher: "xmlenc11#aes128-gcm",
		},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			h := newHarness(t)
			resp, body := h.do(http.MethodPost, "/new/idp", url.Values{"profile": {tc.profile}})
			idpSecret := strings.TrimPrefix(resp.Request.URL.Path, "/manage/")
			idpID := regexp.MustCompile(`/idp/([a-z0-9-]+)/metadata`).FindStringSubmatch(body)[1]
			mustContain(t, body, "Profile: ")
			if !tc.issuer.MatchString(body) {
				t.Fatalf("no entity ID like %s on the manage page", tc.issuer)
			}

			spSecret, spID := h.create("sp")
			_, body = h.do(http.MethodPost, "/manage/"+spSecret+"/idp-set", url.Values{"metadata_url": {h.base + "/idp/" + idpID + "/metadata"}})
			mustContain(t, body, "saved")
			if !tc.issuer.MatchString(body) {
				t.Errorf("the SP does not show the IdP's entity ID")
			}

			body = h.loginAs(idpID, spID, "alice")
			mustContain(t, body, tc.want...)
			if !tc.issuer.MatchString(body) {
				t.Errorf("issuer not like %s", tc.issuer)
			}
			if !tc.id.MatchString(body) {
				t.Errorf("no assertion ID like %s", tc.id)
			}
			// The Response as received is encrypted with the profile's cipher.
			mustContain(t, body, tc.cipher)

			if tc.profile == "shibboleth" {
				_, md := h.do(http.MethodGet, "/idp/"+idpID+"/metadata", nil)
				mustContain(t, md, "urn:mace:shibboleth:metadata:1.0", idpID+".gosaml.dev")
			}

			// Single logout still works with the profile's session indexes.
			_, body = h.do(http.MethodPost, "/sp/"+spID+"/logout", nil)
			body = h.follow(body)
			mustContain(t, body, "Logged out everywhere")

			// Switching back to generic restores the library's shape.
			_, body = h.do(http.MethodPost, "/manage/"+idpSecret+"/profile", url.Values{"profile": {"generic"}})
			mustContain(t, body, "Profile Generic applied", h.base+"/idp/"+idpID+"/metadata")
		})
	}
}

// A pairwise-id is stable for a user at an SP, and different at each SP.
func TestPairwiseIDPerSP(t *testing.T) {
	attrs := []samlidp.Attribute{{Name: pairwiseIDName, Values: []string{"per-sp@x.gosaml.dev"}}, {Name: "mail", Values: []string{"a@b"}}}
	a1 := pairwiseAttributes(attrs, "idp", "alice", "https://sp1")
	a1again := pairwiseAttributes(attrs, "idp", "alice", "https://sp1")
	a2 := pairwiseAttributes(attrs, "idp", "alice", "https://sp2")
	if a1[0].Values[0] != a1again[0].Values[0] || a1[0].Values[0] == a2[0].Values[0] {
		t.Fatalf("%v %v %v", a1[0].Values, a1again[0].Values, a2[0].Values)
	}
	if !strings.HasSuffix(a1[0].Values[0], "@x.gosaml.dev") || a1[1].Values[0] != "a@b" || attrs[0].Values[0] != "per-sp@x.gosaml.dev" {
		t.Fatalf("%+v (input %+v)", a1, attrs)
	}
}
