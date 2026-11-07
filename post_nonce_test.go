package saml

import (
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestPostWithNonce(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 31, 21, 0, time.UTC)
	authnReq := &AuthnRequest{ID: "id-1", Destination: "https://idp.example.com/sso", IssueInstant: now}
	logoutReq := &LogoutRequest{ID: "id-1", Destination: "https://idp.example.com/slo", IssueInstant: now}
	logoutResp := &LogoutResponse{ID: "id-1", Destination: "https://idp.example.com/slo", IssueInstant: now}
	forms := []struct {
		name          string
		post          func(relayState string) []byte
		postWithNonce func(relayState, nonce string) []byte
	}{
		{"AuthnRequest", authnReq.Post, authnReq.PostWithNonce},
		{"LogoutRequest", logoutReq.Post, logoutReq.PostWithNonce},
		{"LogoutResponse", logoutResp.Post, logoutResp.PostWithNonce},
	}

	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			// without a nonce the output is exactly what Post produces
			plain := string(f.post("relayState"))
			assert.Check(t, is.Equal(plain, string(f.postWithNonce("relayState", ""))))
			assert.Check(t, is.Contains(plain, "<script>"))
			assert.Check(t, !strings.Contains(plain, "nonce"))

			withNonce := string(f.postWithNonce("relayState", "rAnd0m+/="))
			assert.Check(t, is.Contains(withNonce, `<script nonce="rAnd0m&#43;/=">`))
			// only the <script> start tag changes
			assert.Check(t, is.Equal(plain, strings.Replace(withNonce, ` nonce="rAnd0m&#43;/="`, "", 1)))

			// the nonce is escaped and cannot break out of the attribute
			evil := string(f.postWithNonce("relayState", `"><script>alert(1)</script>`))
			assert.Check(t, is.Contains(evil, `<script nonce="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">`))
			assert.Check(t, is.Equal(2, strings.Count(evil, "<script")+strings.Count(evil, "</script>")))
		})
	}
}
