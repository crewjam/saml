package samlsp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestNewCanAcceptCookieName(t *testing.T) {

	testCases := []struct {
		testName   string
		cookieName string
		expected   string
	}{
		{"Works with alt name", "altCookie", "altCookie"},
		{"Works with default", "", "token"},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			opts := Options{
				CookieName: tc.cookieName,
			}
			sp, err := New(opts)
			assert.Assert(t, err)
			cookieProvider := sp.Session.(CookieSessionProvider)
			assert.Equal(t, tc.expected, cookieProvider.Name)

		})
	}

}

func TestNewCanAcceptEndpointPaths(t *testing.T) {
	testCases := []struct {
		testName                             string
		baseURL                              string
		metadataPath, acsPath, sloPath       string
		expectMetadata, expectAcs, expectSlo string
	}{
		{"defaults", "https://sp.example.com/", "", "", "",
			"https://sp.example.com/saml/metadata", "https://sp.example.com/saml/acs", "https://sp.example.com/saml/slo"},
		{"defaults under base path", "https://sp.example.com/app/", "", "", "",
			"https://sp.example.com/app/saml/metadata", "https://sp.example.com/app/saml/acs", "https://sp.example.com/app/saml/slo"},
		{"relative custom paths", "https://sp.example.com/app/", "sso/meta", "sso/callback", "sso/logout",
			"https://sp.example.com/app/sso/meta", "https://sp.example.com/app/sso/callback", "https://sp.example.com/app/sso/logout"},
		{"absolute custom paths", "https://sp.example.com/app/", "/meta", "/callback", "/logout",
			"https://sp.example.com/meta", "https://sp.example.com/callback", "https://sp.example.com/logout"},
		{"partial override", "https://sp.example.com/", "", "auth/acs", "",
			"https://sp.example.com/saml/metadata", "https://sp.example.com/auth/acs", "https://sp.example.com/saml/slo"},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			baseURL, err := url.Parse(tc.baseURL)
			assert.Assert(t, err)
			m, err := New(Options{
				URL:          *baseURL,
				MetadataPath: tc.metadataPath,
				AcsPath:      tc.acsPath,
				SloPath:      tc.sloPath,
			})
			assert.Assert(t, err)
			assert.Equal(t, tc.expectMetadata, m.ServiceProvider.MetadataURL.String())
			assert.Equal(t, tc.expectAcs, m.ServiceProvider.AcsURL.String())
			assert.Equal(t, tc.expectSlo, m.ServiceProvider.SloURL.String())

			// The middleware serves the configured endpoints.
			req := httptest.NewRequest(http.MethodGet, tc.expectMetadata, nil)
			resp := httptest.NewRecorder()
			m.ServeHTTP(resp, req)
			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Assert(t, strings.Contains(resp.Body.String(), tc.expectAcs))
		})
	}
}

func TestDefaultServiceProviderAcsIndex(t *testing.T) {
	sp := DefaultServiceProvider(Options{URL: url.URL{Scheme: "https", Host: "sp.example.com"}})
	assert.Assert(t, sp.AcsIndex == nil)

	index := 2
	sp = DefaultServiceProvider(Options{URL: url.URL{Scheme: "https", Host: "sp.example.com"}, AcsIndex: &index})
	assert.Assert(t, sp.AcsIndex != nil)
	assert.Equal(t, 2, *sp.AcsIndex)
}
