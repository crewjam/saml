package samlsp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
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
			require.Nil(t, err)
			cookieProvider := sp.Session.(CookieSessionProvider)
			assert.Equal(t, tc.expected, cookieProvider.Name)

		})
	}

}
