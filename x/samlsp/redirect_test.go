package samlsp_test

import (
	"testing"

	"github.com/crewjam/saml/x/samlsp"
)

func TestSafeRedirectPath(t *testing.T) {
	for _, tt := range []struct {
		p    string
		safe bool
	}{
		{"/", true},
		{"/reports", true},
		{"/reports/7/", true},
		{"/links?x=1&next=//not-a-host", true},
		{"/a#frag", true},
		{"/a#//frag", true},
		{"/caf%C3%A9", true},
		{"/café", true},
		{"/a/../b", true},
		{"/%2F%2Fevil.example", true}, // browsers do not decode it in the path

		{"", false},
		{"evil.example", false},
		{"reports", false},
		{"./reports", false},
		{"https://evil.example", false},
		{"http:/evil.example", false},
		{"javascript:alert(1)", false},
		{"//evil.example", false},
		{"///evil.example", false},
		{"/\\evil.example", false},
		{"/a\\b", false},
		{"\\\\evil.example", false},
		{"/a//b", false},
		{"/..//evil.example", false},
		{"/\t/evil.example", false},
		{"/\n/evil.example", false},
		{"/\r/evil.example", false},
		{"/\x00", false},
		{"/\x7f", false},
		{"/ /evil.example", false},
		{" /x", false},
		{"/x ", false},
		{"/\u00a0/evil.example", false},
		{"/\u2028", false},
		{"/\u200b/evil.example", false},
		{"/\ufeff", false},
		{"/\xff", false},
		{"/%zz", false},
	} {
		got, ok := samlsp.SafeRedirectPath(tt.p)
		if ok != tt.safe {
			t.Errorf("SafeRedirectPath(%q) safe = %v, want %v", tt.p, ok, tt.safe)
		}
		want := "/"
		if tt.safe {
			want = tt.p
		}
		if got != want {
			t.Errorf("SafeRedirectPath(%q) = %q, want %q", tt.p, got, want)
		}
	}
}
