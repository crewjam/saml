package server

import (
	"regexp"
	"testing"
)

func TestInstanceNames(t *testing.T) {
	id := regexp.MustCompile(`^[a-z]+-[a-z]+$`)
	secret := regexp.MustCompile(`^[a-z]+-[a-z]+-[a-z]+$`)
	for range 100 {
		if n := newInstanceID(0); !id.MatchString(n) {
			t.Errorf("id %q", n)
		}
		if n := newInstanceSecret(0); !secret.MatchString(n) {
			t.Errorf("secret %q", n)
		}
	}
	// After a few names that were taken, a number makes a free one likely.
	if n := newInstanceID(3); !regexp.MustCompile(`^[a-z]+-[a-z]+-\d{3}$`).MatchString(n) {
		t.Errorf("numbered id %q", n)
	}
}
