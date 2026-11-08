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

func TestNewID(t *testing.T) {
	shape := regexp.MustCompile(`^[A-Za-z0-9]{10,}$`)
	seen := map[string]bool{}
	for range 1000 {
		id := newID()
		if !shape.MatchString(id) || seen[id] {
			t.Fatalf("id %q (seen before: %v)", id, seen[id])
		}
		seen[id] = true
		if n := idEncoder.Decode(id); len(n) != 1 {
			t.Fatalf("%q decodes to %v", id, n)
		}
	}
}
