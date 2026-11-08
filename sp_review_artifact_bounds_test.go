package saml

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// An oversized or non-printable SAMLart is refused before it reaches the
// ReplayCache or the IdP, even when non-standard artifacts are allowed.
func TestSPArtifactBounds(t *testing.T) {
	testCases := []struct {
		name     string
		artifact string
		ok       bool
	}{
		{"at the limit", strings.Repeat("A", maxArtifactLength), true},
		{"too long", strings.Repeat("A", maxArtifactLength+1), false},
		{"control byte", "abc\ndef", false},
		{"space", "abc def", false},
		{"non-ASCII", "abc\xc3\xa9", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			cache := &artifactKeyRecorder{}
			e.sp.ReplayCache = cache
			var calls atomic.Int32
			e.sp.HTTPClient = &http.Client{Transport: spcovRoundTripper(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("not reached in this test")
			})}

			_, err := e.sp.handleArtifactRequest(t.Context(), tc.artifact, []string{spcovRequestID})
			assert.Check(t, errors.Is(err, ErrArtifactResolution), "%v", err)
			if tc.ok {
				assert.Check(t, is.Equal(int32(1), calls.Load()))
				// The IdP did not resolve it, so it is not recorded.
				assert.Check(t, is.Len(cache.keys, 0))
				return
			}
			assert.Check(t, errors.Is(err, ErrMalformedMessage), "%v", err)
			assert.Check(t, is.Equal(int32(0), calls.Load()))
			assert.Check(t, is.Len(cache.keys, 0))
		})
	}
}

type artifactKeyRecorder struct{ keys []string }

func (c *artifactKeyRecorder) Consume(key string, _ time.Time) error {
	c.keys = append(c.keys, key)
	return nil
}
