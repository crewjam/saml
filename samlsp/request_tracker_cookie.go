package samlsp

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

var _ RequestTracker = CookieRequestTracker{}

// CookieRequestTracker tracks requests by setting a uniquely named
// cookie for each request.
//
// The cookie must be sent back by the browser when the IDP POSTs the SAML
// response to the ACS URL, which is a cross-site request. Browsers treat a
// cookie without a SameSite attribute as SameSite=Lax and do not send it on a
// cross-site POST, so when SameSite is unset (zero or http.SameSiteDefaultMode)
// and the ACS URL uses https, the cookie is issued with SameSite=None (and Secure). Set
// SameSite explicitly to override this.
type CookieRequestTracker struct {
	ServiceProvider *saml.ServiceProvider
	NamePrefix      string
	Codec           TrackedRequestCodec
	MaxAge          time.Duration
	RelayStateFunc  func(w http.ResponseWriter, r *http.Request) string
	SameSite        http.SameSite

	// Path is the Path attribute of the tracking cookies, which must cover
	// the endpoint the IDP answers at. If empty, it is the path of the ACS
	// URL.
	Path string
}

func (t CookieRequestTracker) cookiePath() string {
	if t.Path != "" {
		return t.Path
	}
	return t.ServiceProvider.AcsURL.Path
}

// encodedIndexMarker starts the cookie-name form of an index that is not
// itself usable in a cookie name. It is a valid cookie-name character that
// base64url never produces, and an index used as-is never starts with it, so
// the two forms cannot collide.
const encodedIndexMarker = "~"

// cookieName returns the name of the cookie that tracks the request with the
// given index. An index is the RelayState sent to the IdP; the default one is
// base64url and is used as-is. One from RelayStateFunc may hold characters a
// cookie name cannot (a path or URL has '/', '?' and '='); browsers and
// http.SetCookie drop such a cookie, so that index is base64url-encoded.
func (t CookieRequestTracker) cookieName(index string) string {
	if isCookieNameToken(index) && !strings.HasPrefix(index, encodedIndexMarker) {
		return t.NamePrefix + index
	}
	return t.NamePrefix + encodedIndexMarker + base64.RawURLEncoding.EncodeToString([]byte(index))
}

// isCookieNameToken reports whether s is non-empty and made only of the
// characters RFC 6265 allows in a cookie name (an RFC 2616 token).
func isCookieNameToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}

// TrackRequest starts tracking the SAML request with the given ID. It returns an
// `index` that should be used as the RelayState in the SAMl request flow.
func (t CookieRequestTracker) TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (string, error) {
	trackedRequest := TrackedRequest{
		Index:         base64.RawURLEncoding.EncodeToString(randomBytes(42)),
		SAMLRequestID: samlRequestID,
		URI:           r.URL.String(),
	}

	if t.RelayStateFunc != nil {
		relayState := t.RelayStateFunc(w, r)
		if t.ServiceProvider.LimitRelayStateLength && len(relayState) > saml.MaxRelayStateLength {
			return "", fmt.Errorf("RelayStateFunc returned %d bytes, longer than the %d the SAML bindings allow for a RelayState: %w", len(relayState), saml.MaxRelayStateLength, saml.ErrRelayStateTooLong)
		}
		if relayState != "" {
			trackedRequest.Index = relayState
		}
	}

	signedTrackedRequest, err := t.Codec.Encode(trackedRequest)
	if err != nil {
		return "", err
	}

	secure := t.ServiceProvider.AcsURL.Scheme == "https"
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set when served over https
		Name:     t.cookieName(trackedRequest.Index),
		Value:    signedTrackedRequest,
		MaxAge:   int(t.MaxAge.Seconds()),
		HttpOnly: true,
		SameSite: t.sameSite(secure),
		Secure:   secure,
		Path:     t.cookiePath(),
	})

	return trackedRequest.Index, nil
}

// sameSite returns the SameSite mode for the tracking cookie. An unset mode
// becomes SameSite=None on a secure cookie, so that the browser sends the cookie
// with the IDP's cross-site POST to the ACS URL. Browsers reject SameSite=None
// without Secure, so an insecure cookie keeps the configured mode.
func (t CookieRequestTracker) sameSite(secure bool) http.SameSite {
	if (t.SameSite == 0 || t.SameSite == http.SameSiteDefaultMode) && secure {
		return http.SameSiteNoneMode
	}
	return t.SameSite
}

// StopTrackingRequest stops tracking the SAML request given by index, which is a string
// previously returned from TrackRequest
func (t CookieRequestTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error {
	cookie, err := r.Cookie(t.cookieName(index))
	if err != nil {
		return err
	}
	// TrackRequest sets a host-only cookie, so delete it without a Domain
	// attribute: browsers treat a cookie with Domain set as a different cookie
	// and would keep the tracked request.
	cookie.Value = ""
	cookie.Domain = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	cookie.Path = t.cookiePath()
	cookie.Secure = t.ServiceProvider.AcsURL.Scheme == "https"
	cookie.SameSite = t.sameSite(cookie.Secure)
	http.SetCookie(w, cookie)
	return nil
}

// GetTrackedRequests returns all the pending tracked requests
func (t CookieRequestTracker) GetTrackedRequests(r *http.Request) []TrackedRequest {
	rv := []TrackedRequest{}
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, t.NamePrefix) {
			continue
		}

		trackedRequest, err := t.Codec.Decode(cookie.Value)
		if err != nil {
			continue
		}
		if cookie.Name != t.cookieName(trackedRequest.Index) {
			continue
		}

		rv = append(rv, *trackedRequest)
	}
	return rv
}

// GetTrackedRequest returns a pending tracked request.
func (t CookieRequestTracker) GetTrackedRequest(r *http.Request, index string) (*TrackedRequest, error) {
	cookie, err := r.Cookie(t.cookieName(index))
	if err != nil {
		return nil, err
	}

	trackedRequest, err := t.Codec.Decode(cookie.Value)
	if err != nil {
		return nil, err
	}
	if trackedRequest.Index != index {
		return nil, fmt.Errorf("expected index %q, got %q", index, trackedRequest.Index)
	}
	return trackedRequest, nil
}
