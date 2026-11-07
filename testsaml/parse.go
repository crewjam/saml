// Package testsaml contains functions for use in testing SAML requests and responses.
package testsaml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
)

// MaxDecompressedSize is the largest decompressed message ParseRedirectRequest
// and ParseRedirectResponse will return. It matches the limit the saml package
// applies to the HTTP-Redirect binding, so a test helper never inflates more
// than the library would accept.
const MaxDecompressedSize = 1024 * 1024

// ErrTooLarge is returned when a decompressed message exceeds
// MaxDecompressedSize.
var ErrTooLarge = errors.New("decompressed message is too large")

// ParseRedirectRequest returns the decoded SAML AuthnRequest from an HTTP-Redirect URL
func ParseRedirectRequest(u *url.URL) ([]byte, error) {
	return parseRedirect(u, "SAMLRequest", "request")
}

// ParseRedirectResponse returns the decoded SAML LogoutResponse from an HTTP-Redirect URL
func ParseRedirectResponse(u *url.URL) ([]byte, error) {
	return parseRedirect(u, "SAMLResponse", "response")
}

func parseRedirect(u *url.URL, param, what string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(u.Query().Get(param))
	if err != nil {
		return nil, fmt.Errorf("cannot decode %s: %w", what, err)
	}
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close() //nolint:errcheck // closing a flate reader over a bytes.Reader cannot fail meaningfully
	buf, err := io.ReadAll(io.LimitReader(r, MaxDecompressedSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot decompress %s: %w", what, err)
	}
	if len(buf) > MaxDecompressedSize {
		return nil, fmt.Errorf("cannot decompress %s: %w", what, ErrTooLarge)
	}
	return buf, nil
}
