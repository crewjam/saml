// Package testsaml contains functions for use in testing SAML requests and responses.
package testsaml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
)

// ParseRedirectRequest returns the decoded SAML AuthnRequest from an HTTP-Redirect URL
func ParseRedirectRequest(u *url.URL) ([]byte, error) {
	compressedRequest, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		return nil, fmt.Errorf("cannot decode request: %s", err)
	}
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressedRequest)))
	if err != nil {
		return nil, fmt.Errorf("cannot decompress request: %s", err)
	}
	return buf, nil
}

// ParseRedirectResponse returns the decoded SAML LogoutResponse from an HTTP-Redirect URL
func ParseRedirectResponse(u *url.URL) ([]byte, error) {
	compressedResponse, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLResponse"))
	if err != nil {
		return nil, fmt.Errorf("cannot decode response: %s", err)
	}
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressedResponse)))
	if err != nil {
		return nil, fmt.Errorf("cannot decompress response: %s", err)
	}
	return buf, nil
}
