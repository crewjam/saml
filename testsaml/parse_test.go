package testsaml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func covDeflate(t *testing.T, data string) string {
	t.Helper()
	buf := &bytes.Buffer{}
	w, err := flate.NewWriter(buf, flate.DefaultCompression)
	assert.NilError(t, err)
	_, err = w.Write([]byte(data))
	assert.NilError(t, err)
	assert.NilError(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func covURL(param, value string) *url.URL {
	return &url.URL{
		Scheme:   "https",
		Host:     "idp.example.com",
		Path:     "/saml",
		RawQuery: url.Values{param: {value}}.Encode(),
	}
}

func TestParseRedirect(t *testing.T) {
	const payload = `<samlp:AuthnRequest ID="id-1"></samlp:AuthnRequest>`
	type parseFunc func(*url.URL) ([]byte, error)
	for _, tc := range []struct {
		name  string
		param string
		parse parseFunc
		kind  string
	}{
		{"request", "SAMLRequest", ParseRedirectRequest, "request"},
		{"response", "SAMLResponse", ParseRedirectResponse, "response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := tc.parse(covURL(tc.param, covDeflate(t, payload)))
			assert.NilError(t, err)
			assert.Check(t, is.Equal(payload, string(buf)))

			// empty parameter decodes to an empty (and therefore truncated) stream
			_, err = tc.parse(covURL(tc.param, ""))
			assert.Check(t, is.ErrorContains(err, "cannot decompress "+tc.kind))

			// the other parameter is ignored
			other := "SAMLResponse"
			if tc.param == other {
				other = "SAMLRequest"
			}
			_, err = tc.parse(covURL(other, covDeflate(t, payload)))
			assert.Check(t, is.ErrorContains(err, "cannot decompress "+tc.kind))

			_, err = tc.parse(covURL(tc.param, "!!!not base64"))
			assert.Check(t, is.ErrorContains(err, "cannot decode "+tc.kind))

			_, err = tc.parse(covURL(tc.param, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xff", 16)))))
			assert.Check(t, is.ErrorContains(err, "cannot decompress "+tc.kind))
		})
	}
}
