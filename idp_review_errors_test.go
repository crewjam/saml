package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// A ServiceProviderProvider that wraps os.ErrNotExist, as its documentation
// allows errors to be wrapped elsewhere in Go, is still understood as
// "unknown service provider".
func TestIDPUnknownServiceProviderWrappedErrNotExist(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, id string) (*EntityDescriptor, error) {
			return nil, fmt.Errorf("lookup %s: %w", id, os.ErrNotExist)
		},
	}

	w := httptest.NewRecorder()
	test.IDP.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/login", nil), "https://unknown.example.com/metadata", "")
	assert.Check(t, is.Equal(http.StatusNotFound, w.Code))

	_, err := test.IDP.NewIdpInitiatedRequest(httptest.NewRequest(http.MethodGet, "https://idp.example.com/login", nil), "https://unknown.example.com/metadata", "")
	assert.Check(t, errors.Is(err, ErrUnknownServiceProvider), "%v", err)

	redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("")
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, httptest.NewRequest(http.MethodGet, redirectURL.String(), nil))
	assert.NilError(t, err)
	err = req.Validate()
	assert.Check(t, errors.Is(err, ErrUnknownServiceProvider), "%v", err)
}

// Invalid XML in an HTTP-Redirect message to the SP is reported like every
// other failure of that path: as an *InvalidResponseError that matches
// ErrMalformedMessage.
func TestSPRedirectBindingInvalidXMLIsInvalidResponseError(t *testing.T) {
	test := newSLOTest(t)
	var compressed bytes.Buffer
	fw, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	assert.NilError(t, err)
	// Nested deeper than xmlroundtrip.Validate allows.
	deep := strings.Repeat("<a>", xmlroundtrip.MaxDepth+1) + strings.Repeat("</a>", xmlroundtrip.MaxDepth+1)
	_, err = fw.Write([]byte(deep))
	assert.NilError(t, err)
	assert.NilError(t, fw.Close())
	q := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(compressed.Bytes())}}
	r := httptest.NewRequest(http.MethodGet, test.SP.SloURL.String()+"?"+q.Encode(), nil)

	_, err = test.SP.ParseLogoutResponse(r, []string{"id-1"})
	var ire *InvalidResponseError
	assert.Assert(t, errors.As(err, &ire), "%T: %v", err, err)
	assert.Check(t, errors.Is(err, ErrMalformedMessage), "%v", ire.PrivateErr)
	assert.Check(t, errors.Is(err, xmlroundtrip.ErrTooDeep), "%v", ire.PrivateErr)
}
