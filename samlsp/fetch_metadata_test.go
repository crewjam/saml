package samlsp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchMetadata(t *testing.T) {
	test := NewMiddlewareTest()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/metadata", r.URL.String())
		fmt.Fprint(w, test.IDPMetadata)
	}))

	fmt.Println(testServer.URL + "/metadata")
	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.NoError(t, err)
	assert.Equal(t, "https://idp.testshib.org/idp/shibboleth", md.EntityID)
}
