package samlsp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// When HandleStartAuthFlow cannot start the login, the client gets a bare
// 500: the error, which can describe the SP's keys, signing configuration,
// IdP metadata or session store, is only logged.
func TestHandleStartAuthFlowErrorsAreNotSentToTheClient(t *testing.T) {
	const internal = "cov-secret-detail"
	for name, configure := range map[string]func(test *MiddlewareTest){
		"make request": func(test *MiddlewareTest) {
			test.Middleware.Binding = saml.HTTPPostBinding
			test.Middleware.ServiceProvider.SignatureMethod = internal
		},
		"track request": func(test *MiddlewareTest) {
			test.Middleware.RequestTracker = covRequestTracker{
				CookieRequestTracker: test.Middleware.RequestTracker.(CookieRequestTracker),
				trackErr:             errors.New(internal),
			}
		},
		"redirect": func(test *MiddlewareTest) {
			test.Middleware.ServiceProvider.SignatureMethod = internal
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := covNewMiddlewareTest(t)
			configure(test)
			rec := httptest.NewRecorder()
			test.Middleware.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
			assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
			assert.Check(t, is.Equal(http.StatusText(http.StatusInternalServerError), strings.TrimSpace(rec.Body.String())))
		})
	}
}
