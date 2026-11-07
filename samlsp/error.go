package samlsp

import (
	"errors"
	"log"
	"net/http"

	"github.com/crewjam/saml"
)

// ErrorFunction is a callback that is invoked to return an error to the
// web user.
type ErrorFunction func(w http.ResponseWriter, r *http.Request, err error)

// DefaultOnError is the default ErrorFunction implementation. It prints
// a message via the standard log package and returns a simple text
// "Forbidden" message to the user. If err is, or wraps, a
// *saml.InvalidResponseError, its private details are logged.
func DefaultOnError(w http.ResponseWriter, _ *http.Request, err error) {
	var parseErr *saml.InvalidResponseError
	if errors.As(err, &parseErr) {
		log.Printf("WARNING: received invalid saml response: %s (now: %s) %s", //nolint:gosec // logging the invalid response is intended
			parseErr.Response, parseErr.Now, parseErr.PrivateErr)
	} else {
		log.Printf("ERROR: %s", err)
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
