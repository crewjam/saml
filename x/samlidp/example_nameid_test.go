package samlidp_test

import (
	"errors"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
)

// This example answers a login request with a NameID that SPs cannot
// correlate: a new transient NameID at each login for an SP that asks for
// one, and otherwise a persistent NameID of its own (or of the
// affiliation it asks for), derived from the user's ID under a secret key.
func ExampleConfig_SetNameID() {
	var (
		config *samlidp.Config
		// nameIDKey is a secret, random key of at least
		// samlidp.MinPairwiseKeySize bytes, loaded from the IdP's
		// secret store. It must not change: every persistent NameID
		// depends on it.
		nameIDKey []byte
	)

	continueLogin := func(w http.ResponseWriter, r *http.Request, req *samlidp.AuthnRequest, u *user) {
		subject := samlidp.Subject{
			AuthnInstant: u.LoginTime,
		}
		err := config.SetNameID(r.Context(), req, &subject, nameIDKey, u.ID)
		var msg *samlidp.Message
		if err == nil {
			msg, err = config.Response(r.Context(), req, subject)
		}
		var status *saml.StatusError
		if errors.As(err, &status) {
			// The SP asked for what the IdP will not assert, such as an
			// affiliation it is not a member of.
			msg, err = config.ErrorResponse(r.Context(), req, status)
		}
		if err != nil {
			http.Error(w, "cannot answer the login request", http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	}
	_ = continueLogin
}
