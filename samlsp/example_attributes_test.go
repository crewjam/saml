package samlsp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/golang-jwt/jwt/v5"

	"github.com/crewjam/saml/samlsp"
)

// This example shows how a handler wrapped by Middleware.RequireAccount reads
// the user's identity from the SAML assertion.
//
// The default session (a JWTSessionClaims) keeps the assertion's Subject
// NameID as the JWT subject and each attribute under its FriendlyName, or its
// Name when there is no FriendlyName. Which attributes are present, and what
// they are called, is up to the identity provider.
func Example_attributes() {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// A single attribute value:
		email := samlsp.AttributeFromContext(r.Context(), "mail")
		fmt.Println("mail:", email)

		session := samlsp.SessionFromContext(r.Context())

		// All values of an attribute:
		if s, ok := session.(samlsp.SessionWithAttributes); ok {
			fmt.Println("groups:", s.GetAttributes()["eduPersonAffiliation"])
		}

		// The NameID from the assertion's Subject:
		if claims, ok := session.(samlsp.JWTSessionClaims); ok {
			fmt.Println("NameID:", claims.Subject)
		}
	})

	// In a real service, RequireAccount puts the session in the request
	// context. Here we put one there by hand.
	session := samlsp.JWTSessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "jdoe@example.com"},
		Attributes: samlsp.Attributes{
			"mail":                 {"jdoe@example.com"},
			"eduPersonAffiliation": {"member", "staff"},
		},
	}
	r := httptest.NewRequest("GET", "/hello", nil)
	r = r.WithContext(samlsp.ContextWithSession(r.Context(), session))
	handler.ServeHTTP(httptest.NewRecorder(), r)

	// Output:
	// mail: jdoe@example.com
	// groups: [member staff]
	// NameID: jdoe@example.com
}
