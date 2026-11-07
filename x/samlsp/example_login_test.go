package samlsp_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// AuthnRequest returns a Message to send the browser to the IdP with. By
// default it uses HTTP-Redirect when the IdP supports it.
func ExampleConfig_AuthnRequest() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}

	msg, err := config.AuthnRequest(t0(), "relay-state-123")
	if err != nil {
		log.Fatal(err)
	}
	// Keep msg.ID until the Response arrives, keyed by the RelayState.
	fmt.Println(msg.Binding)
	fmt.Println(msg.Destination)

	u := msg.RedirectURL()
	fmt.Println(u.Query().Get("SAMLRequest") != "", u.Query().Get("RelayState"))
	// Output:
	// urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
	// https://idp.example.com/sso
	// true relay-state-123
}

// Message.Write sends the message. For the HTTP-POST binding it writes a
// page with a form that submits itself. WithScriptNonce adds a nonce to the
// form's script, for an application whose Content-Security-Policy allows
// scripts by nonce.
func ExampleConfig_AuthnRequest_post() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}

	msg, err := config.AuthnRequest(t0(), "relay-state-123",
		samlsp.WithBinding(saml.HTTPPostBinding),
		samlsp.WithScriptNonce("n0nce"))
	if err != nil {
		log.Fatal(err)
	}

	w := httptest.NewRecorder()
	msg.Write(w)
	fmt.Println(w.Code, w.Header().Get("Content-Type"))
	fmt.Println(strings.Contains(w.Body.String(), `action="https://idp.example.com/sso"`))
	fmt.Println(strings.Contains(w.Body.String(), `nonce="n0nce"`))
	// Output:
	// 200 text/html; charset=utf-8
	// true
	// true
}

// ForceAuthn makes the IdP authenticate the user again, for example before
// a sensitive operation. WithAuthnContext asks for a way to authenticate;
// passed to ParseResponse too, it refuses an assertion that does not
// satisfy it.
func ExampleWithAuthnContext() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}
	stepUp := samlsp.WithAuthnContext(samlsp.ComparisonExact,
		samlsp.AuthnContextMobileTwoFactorContract,
		samlsp.AuthnContextSmartcardPKI)

	http.HandleFunc("/settings/delete-account", func(w http.ResponseWriter, r *http.Request) {
		msg, err := config.AuthnRequest(r.Context(), rand.Text(), samlsp.ForceAuthn, stepUp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// remember msg.ID and msg.RelayState
		msg.Write(w)
	})

	http.HandleFunc("/saml/acs/step-up", func(w http.ResponseWriter, r *http.Request) {
		assertion, err := config.ParseResponse(r.Context(), r,
			samlsp.WithRequestID(takePendingRequest(r)), stepUp)
		if errors.Is(err, saml.ErrAuthnContextMismatch) {
			http.Error(w, "a second factor is required", http.StatusForbidden)
			return
		}
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
	})
}

// A comparison other than ComparisonExact needs an order of the classes,
// which WithAuthnContextComparator gives.
func ExampleWithAuthnContextComparator() {
	strength := map[samlsp.AuthnContextClass]int{
		samlsp.AuthnContextPassword:                   1,
		samlsp.AuthnContextPasswordProtectedTransport: 2,
		samlsp.AuthnContextMobileTwoFactorContract:    3,
		samlsp.AuthnContextSmartcardPKI:               4,
	}
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithAuthnContextComparator(func(comparison samlsp.AuthnContextComparison, requested []samlsp.AuthnContextClass, got samlsp.AuthnContextClass) bool {
			if comparison != samlsp.ComparisonMinimum {
				return false
			}
			for _, r := range requested {
				if strength[got] >= strength[r] && strength[got] > 0 {
					return true
				}
			}
			return false
		}))
	if err != nil {
		log.Fatal(err)
	}
	atLeastTwoFactor := samlsp.WithAuthnContext(samlsp.ComparisonMinimum, samlsp.AuthnContextMobileTwoFactorContract)
	_, _ = config, atLeastTwoFactor // pass to AuthnRequest and ParseResponse
}

// ParseResponse verifies the Response at the ACS. Its errors come from
// package saml and can be told apart with errors.Is and errors.As.
func ExampleConfig_ParseResponse() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		requestID := takePendingRequest(r)
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(requestID))

		var status saml.ErrBadStatus
		switch {
		case err == nil:
			startSession(w, assertion)
			http.Redirect(w, r, "/", http.StatusFound)
		case errors.As(err, &status):
			// The IdP answered, but did not log the user in.
			log.Printf("IdP refused login: %s", status.Status)
			http.Error(w, "login refused", http.StatusForbidden)
		case errors.Is(err, saml.ErrUntrustedCertificate):
			// The IdP may have rotated its signing certificate. RemoteMetadata
			// picks it up at its next refresh.
			log.Printf("untrusted signature: %v", errors.Unwrap(err))
			http.Error(w, "login failed", http.StatusForbidden)
		case errors.Is(err, saml.ErrExpired), errors.Is(err, saml.ErrNotYetValid):
			log.Printf("check the clocks of the IdP and the SP: %v", errors.Unwrap(err))
			http.Error(w, "login failed", http.StatusForbidden)
		default:
			// The message seen by the user is deliberately vague; the
			// detail is in errors.Unwrap(err).
			log.Printf("login failed: %v", errors.Unwrap(err))
			http.Error(w, "login failed", http.StatusForbidden)
		}
	})
}

// AllowUnsolicited accepts Responses that the IdP sends without an
// AuthnRequest (IdP-initiated login), such as from an IdP's app launcher.
// Their RelayState is not ours, so redirect only to a known local path.
func ExampleConfig_ParseResponse_unsolicited() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		opts := []samlsp.ResponseOption{samlsp.AllowUnsolicited}
		if id := takePendingRequest(r); id != "" {
			opts = append(opts, samlsp.WithRequestID(id))
		}
		assertion, err := config.ParseResponse(r.Context(), r, opts...)
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)

		target := "/"
		if assertion.InResponseTo == "" && r.FormValue("RelayState") == "/reports" {
			target = "/reports"
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
}

// IsPassive checks whether the user is already logged in at the IdP
// without showing them anything. If not, the IdP answers with the status
// NoPassive.
func Example_passiveLogin() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		msg, err := config.AuthnRequest(r.Context(), rand.Text(), samlsp.IsPassive)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// remember msg.ID and msg.RelayState
		msg.Write(w)
	})

	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(takePendingRequest(r)))
		var status saml.ErrBadStatus
		if errors.As(err, &status) {
			// Not logged in at the IdP (NoPassive), or the IdP cannot tell
			// without asking: show the anonymous page.
			http.Redirect(w, r, "/welcome", http.StatusFound)
			return
		}
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

// DecodeAttributes copies attributes into a struct, by Name or
// FriendlyName.
func ExampleAssertion_DecodeAttributes() {
	assertion := &samlsp.Assertion{ // as returned by ParseResponse
		Attributes: samlsp.Attributes{
			{Name: "urn:oid:0.9.2342.19200300.100.1.3", FriendlyName: "mail", Values: []string{"alice@example.com"}},
			{Name: "urn:oid:2.16.840.1.113730.3.1.241", FriendlyName: "displayName", Values: []string{"Alice"}},
			{Name: "memberOf", Values: []string{"admins", "users"}},
		},
	}

	var user struct {
		Email  string   `saml:"mail"`
		Name   string   `saml:"urn:oid:2.16.840.1.113730.3.1.241"`
		Groups []string `saml:"memberOf"`
		Phone  string   `saml:"telephoneNumber"` // absent: left as is
	}
	if err := assertion.DecodeAttributes(&user); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", user)
	// Output:
	// {Email:alice@example.com Name:Alice Groups:[admins users] Phone:}
}

// Get and Values look attributes up by Name or FriendlyName.
func ExampleAttributes_Get() {
	attrs := samlsp.Attributes{
		{Name: "urn:oid:0.9.2342.19200300.100.1.3", FriendlyName: "mail", Values: []string{"alice@example.com"}},
		{Name: "memberOf", Values: []string{"admins", "users"}},
	}
	fmt.Println(attrs.Get("mail"))
	fmt.Println(attrs.Get("urn:oid:0.9.2342.19200300.100.1.3"))
	fmt.Println(attrs.Values("memberOf"))
	fmt.Printf("%q\n", attrs.Get("missing"))
	// Output:
	// alice@example.com
	// alice@example.com
	// [admins users]
	// ""
}
