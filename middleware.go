package saml

import (
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml/metadata"
	"github.com/dgrijalva/jwt-go"
)

// ServiceProviderMiddleware implements middleware than allows a web application
// to support SAML.
//
// It implements http.Handler so that it can provide the metadata and ACS endpoints,
// typically /saml/metadata and /saml/acs, respectively.
//
// It also provides middleware, RequireAccountMiddleware which redirects users to
// the auth process if they do not have session credentials.
//
// You can stub in your session mechanism by providing values for
// IsAuthorizedFunc (called to determine if a request is already authorized) and
// AuthorizeFunc (called when the SAML response is received). The default
// implementations of these functions issue and verify a signed cookie containing
// information from the SAML assertion.
type ServiceProviderMiddleware struct {
	ServiceProvider *ServiceProvider
}

const cookieMaxAge = time.Hour // TODO(ross): must be configurable
const cookieName = "token"

// ServeHTTP implements http.Handler and serves the SAML-specific HTTP endpoints
// on the URIs specified by m.ServiceProvider.MetadataURL and
// m.ServiceProvider.AcsURL.
func (m *ServiceProviderMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metadataURL, _ := url.Parse(m.ServiceProvider.MetadataURL)
	if r.URL.Path == metadataURL.Path {
		buf, _ := xml.MarshalIndent(metadata.EntitiesDescriptor{
			EntityDescriptor: []*metadata.Metadata{m.ServiceProvider.Metadata()},
		}, "", "  ")
		w.Write(buf)
		return
	}

	acsURL, _ := url.Parse(m.ServiceProvider.AcsURL)
	if r.URL.Path == acsURL.Path {
		r.ParseForm()
		assertion, err := m.ServiceProvider.ParseResponse(r, m.getPossibleRequestIDs(r))
		if err != nil {
			if parseErr, ok := err.(*InvalidResponseError); ok {
				log.Printf("RESPONSE: ===\n%s\n===\nNOW: %s\nERROR: %s",
					parseErr.Response, parseErr.Now, parseErr.PrivateErr)
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		m.Authorize(w, r, assertion)
		return
	}

	http.NotFoundHandler().ServeHTTP(w, r)
}

// RequireAccountMiddleware is HTTP middleware that requires that each request be
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middlware redirects the user
// to start the SAML auth flow.
func (m *ServiceProviderMiddleware) RequireAccountMiddleware(handler http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if m.IsAuthorized(r) {
			handler.ServeHTTP(w, r)
			return
		}

		// If we try to redirect when the original request is the ACS URL we'll
		// end up in a loop. This is a programming error, so we panic here. In
		// general this means a 500 to the user, which is preferable to a
		// redirect loop.
		acsURL, _ := url.Parse(m.ServiceProvider.AcsURL)
		if r.URL.Path == acsURL.Path {
			panic("don't wrap ServiceProviderMiddleware with RequireAccountMiddleware")
		}

		req, err := m.ServiceProvider.MakeAuthenticationRequest(
			m.ServiceProvider.GetSSOBindingLocation(HTTPRedirectBinding))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// relayState is limited to 80 bytes but also must be integrety protected.
		// this means that we cannot use a JWT because it is way to long. Instead
		// we set a cookie that corresponds to the state
		relayState := base64.StdEncoding.EncodeToString(randomBytes(42))

		secretBlock, _ := pem.Decode([]byte(m.ServiceProvider.Key))
		state := jwt.New(jwt.GetSigningMethod("HS256"))
		state.Claims["id"] = req.ID
		state.Claims["uri"] = r.URL.String()
		signedState, err := state.SignedString(secretBlock.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     fmt.Sprintf("saml_%s", relayState),
			Value:    signedState,
			MaxAge:   int(MaxIssueDelay.Seconds()),
			HttpOnly: false,
			Path:     acsURL.Path,
		})
		redirectURL := req.Redirect(relayState)

		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	return http.HandlerFunc(fn)
}

func (m *ServiceProviderMiddleware) getPossibleRequestIDs(r *http.Request) []string {
	rv := []string{}
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, "saml_") {
			continue
		}
		log.Printf("getPossibleRequestIDs: cookie: %s", cookie.String())
		token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
			secretBlock, _ := pem.Decode([]byte(m.ServiceProvider.Key))
			return secretBlock.Bytes, nil
		})
		if err != nil || !token.Valid {
			log.Printf("... invalid token %s", err)
			continue
		}
		rv = append(rv, token.Claims["id"].(string))
	}
	return rv
}

// Authorize is invoked by ServeHTTP when we have a new, valid SAML assertion.
// It sets a cookie that contains a signed JWT containing the assertion attributes.
// It then redirects the user's browser to the original URL contained in RelayState.
func (m *ServiceProviderMiddleware) Authorize(w http.ResponseWriter, r *http.Request, assertion *Assertion) {
	secretBlock, _ := pem.Decode([]byte(m.ServiceProvider.Key))

	redirectURI := "/"
	if r.Form.Get("RelayState") != "" {
		stateCookie, err := r.Cookie(fmt.Sprintf("saml_%s", r.Form.Get("RelayState")))
		if err != nil {
			log.Printf("cannot find corresponding cookie: %s", fmt.Sprintf("saml_%s", r.Form.Get("RelayState")))
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		state, err := jwt.Parse(stateCookie.Value, func(t *jwt.Token) (interface{}, error) {
			return secretBlock.Bytes, nil
		})
		if err != nil || !state.Valid {
			log.Printf("Cannot decode state JWT: %s (%s)", err, stateCookie.Value)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		redirectURI = state.Claims["uri"].(string)

		// delete the cookie
		stateCookie.Value = ""
		stateCookie.Expires = time.Time{}
		http.SetCookie(w, stateCookie)
	}

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	for _, attr := range assertion.AttributeStatement.Attributes {
		valueStrings := []string{}
		for _, v := range attr.Values {
			valueStrings = append(valueStrings, v.Value)
		}
		if len(valueStrings) == 1 || true { // TODO(ross): use an array if there are multiple values (or something)
			token.Claims[attr.FriendlyName] = valueStrings[len(valueStrings)-1]
		} else {
			token.Claims[attr.FriendlyName] = valueStrings
		}
	}
	token.Claims["exp"] = timeNow().Add(cookieMaxAge).Unix()
	signedToken, err := token.SignedString(secretBlock.Bytes)
	if err != nil {
		panic(err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    signedToken,
		MaxAge:   int(cookieMaxAge.Seconds()),
		HttpOnly: false,
		Path:     "/",
	})

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// IsAuthorized is invoked by RequireAccountMiddleware to determine if the request
// is already authorized or if the user's browser should be redirected to the
// SAML login flow. If the request is authorized, then the request headers
// starting with X-Saml- for each SAML assertion attribute are set. For example,
// if an attribute "uid" has the value "alice@example.com", then the following
// header would be added to the request:
//
//     X-Saml-Uid: alice@example.com
//
// It is an error for this function to be invoked with a request containing
// any headers starting with X-Saml. This function will panic if you do.
func (m *ServiceProviderMiddleware) IsAuthorized(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
		secretBlock, _ := pem.Decode([]byte(m.ServiceProvider.Key))
		return secretBlock.Bytes, nil
	})
	if err != nil || !token.Valid {
		return false
	}

	// It is an error for the request to include any X-SAML* headers,
	// because those might be confused with ours. If we encounter any
	// such headers, we abort the request, so there is no confustion.
	for headerName := range r.Header {
		if strings.HasPrefix(headerName, "X-Saml") {
			panic("X-Saml-* headers should not exist when this function is called")
		}
	}

	for claimName, claimValue := range token.Claims {
		if c, ok := claimValue.(string); ok {
			r.Header.Set(fmt.Sprintf("X-Saml-%s", claimName), c)
		}
	}
	return true
}

// RequireAttribute returns a middleware function that requires that the
// SAML attribute `name` be set to `value`. This can be used to require
// that a remote user be a member of a group. It relies on the X-Saml-* headers
// that RequireAccountMiddleware adds to the request.
//
// For example:
//
//     goji.Use(m.RequireAccountMiddleware)
//     goji.Use(RequireAttributeMiddleware("eduPersonAffiliation", "Staff"))
//
func RequireAttribute(name, value string) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if values, ok := r.Header[http.CanonicalHeaderKey(fmt.Sprintf("X-Saml-%s", name))]; ok {
				for _, actualValue := range values {
					if actualValue == value {
						handler.ServeHTTP(w, r)
						return
					}
				}
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}
		return http.HandlerFunc(fn)
	}
}
