package samlidp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml"
)

var sessionMaxAge = time.Hour

// dummyPasswordHash is compared against the submitted password when the user
// does not exist (or has no usable password hash), so that every login attempt
// costs the same bcrypt work. It is a hash of a random value at
// bcrypt.DefaultCost, the cost HandlePutUser uses for real passwords. A
// successful comparison against it never authenticates anyone.
var dummyPasswordHash = []byte("$2a$10$Ovb3BvjFgCzUJjLMY9KjI.vCmY12QV6y0QrT6LdUAT6e/C2NMUx7m")

// compareHashAndPassword is a variable so tests can observe which hash is used.
var compareHashAndPassword = bcrypt.CompareHashAndPassword

// isBcryptHash reports whether hash is a well-formed bcrypt hash that
// bcrypt.CompareHashAndPassword will actually do the hashing work for.
func isBcryptHash(hash []byte) bool {
	_, err := bcrypt.Cost(hash)
	return err == nil
}

// GetSession returns the *Session for this request.
//
// If the remote user has specified a username and password in the request
// then it is validated against the user database. If valid it sets a
// cookie and returns the newly created session object.
//
// If the remote user has specified invalid credentials then a login form
// is returned with an English-language toast telling the user their
// password was invalid.
//
// If a session cookie already exists and represents a valid session,
// then the session is returned, unless the AuthnRequest has
// ForceAuthn="true": the user must then authenticate again, so the login
// form is sent and the assertion that follows carries a new AuthnInstant
// (saml-core §3.4.1).
//
// If neither credentials nor a usable session exist, this function sends a
// login form and returns nil. If the AuthnRequest has IsPassive="true", it
// sends no login form: it answers with a SAML error Response with the
// status Responder and the second-level status NoPassive instead
// (saml-core §3.4.1 and §3.2.2.2). A passive request with a usable session
// gets that session as usual.
func (s *Server) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	// if we received login credentials then maybe we can create a session
	if r.Method == "POST" && r.PostForm.Get("user") != "" {
		return s.authenticate(w, r, req)
	}

	if !isTrue(req.Request.ForceAuthn) {
		session, err := s.lookupSession(r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}
		if session != nil {
			return session
		}
	}

	s.promptLogin(w, req, "")
	return nil
}

// authenticate checks the username and password posted in r and, if they
// are valid, creates a session, sets the session cookie and returns the
// session. Otherwise it prompts the user to log in again and returns nil.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	user := User{}
	lookupErr := s.Store.Get(fmt.Sprintf("/users/%s", r.PostForm.Get("user")), &user)

	// Always perform exactly one bcrypt comparison, whether or not the user
	// exists or has a usable password, so that response timing does not
	// reveal which usernames are valid.
	hash := user.HashedPassword
	if lookupErr != nil || !isBcryptHash(hash) {
		hash = dummyPasswordHash
	}
	compareErr := compareHashAndPassword(hash, []byte(r.PostForm.Get("password")))

	if lookupErr != nil {
		s.logger.Printf("ERROR: User '%s' doesn't exists", r.PostForm.Get("user"))
		s.promptLogin(w, req, "Invalid username or password")
		return nil
	}
	if compareErr != nil || !isBcryptHash(user.HashedPassword) {
		s.logger.Printf("ERROR: Invalid password for user '%s'", r.PostForm.Get("user"))
		s.promptLogin(w, req, "Invalid username or password")
		return nil
	}

	session := &saml.Session{
		ID:           base64.StdEncoding.EncodeToString(randomBytes(32)),
		NameID:       user.Email,
		NameIDFormat: nameIDFormatForEmail(user.Email),
		CreateTime:   saml.TimeNow(),
		ExpireTime:   saml.TimeNow().Add(sessionMaxAge),
		Index:        hex.EncodeToString(randomBytes(32)),
		UserName:     user.Name,
		// nolint:gocritic // Groups should be a slice here.
		Groups:                user.Groups[:],
		UserEmail:             user.Email,
		UserCommonName:        user.CommonName,
		UserSurname:           user.Surname,
		UserGivenName:         user.GivenName,
		UserScopedAffiliation: user.ScopedAffiliation,
	}
	if err := s.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), &session); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set when served over https
		Name:     sessionCookieName,
		Value:    session.ID,
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil || r.URL.Scheme == "https",
		Path:     "/",
	})

	s.logger.Printf("User '%s' authenticated successfully", r.PostForm.Get("user"))
	return session
}

// lookupSession returns the unexpired session named by the session cookie
// in r, or nil if there is no such cookie, no such session or the session
// has expired. It returns an error only if the store fails.
func (s *Server) lookupSession(r *http.Request) (*saml.Session, error) {
	sessionCookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, nil
	}
	session := &saml.Session{}
	if err := s.Store.Get(fmt.Sprintf("/sessions/%s", sessionCookie.Value), session); err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	if saml.TimeNow().After(session.ExpireTime) {
		return nil, nil
	}
	return session, nil
}

// promptLogin asks the user to log in with the login form, showing toast.
// If the AuthnRequest has IsPassive="true", the identity provider must not
// interact with the user, so it answers with a SAML error Response with the
// status Responder and NoPassive instead.
func (s *Server) promptLogin(w http.ResponseWriter, req *saml.IdpAuthnRequest, toast string) {
	if !isTrue(req.Request.IsPassive) {
		s.sendLoginForm(w, req, toast)
		return
	}
	err := req.IDP.SendErrorResponse(w, req, &saml.StatusError{
		TopLevel:    saml.StatusResponder,
		SecondLevel: saml.StatusNoPassive,
		Message:     "the user cannot be authenticated passively",
	})
	if err != nil {
		s.logger.Printf("ERROR: cannot answer a passive request: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// isTrue reports whether an optional boolean attribute is present and true.
func isTrue(b *bool) bool {
	return b != nil && *b
}

var defaultLoginFormTemplate = template.Must(template.New("saml-post-form").Parse(`` +
	`<html xmlns="http://www.w3.org/1999/xhtml">` +
	`<head><title>Log in</title></head>` +
	`<body>` +
	`<p>{{.Toast}}</p>` +
	`<form method="post" action="{{.URL}}">` +
	`<input type="text" name="user" placeholder="user" value="" />` +
	`<input type="password" name="password" placeholder="password" value="" />` +
	`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
	`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
	`<input type="submit" value="Log In" />` +
	`</form>` +
	`</body>` +
	`</html>`))

// sendLoginForm produces a form which requests a username and password. If the form is
// shown during an SP-initiated flow, it directs the user back to the IDP SSO URL to restart
// the SAML login flow, this time establishing a session based on the credentials that were
// provided. Otherwise it posts to the IDP login URL.
func (s *Server) sendLoginForm(w http.ResponseWriter, req *saml.IdpAuthnRequest, toast string) {
	tmpl := s.LoginFormTemplate
	if tmpl == nil {
		tmpl = defaultLoginFormTemplate
	}

	// When the form is shown in the middle of an SP-initiated flow, it must post
	// back to the SSO endpoint together with the original SAMLRequest so that
	// ServeSSO can authenticate the user and finish the flow. Posting it to the
	// login endpoint instead would only establish a session and reply with JSON,
	// leaving the user stranded at the IdP.
	formURL := req.IDP.LoginURL
	if len(req.RequestBuffer) > 0 {
		formURL = req.IDP.SSOURL
	}

	data := struct {
		Toast       string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Toast:       toast,
		URL:         formURL.String(),
		SAMLRequest: base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:  req.RelayState,
	}

	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
}

// HandleLogin handles the `POST /login` and `GET /login` forms. If credentials are present
// in the request body, then they are validated. For valid credentials, the response is a
// 200 OK and the JSON session object. For invalid credentials, the HTML login prompt form
// is sent.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	session := s.GetSession(w, r, &saml.IdpAuthnRequest{IDP: &s.IDP})
	if session == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(session); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandleListSessions handles the `GET /sessions/` request and responds with a JSON formatted list
// of session names.
func (s *Server) HandleListSessions(w http.ResponseWriter, _ *http.Request) {
	sessions, err := s.Store.List("/sessions/")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(struct {
		Sessions []string `json:"sessions"`
	}{Sessions: sessions})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandleGetSession handles the `GET /sessions/:id` request and responds with the session
// object in JSON format.
func (s *Server) HandleGetSession(w http.ResponseWriter, r *http.Request) {
	session := saml.Session{}
	err := s.Store.Get(fmt.Sprintf("/sessions/%s", r.PathValue("id")), &session)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(session); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandleDeleteSession handles the `DELETE /sessions/:id` request. It invalidates the
// specified session.
func (s *Server) HandleDeleteSession(w http.ResponseWriter, r *http.Request) {
	err := s.deleteSession(r.PathValue("id"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// nameIDFormatForEmail returns the format of a NameID whose value is the
// user's email address: emailAddress, rather than the transient format
// saml.DefaultAssertionMaker assumes when none is given, since an email
// address is neither random nor short-lived (saml-core §8.3.8). It returns
// "" for a user with no email address, keeping the transient default.
func nameIDFormatForEmail(email string) string {
	if email == "" {
		return ""
	}
	return string(saml.EmailAddressNameIDFormat)
}
