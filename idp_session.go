package saml

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"text/template"
	"time"
)

var sessionMaxAge = time.Hour // TODO(ross): must be configurable

// Session represents a user session. It is returned by the
// SessionProvider implementation's GetSession method. Fields here
// are used to set fields in the SAML assertion.
type Session struct {
	ID         string
	CreateTime time.Time
	ExpireTime time.Time
	Index      string

	NameID         string
	Groups         []string
	UserName       string
	UserEmail      string
	UserCommonName string
	UserSurname    string
	UserGivenName  string
}

// SessionProvider is an interface used by IdentityProvider to determine the
// Session associated with a request. The default implementation is
// DefaultSessionProvider.
type SessionProvider interface {
	// GetSession returns the remote user session associated with the http.Request.
	//
	// If (and only if) the request is not associated with a session then GetSession
	// must complete the HTTP request and return nil.
	GetSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
}

// SessionStore is an interface that describes how session
// objects are stored. It must be
type SessionStore interface {
	New(user *User) (*Session, error)
	Get(id string) (*Session, error)
	Delete(id string) error
}

// DefaultSessionProvider is a session provider that stores the user session as
// an HTTP cookie. This provider displays a very basic login form to the user
// and is almost certainly suitable only for the most trivial of use cases.
type DefaultSessionProvider struct {
	Users    UserStore
	Sessions SessionStore
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
// then the session is returned
//
// If neither credentials nor a valid session cookie exist, this function
// sends a login form and returns nil.
func (sp *DefaultSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
	// if we received login credentials then maybe we can create a session
	if r.Method == "POST" && r.PostForm.Get("user") != "" {
		user, err := sp.Users.Get(r.PostForm.Get("user"))
		if err != nil {
			sp.sendLoginForm(w, r, req, "Invalid username or password")
			return nil
		}
		if user == nil {
			sp.sendLoginForm(w, r, req, "Invalid username or password")
			return nil
		}
		if user.Password != r.PostForm.Get("password") {
			sp.sendLoginForm(w, r, req, "Invalid username or password")
			return nil
		}
		session, err := sp.Sessions.New(user)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    session.ID,
			MaxAge:   int(sessionMaxAge.Seconds()),
			HttpOnly: false,
			Path:     "/",
		})
		return session
	}

	if sessionCookie, err := r.Cookie("session"); err == nil {
		session, err := sp.Sessions.Get(sessionCookie.Value)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}
		if session != nil {
			return session
		}
	}

	sp.sendLoginForm(w, r, req, "")
	return nil
}

// sendLoginForm produces a form which requests a username and password and directs the user
// back to the IDP authorize URL to restart the SAML login flow, this time establishing a
// session based on the credentials that were provided.
func (sp *DefaultSessionProvider) sendLoginForm(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest, toast string) {
	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<html>` +
		`<p>{{.Toast}}</p>` +
		`<form method="post" action="{{.URL}}">` +
		`<input type="text" name="user" placeholder="user" value="" />` +
		`<input type="password" name="password" placeholder="password" value="" />` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input type="submit" value="Log In" />` +
		`</form>` +
		`</html>`))
	data := struct {
		Toast       string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Toast:       toast,
		URL:         req.IDP.SSOURL,
		SAMLRequest: base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:  req.RelayState,
	}

	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
}

// MemorySessionStore is an in-memory, thread safe implementation of SessionStore.
type MemorySessionStore struct {
	mu   sync.RWMutex
	data map[string]*Session
}

// New returns a new session
func (m *MemorySessionStore) New(user *User) (*Session, error) {
	session := &Session{
		ID:             base64.StdEncoding.EncodeToString(randomBytes(32)),
		CreateTime:     TimeNow(),
		Index:          hex.EncodeToString(randomBytes(32)),
		UserName:       user.Name,
		Groups:         user.Groups[:],
		UserEmail:      user.Email,
		UserCommonName: user.CommonName,
		UserSurname:    user.Surname,
		UserGivenName:  user.GivenName,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = map[string]*Session{}
	}
	m.data[session.ID] = session
	return session, nil
}

// Get fetches an existing session by ID
func (m *MemorySessionStore) Get(id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, _ := m.data[id]
	return s, nil
}

// Delete removes a session.
func (m *MemorySessionStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
	return nil
}
