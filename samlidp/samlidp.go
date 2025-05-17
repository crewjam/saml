// Package samlidp a rudimentary SAML identity provider suitable for
// testing or as a starting point for a more complex service.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// Options represent the parameters to New() for creating a new IDP server
type Options struct {
	URL               url.URL
	Key               crypto.PrivateKey
	Signer            crypto.Signer
	Logger            logger.Interface
	Certificate       *x509.Certificate
	Store             Store
	LoginFormTemplate *template.Template
}

// Server represents an IDP server. The server provides the following URLs:
//
//	/metadata     - the SAML metadata
//	/sso          - the SAML endpoint to initiate an authentication flow
//	/login        - prompt for a username and password if no session established
//	/login/:shortcut - kick off an IDP-initiated authentication flow
//	/services     - RESTful interface to Service objects
//	/users        - RESTful interface to User objects
//	/sessions     - RESTful interface to Session objects
//	/shortcuts    - RESTful interface to Shortcut objects
type Server struct {
	http.Handler
	idpConfigMu       sync.RWMutex // protects calls into the IDP
	logger            logger.Interface
	serviceProviders  map[string]*saml.EntityDescriptor
	IDP               saml.IdentityProvider // the underlying IDP
	Store             Store                 // the data store
	LoginFormTemplate *template.Template
}

// New returns a new Server
func New(opts Options) (*Server, error) {
	opts.URL.Path = strings.TrimSuffix(opts.URL.Path, "/")

	metadataURL := opts.URL
	metadataURL.Path += "/metadata"
	ssoURL := opts.URL
	ssoURL.Path += "/sso"
	loginURL := opts.URL
	loginURL.Path += "/login"
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	s := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		IDP: saml.IdentityProvider{
			Key:         opts.Key,
			Signer:      opts.Signer,
			Logger:      logr,
			Certificate: opts.Certificate,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
			LoginURL:    loginURL,
		},
		logger:            logr,
		Store:             opts.Store,
		LoginFormTemplate: opts.LoginFormTemplate,
	}

	s.IDP.SessionProvider = s
	s.IDP.ServiceProviderProvider = s

	if err := s.initializeServices(); err != nil {
		return nil, err
	}
	s.InitializeHTTP()
	return s, nil
}

// InitializeHTTP sets up the HTTP handler for the server. (This function
// is called automatically for you by New, but you may need to call it
// yourself if you don't create the object using New.)
func (s *Server) InitializeHTTP() {
	mux := http.NewServeMux()
	s.Handler = mux

	mux.HandleFunc("GET /metadata", func(w http.ResponseWriter, r *http.Request) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeMetadata(w, r)
	})
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		s.IDP.ServeSSO(w, r)
	})

	mux.HandleFunc("/login", s.HandleLogin)
	mux.HandleFunc("/login/{shortcut}", s.HandleIDPInitiated)
	mux.HandleFunc("/login/{shortcut}/{suffix}", s.HandleIDPInitiated)

	mux.HandleFunc("GET /services/", s.HandleListServices)
	mux.HandleFunc("GET /services/{id}", s.HandleGetService)
	mux.HandleFunc("PUT /services/{id}", s.HandlePutService)
	mux.HandleFunc("POST /services/{id}", s.HandlePutService)
	mux.HandleFunc("DELETE /services/{id}", s.HandleDeleteService)

	mux.HandleFunc("GET /users/", s.HandleListUsers)
	mux.HandleFunc("GET /users/{id}", s.HandleGetUser)
	mux.HandleFunc("PUT /users/{id}", s.HandlePutUser)
	mux.HandleFunc("DELETE /users/{id}", s.HandleDeleteUser)

	mux.HandleFunc("GET /sessions/", s.HandleListSessions)
	mux.HandleFunc("GET /sessions/{id}", s.HandleGetSession)
	mux.HandleFunc("DELETE /sessions/{id}", s.HandleDeleteSession)

	mux.HandleFunc("GET /shortcuts/", s.HandleListShortcuts)
	mux.HandleFunc("GET /shortcuts/{id}", s.HandleGetShortcut)
	mux.HandleFunc("PUT /shortcuts/{id}", s.HandlePutShortcut)
	mux.HandleFunc("DELETE /shortcuts/{id}", s.HandleDeleteShortcut)
}
