// Package samlidp a rudimentary SAML identity provider suitable for
// testing or as a starting point for a more complex service.
//
// The administrative endpoints (/services, /users, /sessions and /shortcuts)
// are not authenticated: anyone who can reach the server can read and change
// its users, service providers, sessions and shortcuts. Set
// Options.AdminMiddleware to protect them, or do not expose the server to
// untrusted clients.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

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

	// AdminMiddleware, if set, wraps the handlers of the administrative
	// endpoints (/services, /users, /sessions and /shortcuts), for example to
	// require authentication. It is not applied to /metadata, /sso and
	// /login, /slo and /logout, which must stay reachable by browsers and service
	// providers.
	// If nil, the administrative endpoints are unauthenticated.
	AdminMiddleware func(http.Handler) http.Handler

	// ExtraCertificates are additional signing certificates published in
	// the metadata, for example to announce a new certificate before a key
	// rollover. They are never used to sign anything. See
	// saml.IdentityProvider.ExtraCertificates.
	ExtraCertificates []*x509.Certificate

	// MetadataScopes are published in the metadata as Shibboleth
	// shibmd:Scope extension elements. See
	// saml.IdentityProvider.MetadataScopes.
	MetadataScopes []saml.ShibbolethScope

	// SOAPLogout, if true, has /slo also accept LogoutRequests that service
	// providers send server to server with the SOAP binding, and advertises
	// a SOAP SingleLogoutService for it in the metadata (see
	// saml.IdentityProvider.LogoutBindings). The sessions are then ended by
	// NameID and SessionIndex, without the browser (see
	// Server.InvalidateSession), and the logout is propagated only to the
	// service providers that also offer a SOAP SingleLogoutService.
	//
	// It is off by default: a service provider that finds a SOAP endpoint in
	// the metadata may start using it instead of the browser, and a logout
	// that starts without a browser cannot reach the service providers that
	// only offer front-channel logout, which a browser-based logout reaches.
	// It also needs /slo to be reachable from the service providers'
	// servers.
	SOAPLogout bool

	// SPMetadataCertificates, if set, are the certificates that service
	// provider metadata registered through PUT or POST /services/:id must
	// be signed with (saml-metadata-2.0-os §3, §4.3.3.2): the service
	// providers' own metadata signing certificates, or their federation's,
	// obtained from a source you trust. The root element of the metadata
	// must then carry a valid enveloped signature made with one of them,
	// and only the content the signature covers is stored; unsigned
	// metadata, or metadata whose signature does not verify, is refused
	// with 400 Bad Request. See saml.VerifyMetadataSignature.
	//
	// If empty (the default), service provider metadata is accepted
	// without checking any signature it carries.
	SPMetadataCertificates []*x509.Certificate

	// Clock, if non-nil, is the time source of the server: it is set as
	// the Clock of the IdentityProvider (see saml.IdentityProvider.Clock),
	// and sets the creation and expiry times of login sessions. If nil, the
	// real clock is used.
	Clock *dsig.Clock
}

// Server represents an IDP server. The server provides the following URLs:
//
//	/metadata     - the SAML metadata
//	/sso          - the SAML endpoint to initiate an authentication flow
//	/slo          - the SAML single logout endpoint (SP-initiated logout,
//	                also over SOAP if Options.SOAPLogout is set, and the
//	                service providers' answers to IdP-initiated logout)
//	/logout       - log the browser's session out of the IdP and of every
//	                service provider it was used for (IdP-initiated logout)
//	/login        - prompt for a username and password if no session established
//	/login/:shortcut - kick off an IDP-initiated authentication flow
//	/services     - RESTful interface to Service objects
//	/users        - RESTful interface to User objects
//	/sessions     - RESTful interface to Session objects
//	/shortcuts    - RESTful interface to Shortcut objects
//
// The RESTful interfaces are administrative endpoints. They are only
// protected if AdminMiddleware is set.
type Server struct {
	http.Handler
	idpConfigMu      sync.RWMutex // protects calls into the IDP
	logger           logger.Interface
	serviceProviders map[string]*saml.EntityDescriptor // by entity ID; protected by idpConfigMu

	// servicesMu serialises the changes to the stored services, so that
	// the store and serviceProviders change in the same order.
	servicesMu sync.Mutex
	// services holds the metadata of each stored service by its store ID
	// (the :id of /services/:id). Protected by idpConfigMu.
	services map[string]*saml.EntityDescriptor

	// expiry schedules the deletion of expired sessions (see
	// scheduleSessionDeletion). afterFunc, if set, replaces time.AfterFunc
	// for its timer, in tests.
	expiry    sessionExpiry
	afterFunc func(time.Duration, func()) stopper

	IDP               saml.IdentityProvider // the underlying IDP
	Store             Store                 // the data store
	LoginFormTemplate *template.Template

	// AdminMiddleware, if set, wraps the administrative endpoints. See
	// Options.AdminMiddleware. Call InitializeHTTP after changing it.
	AdminMiddleware func(http.Handler) http.Handler

	// SPMetadataCertificates, if set, are the certificates that service
	// provider metadata registered through /services/:id must be signed
	// with. See Options.SPMetadataCertificates.
	SPMetadataCertificates []*x509.Certificate
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
	logoutURL := opts.URL
	logoutURL.Path += "/slo"
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	s := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		services:         map[string]*saml.EntityDescriptor{},
		IDP: saml.IdentityProvider{
			Key:         opts.Key,
			Signer:      opts.Signer,
			Logger:      logr,
			Certificate: opts.Certificate,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
			LoginURL:    loginURL,
			LogoutURL:   logoutURL,
			LogoutBindings: []string{
				saml.HTTPRedirectBinding,
				saml.HTTPPostBinding,
			},
			ExtraCertificates: opts.ExtraCertificates,
			MetadataScopes:    opts.MetadataScopes,
			NameIDFormats:     defaultNameIDFormats(),
			Clock:             opts.Clock,
		},
		logger:            logr,
		Store:             opts.Store,
		LoginFormTemplate: opts.LoginFormTemplate,
		AdminMiddleware:   opts.AdminMiddleware,

		SPMetadataCertificates: opts.SPMetadataCertificates,
	}

	if opts.SOAPLogout {
		s.IDP.LogoutBindings = append(s.IDP.LogoutBindings, saml.SOAPBinding)
	}
	s.IDP.SessionProvider = s
	s.IDP.ServiceProviderProvider = s

	if err := s.initializeServices(); err != nil {
		return nil, err
	}
	s.InitializeHTTP()
	return s, nil
}

// defaultNameIDFormats returns the NameID formats samlidp advertises in its
// metadata: the ones it issues (see nameIDFormatForEmail), emailAddress for
// users with an email address and transient for the others
// (saml-metadata §2.4.3). Set Server.IDP.NameIDFormats after New to
// advertise others, for example with a custom SessionProvider.
func defaultNameIDFormats() []saml.NameIDFormat {
	return []saml.NameIDFormat{
		saml.EmailAddressNameIDFormat,
		saml.TransientNameIDFormat,
	}
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
	mux.HandleFunc("/slo", func(w http.ResponseWriter, r *http.Request) {
		s.IDP.ServeSLO(w, r)
	})
	mux.HandleFunc("GET /logout", s.HandleLogout)
	mux.HandleFunc("POST /logout", s.HandleLogout)

	mux.HandleFunc("/login", s.HandleLogin)
	mux.HandleFunc("/login/{shortcut}", s.HandleIDPInitiated)
	mux.HandleFunc("/login/{shortcut}/{suffix}", s.HandleIDPInitiated)

	// The administrative endpoints are wrapped by AdminMiddleware, if set.
	admin := func(pattern string, handler http.HandlerFunc) {
		if s.AdminMiddleware == nil {
			mux.Handle(pattern, handler)
			return
		}
		mux.Handle(pattern, s.AdminMiddleware(handler))
	}

	admin("GET /services/", s.HandleListServices)
	admin("GET /services/{id}", s.HandleGetService)
	admin("PUT /services/{id}", s.HandlePutService)
	admin("POST /services/{id}", s.HandlePutService)
	admin("DELETE /services/{id}", s.HandleDeleteService)

	admin("GET /users/", s.HandleListUsers)
	admin("GET /users/{id}", s.HandleGetUser)
	admin("PUT /users/{id}", s.HandlePutUser)
	admin("DELETE /users/{id}", s.HandleDeleteUser)

	admin("GET /sessions/", s.HandleListSessions)
	admin("GET /sessions/{id}", s.HandleGetSession)
	admin("DELETE /sessions/{id}", s.HandleDeleteSession)

	admin("GET /shortcuts/", s.HandleListShortcuts)
	admin("GET /shortcuts/{id}", s.HandleGetShortcut)
	admin("PUT /shortcuts/{id}", s.HandlePutShortcut)
	admin("DELETE /shortcuts/{id}", s.HandleDeleteShortcut)
}
