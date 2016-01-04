// This package implements a SAML identity provider
package samlidp

import (
	"net/http"
	"sync"

	"github.com/crewjam/saml"
	"github.com/zenazn/goji/web"
)

type Options struct {
	URL         string
	Key         string
	Certificate string
	Store       Store
}

type Server struct {
	http.Handler
	idpConfigMu sync.RWMutex
	IDP         saml.IdentityProvider
	Store       Store
}

func New(opts Options) (*Server, error) {
	mux := web.New()
	s := &Server{
		IDP: saml.IdentityProvider{
			Key:              opts.Key,
			Certificate:      opts.Certificate,
			MetadataURL:      opts.URL + "/metadata",
			SSOURL:           opts.URL + "/sso",
			ServiceProviders: map[string]*saml.Metadata{},
		},
		Store:   opts.Store,
		Handler: mux,
	}
	s.IDP.SessionProvider = s

	mux.Get("/metadata", func(w http.ResponseWriter, r *http.Request) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeMetadata(w, r)
	})
	mux.Handle("/sso", func(w http.ResponseWriter, r *http.Request) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeSSO(w, r)
	})

	mux.Handle("/login", s.HandleLogin)
	mux.Handle("/login/:shortcut", s.HandleIDPInitiated)
	mux.Handle("/login/:shortcut/*", s.HandleIDPInitiated)

	mux.Get("/services/", s.HandleListServices)
	mux.Get("/services/:id", s.HandleGetService)
	mux.Put("/services/:id", s.HandlePutService)
	mux.Post("/services/:id", s.HandlePutService)
	mux.Delete("/services/:id", s.HandleDeleteService)

	mux.Get("/users/", s.HandleListUsers)
	mux.Get("/users/:id", s.HandleGetUser)
	mux.Put("/users/:id", s.HandlePutUser)
	mux.Delete("/users/:id", s.HandleDeleteUser)

	mux.Get("/sessions/", s.HandleListSessions)
	mux.Get("/sessions/:id", s.HandleGetSession)
	mux.Delete("/sessions/:id", s.HandleDeleteSession)

	mux.Get("/shortcuts/", s.HandleListShortcuts)
	mux.Get("/shortcuts/:id", s.HandleGetShortcut)
	mux.Put("/shortcuts/:id", s.HandlePutShortcut)
	mux.Delete("/shortcuts/:id", s.HandleDeleteShortcut)

	if err := s.initializeServices(); err != nil {
		return nil, err
	}

	return s, nil
}
