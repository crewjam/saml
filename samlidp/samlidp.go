// This package implements a SAML identity provider
package samlidp

import (
	"net/http"

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
	IDP   saml.IdentityProvider
	Store Store
}

func New(opts Options) *Server {
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

	mux.Get("/metadata", s.IDP.ServeMetadata)
	mux.Handle("/sso", s.IDP.ServeSSO)

	/*
		mux.Handle("/login/:shortcut", s.HandleIDPInitiated)
		mux.Handle("/login/:shortcut/*", s.HandleIDPInitiated)

		mux.Get("/services", s.HandleListService)
		mux.Get("/services/:id", s.HandleGetService)
		mux.Put("/services/:id", s.HandlePutService)
		mux.Delete("/services/:id", s.HandleDeleteService)

		mux.Get("/users", s.HandleListUsers)
		mux.Get("/users/:id", s.HandleGetUser)
		mux.Put("/users/:id", s.HandlePutUser)
		mux.Delete("/users/:id", s.HandleDeleteUser)

		mux.Get("/groups", s.HandleListGroups)
		mux.Get("/groups/:id", s.HandleGetGroup)
		mux.Put("/groups/:id", s.HandlePutGroup)
		mux.Delete("/groups/:id", s.HandleDeleteGroup)

		mux.Get("/sessions", s.HandleListSesssions)
		mux.Get("/sessions/:id", s.HandleGetSession)
		mux.Delete("/sessions/:id", s.HandleDeleteSession)

		mux.Get("/shortcuts", s.HandleListShortcuts)
		mux.Get("/shortcuts/:id", s.HandleGetShortcut)
		mux.Put("/shortcuts/:id", s.HandlePutShortcut)
		mux.Delete("/shortcuts/:id", s.HandleDeleteShortcut)
	*/

	return s
}
