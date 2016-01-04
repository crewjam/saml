package samlidp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/zenazn/goji/web"
)

type Shortcut struct {
	Name string `json:"name"`

	// The entity ID of the service provider to use for this shortcut, i.e.
	// https://someapp.example.com/saml/metadata.
	ServiceProviderID string `json:"service_provider"`

	// If specified then the relay state is the fixed string provided
	RelayState *string `json:"relay_state,omitempty"`

	// If true then the URL suffix is used as the relayState. So for example, a user
	// requesting https://idp.example.com/login/myservice/foo will get redirected
	// to the myservice endpoint with a RelayState of "foo".
	URISuffixAsRelayState bool `json:"url_suffix_as_relay_state,omitempty"`
}

func (s *Server) HandleListShortcuts(c web.C, w http.ResponseWriter, r *http.Request) {
	shortcuts, err := s.Store.List("/shortcuts/")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Shortcuts []string `json:"shortcuts"`
	}{Shortcuts: shortcuts})
}

func (s *Server) HandleGetShortcut(c web.C, w http.ResponseWriter, r *http.Request) {
	shortcut := Shortcut{}
	err := s.Store.Get(fmt.Sprintf("/shortcuts/%s", c.URLParams["id"]), &shortcut)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(shortcut)
}

func (s *Server) HandlePutShortcut(c web.C, w http.ResponseWriter, r *http.Request) {
	shortcut := Shortcut{}
	if err := json.NewDecoder(r.Body).Decode(&shortcut); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	shortcut.Name = c.URLParams["id"]

	err := s.Store.Put(fmt.Sprintf("/shortcuts/%s", c.URLParams["id"]), &shortcut)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandleDeleteShortcut(c web.C, w http.ResponseWriter, r *http.Request) {
	err := s.Store.Delete(fmt.Sprintf("/shortcuts/%s", c.URLParams["id"]))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandleIDPInitiated(c web.C, w http.ResponseWriter, r *http.Request) {
	shortcutName := c.URLParams["shortcut"]
	shortcut := Shortcut{}
	if err := s.Store.Get(fmt.Sprintf("/shortcuts/%s", shortcutName), &shortcut); err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	relayState := ""
	switch {
	case shortcut.RelayState != nil:
		relayState = *shortcut.RelayState
	case shortcut.URISuffixAsRelayState:
		relayState, _ = c.URLParams["*"]
	}

	s.idpConfigMu.RLock()
	defer s.idpConfigMu.RUnlock()
	s.IDP.ServeIDPInitiated(w, r, shortcut.ServiceProviderID, relayState)
}
