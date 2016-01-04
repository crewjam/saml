package samlidp

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/zenazn/goji/web"
)

type Service struct {
	Name     string
	Metadata saml.Metadata
}

func (s *Server) HandleListServices(c web.C, w http.ResponseWriter, r *http.Request) {
	services, err := s.Store.List("/services/")
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Services []string `json:"services"`
	}{Services: services})
}

func (s *Server) HandleGetService(c web.C, w http.ResponseWriter, r *http.Request) {
	service := Service{}
	err := s.Store.Get(fmt.Sprintf("/services/%s", c.URLParams["id"]), &service)
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	xml.NewEncoder(w).Encode(service.Metadata)
}

func (s *Server) HandlePutService(c web.C, w http.ResponseWriter, r *http.Request) {
	service := Service{}
	if err := xml.NewDecoder(r.Body).Decode(&service.Metadata); err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	err := s.Store.Put(fmt.Sprintf("/services/%s", c.URLParams["id"]), &service)
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.idpConfigMu.Lock()
	s.IDP.ServiceProviders[service.Metadata.EntityID] = &service.Metadata
	s.idpConfigMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandleDeleteService(c web.C, w http.ResponseWriter, r *http.Request) {
	service := Service{}
	err := s.Store.Get(fmt.Sprintf("/services/%s", c.URLParams["id"]), &service)
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := s.Store.Delete(fmt.Sprintf("/services/%s", c.URLParams["id"])); err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.idpConfigMu.Lock()
	delete(s.IDP.ServiceProviders, service.Metadata.EntityID)
	s.idpConfigMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) initializeServices() error {
	serviceNames, err := s.Store.List("/services/")
	if err != nil {
		return err
	}
	for _, serviceName := range serviceNames {
		service := Service{}
		if err := s.Store.Get(fmt.Sprintf("/services/%s", serviceName), &service); err != nil {
			return err
		}

		s.idpConfigMu.Lock()
		s.IDP.ServiceProviders[service.Metadata.EntityID] = &service.Metadata
		s.idpConfigMu.Unlock()
	}
	return nil
}
