package samlidp

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"

	"github.com/crewjam/saml"
)

// Service represents a configured SP for whom this IDP provides authentication services.
type Service struct {
	// Name is the name of the service provider
	Name string

	// Metadata is the metadata of the service provider. When RawMetadata is
	// set, Metadata is parsed from it and is not itself stored.
	Metadata saml.EntityDescriptor

	// RawMetadata is the metadata document exactly as HandlePutService
	// received it, XML signatures and all. Services stored by earlier
	// versions have only Metadata.
	RawMetadata []byte `json:",omitempty"`
}

// MarshalJSON implements json.Marshaler. A Service with RawMetadata is
// stored as its Name and RawMetadata only: the parsed Metadata can hold XML
// signatures (*etree.Element), which do not survive a JSON round trip.
func (s Service) MarshalJSON() ([]byte, error) {
	if len(s.RawMetadata) == 0 {
		type alias Service
		return json.Marshal(alias(s))
	}
	return json.Marshal(struct {
		Name        string
		RawMetadata []byte
	}{Name: s.Name, RawMetadata: s.RawMetadata})
}

// UnmarshalJSON implements json.Unmarshaler. A Service stored with
// RawMetadata gets its Metadata parsed from it. A Service stored by an
// earlier version is decoded from its JSON-encoded Metadata; any XML
// signatures in it, which cannot be decoded from JSON, are left out.
func (s *Service) UnmarshalJSON(data []byte) error {
	var stored struct {
		Name        string
		RawMetadata []byte
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	if len(stored.RawMetadata) == 0 {
		return s.unmarshalLegacyJSON(data)
	}
	md, err := parseSPMetadata(stored.RawMetadata)
	if err != nil {
		return err
	}
	*s = Service{Name: stored.Name, Metadata: *md, RawMetadata: stored.RawMetadata}
	return nil
}

// unmarshalLegacyJSON decodes a Service stored without RawMetadata.
func (s *Service) unmarshalLegacyJSON(data []byte) error {
	type alias Service
	err := json.Unmarshal(data, (*alias)(s))
	if err == nil {
		return nil
	}
	stripped, stripErr := stripJSONSignatures(data)
	if stripErr != nil || stripped == nil {
		return err
	}
	*s = Service{}
	return json.Unmarshal(stripped, (*alias)(s))
}

// stripJSONSignatures removes the non-null "Signature" members from the
// JSON-encoded Metadata of a Service. It returns nil if there were none.
func stripJSONSignatures(data []byte) ([]byte, error) {
	var v map[string]interface{}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if !deleteSignatures(v["Metadata"]) {
		return nil, nil
	}
	return json.Marshal(v)
}

// deleteSignatures removes, from v and everything in it, the "Signature"
// members whose value is an object. It reports whether it removed any.
func deleteSignatures(v interface{}) bool {
	removed := false
	switch v := v.(type) {
	case map[string]interface{}:
		if _, ok := v["Signature"].(map[string]interface{}); ok {
			delete(v, "Signature")
			removed = true
		}
		for _, child := range v {
			removed = deleteSignatures(child) || removed
		}
	case []interface{}:
		for _, child := range v {
			removed = deleteSignatures(child) || removed
		}
	}
	return removed
}

// GetServiceProvider returns the Service Provider metadata for the
// service provider ID, which is typically the service provider's
// metadata URL. If an appropriate service provider cannot be found then
// the returned error must be os.ErrNotExist.
func (s *Server) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	s.idpConfigMu.RLock()
	defer s.idpConfigMu.RUnlock()
	rv, ok := s.serviceProviders[serviceProviderID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return rv, nil
}

// HandleListServices handles the `GET /services/` request and responds with a JSON formatted list
// of service names.
func (s *Server) HandleListServices(w http.ResponseWriter, _ *http.Request) {
	services, err := s.Store.List("/services/")
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(struct {
		Services []string `json:"services"`
	}{Services: services})
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// HandleGetService handles the `GET /services/:id` request and responds with the service
// metadata in XML format.
func (s *Server) HandleGetService(w http.ResponseWriter, r *http.Request) {
	service := Service{}
	err := s.Store.Get(fmt.Sprintf("/services/%s", r.PathValue("id")), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if len(service.RawMetadata) > 0 {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, err = w.Write(service.RawMetadata)
	} else {
		err = xml.NewEncoder(w).Encode(service.Metadata)
	}
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// HandlePutService handles the `PUT /shortcuts/:id` request. It accepts the XML-formatted
// service metadata in the request body and stores it.
//
// If SPMetadataCertificates is set, the metadata must be signed with one of
// them, and only the content the signature covers is stored; unsigned
// metadata, or metadata whose signature does not verify, is refused with
// 400 Bad Request.
//
// The request body is stored as it was received (see Service.RawMetadata),
// and GET /services/:id returns it unchanged.
func (s *Server) HandlePutService(w http.ResponseWriter, r *http.Request) {
	service := Service{}

	data, err := readSPMetadata(r.Body)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	metadata, err := verifiedSPMetadata(data, s.SPMetadataCertificates)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	service.Metadata = *metadata
	service.RawMetadata = data

	err = s.Store.Put(fmt.Sprintf("/services/%s", r.PathValue("id")), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.idpConfigMu.Lock()
	s.serviceProviders[service.Metadata.EntityID] = &service.Metadata
	s.idpConfigMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteService handles the `DELETE /services/:id` request.
func (s *Server) HandleDeleteService(w http.ResponseWriter, r *http.Request) {
	service := Service{}
	err := s.Store.Get(fmt.Sprintf("/services/%s", r.PathValue("id")), &service)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := s.Store.Delete(fmt.Sprintf("/services/%s", r.PathValue("id"))); err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.idpConfigMu.Lock()
	delete(s.serviceProviders, service.Metadata.EntityID)
	s.idpConfigMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// initializeServices reads all the stored services and initializes the underlying
// identity provider to accept them.
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
		s.serviceProviders[service.Metadata.EntityID] = &service.Metadata
		s.idpConfigMu.Unlock()
	}
	return nil
}
