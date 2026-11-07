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

	// Metdata is the XML metadata of the service provider.
	Metadata saml.EntityDescriptor
}

// UnmarshalJSON implements json.Unmarshaler.
//
// An XML signature (an *etree.Element) cannot be decoded from JSON, so
// HandlePutService drops the signatures from metadata before storing it.
// Services stored before that was done may still hold JSON-encoded
// signatures; they are decoded without them.
func (s *Service) UnmarshalJSON(data []byte) error {
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

// clearSignatures removes the XML signatures from md. They cannot be stored
// as JSON, and they are of no use once the metadata has been accepted: they
// were checked then, if SPMetadataCertificates was set, and they do not
// verify against metadata that has been decoded and encoded again.
func clearSignatures(md *saml.EntityDescriptor) {
	md.Signature = nil
	for i := range md.RoleDescriptors {
		md.RoleDescriptors[i].Signature = nil
	}
	for i := range md.IDPSSODescriptors {
		md.IDPSSODescriptors[i].Signature = nil
	}
	for i := range md.SPSSODescriptors {
		md.SPSSODescriptors[i].Signature = nil
	}
	for i := range md.AuthnAuthorityDescriptors {
		md.AuthnAuthorityDescriptors[i].Signature = nil
	}
	for i := range md.AttributeAuthorityDescriptors {
		md.AttributeAuthorityDescriptors[i].Signature = nil
	}
	for i := range md.PDPDescriptors {
		md.PDPDescriptors[i].Signature = nil
	}
	if md.AffiliationDescriptor != nil {
		md.AffiliationDescriptor.Signature = nil
	}
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
	err = xml.NewEncoder(w).Encode(service.Metadata)
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
// XML signatures in the metadata are not stored.
func (s *Server) HandlePutService(w http.ResponseWriter, r *http.Request) {
	service := Service{}

	metadata, err := getVerifiedSPMetadata(r.Body, s.SPMetadataCertificates)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	service.Metadata = *metadata
	clearSignatures(&service.Metadata)

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
