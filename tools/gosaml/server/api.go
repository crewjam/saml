package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/tools/gosaml/store"
	"github.com/crewjam/saml/x/samlidp"
)

// The JSON API, documented at /api (web/templates/api.html). It does
// what the management pages do, for scripts and tests: an instance's
// management secret is its credential here too, so the routes under
// /api/manage/{secret} mirror /manage/{secret}.

func (s *Server) apiRoutes() {
	m := s.mux
	m.HandleFunc("GET /api", func(w http.ResponseWriter, r *http.Request) {
		s.renderStatus(w, r, http.StatusOK, "api", "API", apiDocs{
			Profiles: idpProfiles, Formats: nameIDFormats, MaxUsers: maxUsers, MaxSPs: maxSPs,
			MaxEvents: store.MaxEventsPerInstance, Lifetime: roundDuration(s.TTL),
		})
	})
	m.HandleFunc("POST /api/idps", s.apiNewIDP)
	m.HandleFunc("POST /api/sps", s.apiNewSP)
	m.HandleFunc("GET /api/manage/{secret}", s.apiInstance(s.apiGet))
	m.HandleFunc("PATCH /api/manage/{secret}", s.apiInstance(s.apiPatch))
	m.HandleFunc("DELETE /api/manage/{secret}", s.apiInstance(s.apiDelete))
	m.HandleFunc("POST /api/manage/{secret}/profile", s.apiIDP(s.apiSetProfile))
	m.HandleFunc("PUT /api/manage/{secret}/users/{username}", s.apiIDP(s.apiPutUser))
	m.HandleFunc("DELETE /api/manage/{secret}/users/{username}", s.apiIDP(s.apiDeleteUser))
	m.HandleFunc("POST /api/manage/{secret}/service-providers", s.apiIDP(s.apiAddSP))
	m.HandleFunc("DELETE /api/manage/{secret}/service-providers", s.apiIDP(s.apiDeleteSP))
	m.HandleFunc("PUT /api/manage/{secret}/idp", s.apiSP(s.apiSetIDP))
	m.HandleFunc("GET /api/manage/{secret}/events", s.apiInstance(s.apiEvents))
	m.HandleFunc("DELETE /api/manage/{secret}/events", s.apiInstance(s.apiClearEvents))
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "no such API endpoint: "+r.Method+" "+r.URL.Path+"; see "+s.BaseURL+"/api", nil)
	})
}

// apiDocs is the data of the API documentation page.
type apiDocs struct {
	Profiles                    []idpProfile
	Formats                     []saml.NameIDFormat
	MaxUsers, MaxSPs, MaxEvents int
	Lifetime                    string
}

// APIError is the body of every API response that is not a success.
type APIError struct {
	Error string `json:"error"`
	// Detail is the full error chain, when there is one.
	Detail string `json:"detail,omitempty"`
}

func apiError(w http.ResponseWriter, status int, msg string, err error) {
	e := APIError{Error: msg}
	if err != nil {
		e.Detail = errorChain(err)
	}
	writeJSON(w, status, e)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// readJSON decodes a request body into v. An empty body leaves v as it
// is. Unknown fields are refused, so that a misspelt setting is an error
// rather than ignored.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if errors.Is(err, io.EOF) {
		return true
	}
	if err == nil && dec.More() {
		err = errors.New("more than one JSON value")
	}
	if err != nil {
		apiError(w, http.StatusBadRequest, "cannot read the request body: "+err.Error(), nil)
		return false
	}
	return true
}

// apiInstance wraps a handler of an instance named by its management
// secret.
func (s *Server) apiInstance(h func(http.ResponseWriter, *http.Request, *store.Instance)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		in, err := s.Store.InstanceBySecret(r.Context(), r.PathValue("secret"))
		if err != nil {
			apiError(w, http.StatusNotFound, "no such instance; instances are deleted "+roundDuration(s.TTL)+" after they are created", nil)
			return
		}
		h(w, r, in)
	}
}

// apiIDP wraps a handler of an IdP's configuration, which it saves when
// the handler returns a status below 300.
func (s *Server) apiIDP(h func(http.ResponseWriter, *http.Request, *store.Instance, *IDPConfig) (int, any)) http.HandlerFunc {
	return s.apiInstance(func(w http.ResponseWriter, r *http.Request, in *store.Instance) {
		if in.Kind != store.KindIDP {
			apiError(w, http.StatusConflict, "this endpoint is for identity providers, and this instance is a service provider", nil)
			return
		}
		cfg, err := decodeIDPConfig(in.Config)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "cannot read the configuration", err)
			return
		}
		status, body := h(w, r, in, cfg)
		s.apiFinish(w, r, in, cfg, status, body)
	})
}

// apiSP is apiIDP for SPs.
func (s *Server) apiSP(h func(http.ResponseWriter, *http.Request, *store.Instance, *SPConfig) (int, any)) http.HandlerFunc {
	return s.apiInstance(func(w http.ResponseWriter, r *http.Request, in *store.Instance) {
		if in.Kind != store.KindSP {
			apiError(w, http.StatusConflict, "this endpoint is for service providers, and this instance is an identity provider", nil)
			return
		}
		cfg, err := decodeSPConfig(in.Config)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "cannot read the configuration", err)
			return
		}
		status, body := h(w, r, in, cfg)
		s.apiFinish(w, r, in, cfg, status, body)
	})
}

// apiFinish saves cfg after a successful change and writes the
// response. A nil body means the instance as it now is.
func (s *Server) apiFinish(w http.ResponseWriter, r *http.Request, in *store.Instance, cfg any, status int, body any) {
	if status == 0 {
		return // the handler has written the response
	}
	if status >= 300 {
		writeJSON(w, status, body)
		return
	}
	b, err := encodeConfig(cfg)
	if err == nil {
		err = s.Store.UpdateConfig(r.Context(), in.ID, b)
	}
	if err != nil {
		apiError(w, http.StatusInternalServerError, "cannot save the configuration", err)
		return
	}
	in.Config = b
	if body == nil {
		body, err = s.apiView(in)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "cannot read the configuration", err)
			return
		}
	}
	writeJSON(w, status, body)
}

// errorBody is the response body of a failed change.
func errorBody(msg string) *APIError {
	return &APIError{Error: msg}
}

// APIInstance is an instance as the API shows it. Exactly one of IdP
// and SP is set.
type APIInstance struct {
	Kind        store.Kind `json:"kind"`
	ID          string     `json:"id"`
	Secret      string     `json:"secret"`
	ManageURL   string     `json:"manage_url"`
	APIURL      string     `json:"api_url"`
	EntityID    string     `json:"entity_id"`
	MetadataURL string     `json:"metadata_url"`
	CertURL     string     `json:"certificate_url"`
	Certificate string     `json:"certificate"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	IDP         *APIIDP    `json:"idp,omitempty"`
	SP          *APISP     `json:"sp,omitempty"`
}

// APIIDP is what is particular to an IdP.
type APIIDP struct {
	SSOURL           string            `json:"sso_url"`
	SLOURL           string            `json:"slo_url"`
	ArtifactURL      string            `json:"artifact_resolution_url"`
	Settings         APIIDPSettings    `json:"settings"`
	Profile          string            `json:"profile"`
	Users            []APIUser         `json:"users"`
	ServiceProviders []APIRegisteredSP `json:"service_providers"`
}

// APIIDPSettings are an IdP's settings. In a PATCH, a missing field is
// left as it is.
type APIIDPSettings struct {
	Name                  *string `json:"name,omitempty"`
	AutoFetchSPMetadata   *bool   `json:"auto_fetch_sp_metadata,omitempty"`
	RequireSignedRequests *bool   `json:"require_signed_requests,omitempty"`
	SignatureMethod       *string `json:"signature_method,omitempty"`
	Encryption            *string `json:"encryption,omitempty"`
	ResponseSigning       *string `json:"response_signing,omitempty"`
	RememberSessions      *bool   `json:"remember_sessions,omitempty"`
	BackChannelLogout     *bool   `json:"back_channel_logout,omitempty"`
	ArtifactForm          *bool   `json:"artifact_form,omitempty"`
}

// APIUser is a user of an IdP.
type APIUser struct {
	Username     string         `json:"username"`
	NameID       string         `json:"nameid"`
	NameIDFormat string         `json:"nameid_format"`
	Attributes   []APIAttribute `json:"attributes"`
}

// APIAttribute is an attribute of a user.
type APIAttribute struct {
	Name         string   `json:"name"`
	FriendlyName string   `json:"friendly_name,omitempty"`
	NameFormat   string   `json:"name_format,omitempty"`
	Values       []string `json:"values"`
}

// APIRegisteredSP is an SP registered with an IdP.
type APIRegisteredSP struct {
	EntityID string    `json:"entity_id"`
	Source   string    `json:"metadata_url,omitempty"`
	Metadata string    `json:"metadata"`
	AddedAt  time.Time `json:"added_at"`
}

// APISP is what is particular to an SP.
type APISP struct {
	ACSURL      string        `json:"acs_url"`
	LoginURL    string        `json:"login_url"`
	SLOURL      string        `json:"slo_url"`
	ArtifactURL string        `json:"artifact_resolution_url"`
	Settings    APISPSettings `json:"settings"`
	IDP         *APITrusted   `json:"idp"`
}

// APISPSettings are an SP's settings. In a PATCH, a missing field is
// left as it is.
type APISPSettings struct {
	Name                 *string `json:"name,omitempty"`
	SignAuthnRequests    *bool   `json:"sign_authn_requests,omitempty"`
	PublishEncryptionKey *bool   `json:"publish_encryption_key,omitempty"`
	Binding              *string `json:"binding,omitempty"`
	ResponseBinding      *string `json:"response_binding,omitempty"`
	NameIDFormat         *string `json:"nameid_format,omitempty"`
	AllowUnsolicited     *bool   `json:"allow_unsolicited,omitempty"`
	AllowSHA1            *bool   `json:"allow_sha1,omitempty"`
	AllowUnsignedCBC     *bool   `json:"allow_unsigned_cbc,omitempty"`
	BackChannelLogout    *bool   `json:"back_channel_logout,omitempty"`
	ArtifactForm         *bool   `json:"artifact_form,omitempty"`
}

// APITrusted is the IdP an SP trusts.
type APITrusted struct {
	EntityID string `json:"entity_id"`
	Source   string `json:"metadata_url,omitempty"`
	Metadata string `json:"metadata"`
}

// APIMetadata names metadata: by the URL it is fetched from, or as XML.
type APIMetadata struct {
	MetadataURL string `json:"metadata_url,omitempty"`
	MetadataXML string `json:"metadata_xml,omitempty"`
}

// APIEvent is an entry of an instance's log.
type APIEvent struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	Direction string    `json:"direction"`
	OK        bool      `json:"ok"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	XML       string    `json:"xml,omitempty"`
	URL       string    `json:"url"`
}

func (s *Server) apiView(in *store.Instance) (*APIInstance, error) {
	base := s.BaseURL + "/" + string(in.Kind) + "/" + in.ID
	v := &APIInstance{
		Kind: in.Kind, ID: in.ID, Secret: in.Secret,
		ManageURL:   s.BaseURL + "/manage/" + in.Secret,
		APIURL:      s.BaseURL + "/api/manage/" + in.Secret,
		MetadataURL: base + "/metadata",
		CertURL:     base + "/certificate.pem",
		Certificate: in.CertPEM,
		CreatedAt:   in.CreatedAt.UTC(), ExpiresAt: in.ExpiresAt.UTC(),
	}
	switch in.Kind {
	case store.KindIDP:
		cfg, err := decodeIDPConfig(in.Config)
		if err != nil {
			return nil, err
		}
		v.EntityID = s.idpEntityIDFor(in.ID, cfg)
		idp := &APIIDP{
			SSOURL: base + "/sso", SLOURL: base + "/slo", ArtifactURL: base + "/artifact",
			Profile: profileByKey(cfg.Profile).Key,
			Settings: APIIDPSettings{
				Name:                  &cfg.Name,
				AutoFetchSPMetadata:   &cfg.AutoFetchSPMetadata,
				RequireSignedRequests: &cfg.RequireSignedRequests,
				SignatureMethod:       ptr(oneOf(cfg.SignatureMethod, "sha256", "sha384", "sha512")),
				Encryption:            ptr(oneOf(cfg.Encryption, "auto", "gcm", "gcm128", "cbc256", "cbc", "off")),
				ResponseSigning:       ptr(oneOf(cfg.ResponseSigning, "both", "assertion", "response")),
				RememberSessions:      &cfg.RememberSessions,
				BackChannelLogout:     &cfg.BackChannelLogout,
				ArtifactForm:          &cfg.ArtifactForm,
			},
			Users:            []APIUser{},
			ServiceProviders: []APIRegisteredSP{},
		}
		for _, u := range cfg.Users {
			idp.Users = append(idp.Users, apiUser(u))
		}
		for _, sp := range cfg.ServiceProviders {
			idp.ServiceProviders = append(idp.ServiceProviders, APIRegisteredSP{
				EntityID: sp.EntityID, Source: sp.Source, Metadata: sp.Metadata, AddedAt: sp.AddedAt.UTC(),
			})
		}
		v.IDP = idp
	case store.KindSP:
		cfg, err := decodeSPConfig(in.Config)
		if err != nil {
			return nil, err
		}
		v.EntityID = s.spEntityID(in.ID)
		sp := &APISP{
			ACSURL: base + "/acs", LoginURL: base + "/login", SLOURL: base + "/slo", ArtifactURL: base + "/artifact",
			Settings: APISPSettings{
				Name:                 &cfg.Name,
				SignAuthnRequests:    &cfg.SignAuthnRequests,
				PublishEncryptionKey: &cfg.PublishEncryptionKey,
				Binding:              ptr(apiBindingName(cfg.Binding)),
				ResponseBinding:      ptr(apiResponseBindingName(cfg.ResponseBinding)),
				NameIDFormat:         &cfg.NameIDFormat,
				AllowUnsolicited:     &cfg.AllowUnsolicited,
				AllowSHA1:            &cfg.AllowSHA1,
				AllowUnsignedCBC:     &cfg.AllowUnsignedCBC,
				BackChannelLogout:    &cfg.BackChannelLogout,
				ArtifactForm:         &cfg.ArtifactForm,
			},
		}
		if cfg.IDPMetadata != "" {
			sp.IDP = &APITrusted{EntityID: cfg.IDPEntityID, Source: cfg.IDPMetadataSource, Metadata: cfg.IDPMetadata}
		}
		v.SP = sp
	}
	return v, nil
}

func ptr[T any](v T) *T { return &v }

// The SP's Binding and ResponseBinding are "" for their defaults, which
// the API names.
func apiBindingName(b string) string {
	if b == "" {
		return "auto"
	}
	return b
}

func apiResponseBindingName(b string) string {
	if b == "" {
		return "post"
	}
	return b
}

func apiUser(u User) APIUser {
	out := APIUser{Username: u.Username, NameID: u.NameID, NameIDFormat: u.NameIDFormat, Attributes: []APIAttribute{}}
	for _, a := range u.Attributes {
		values := a.Values
		if values == nil {
			values = []string{}
		}
		out.Attributes = append(out.Attributes, APIAttribute{Name: a.Name, FriendlyName: a.FriendlyName, NameFormat: a.NameFormat, Values: values})
	}
	return out
}

// apiNewIDPRequest is the body of POST /api/idps.
type apiNewIDPRequest struct {
	Profile string `json:"profile"`
	APIIDPSettings
}

func (s *Server) apiNewIDP(w http.ResponseWriter, r *http.Request) {
	var req apiNewIDPRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Profile != "" && profileByKey(req.Profile).Key != req.Profile {
		apiError(w, http.StatusBadRequest, "unknown profile "+strconv.Quote(req.Profile)+"; use one of "+strings.Join(profileKeys(), ", "), nil)
		return
	}
	// Check the settings first: they do not depend on the instance.
	if err := applyIDPSettings(&IDPConfig{}, &req.APIIDPSettings); err != nil {
		apiError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	in, err := s.newInstance(r.Context(), store.KindIDP, func(id string) any {
		cfg := newIDPConfig(id, req.Profile)
		_ = applyIDPSettings(cfg, &req.APIIDPSettings)
		return cfg
	})
	s.apiCreated(w, in, err)
}

// apiNewSPRequest is the body of POST /api/sps.
type apiNewSPRequest struct {
	IDP *APIMetadata `json:"idp"`
	APISPSettings
}

func (s *Server) apiNewSP(w http.ResponseWriter, r *http.Request) {
	var req apiNewSPRequest
	if !readJSON(w, r, &req) {
		return
	}
	cfg := &SPConfig{
		Name:                 "Test SP",
		SignAuthnRequests:    true,
		PublishEncryptionKey: true,
		AllowUnsolicited:     true,
	}
	if err := applySPSettings(cfg, &req.APISPSettings); err != nil {
		apiError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if req.IDP != nil {
		if _, err := s.setIDP(r.Context(), cfg, strings.TrimSpace(req.IDP.MetadataURL), req.IDP.MetadataXML); err != nil {
			apiError(w, http.StatusBadRequest, "cannot use that identity provider: "+err.Error(), nil)
			return
		}
	}
	in, err := s.newInstance(r.Context(), store.KindSP, func(string) any { return cfg })
	s.apiCreated(w, in, err)
}

func (s *Server) apiCreated(w http.ResponseWriter, in *store.Instance, err error) {
	if errors.Is(err, errTooManyInstances) {
		apiError(w, http.StatusServiceUnavailable, s.tooManyMessage(), nil)
		return
	}
	if err != nil {
		apiError(w, http.StatusInternalServerError, "cannot create the instance", err)
		return
	}
	v, err := s.apiView(in)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "cannot read the configuration", err)
		return
	}
	w.Header().Set("Location", v.APIURL)
	writeJSON(w, http.StatusCreated, v)
}

func profileKeys() []string {
	keys := make([]string, 0, len(idpProfiles))
	for _, p := range idpProfiles {
		keys = append(keys, p.Key)
	}
	return keys
}

// apiEnum checks that a setting's value is one of those allowed, and
// sets *dst to it.
func apiEnum(dst *string, v *string, field string, allowed ...string) error {
	if v == nil {
		return nil
	}
	for _, a := range allowed {
		if *v == a {
			*dst = a
			return nil
		}
	}
	return fmt.Errorf("%s must be one of %s, not %q", field, strings.Join(allowed, ", "), *v)
}

func setBool(dst *bool, v *bool) {
	if v != nil {
		*dst = *v
	}
}

func apiName(dst *string, v *string, def string) {
	if v == nil {
		return
	}
	*dst = limit(strings.TrimSpace(*v), 100)
	if *dst == "" {
		*dst = def
	}
}

func applyIDPSettings(cfg *IDPConfig, p *APIIDPSettings) error {
	c := *cfg
	apiName(&c.Name, p.Name, "Test IdP")
	setBool(&c.AutoFetchSPMetadata, p.AutoFetchSPMetadata)
	setBool(&c.RequireSignedRequests, p.RequireSignedRequests)
	setBool(&c.RememberSessions, p.RememberSessions)
	setBool(&c.BackChannelLogout, p.BackChannelLogout)
	setBool(&c.ArtifactForm, p.ArtifactForm)
	if err := errors.Join(
		apiEnum(&c.SignatureMethod, p.SignatureMethod, "signature_method", "sha256", "sha384", "sha512"),
		apiEnum(&c.Encryption, p.Encryption, "encryption", "auto", "gcm", "gcm128", "cbc256", "cbc", "off"),
		apiEnum(&c.ResponseSigning, p.ResponseSigning, "response_signing", "both", "assertion", "response"),
	); err != nil {
		return err
	}
	*cfg = c
	return nil
}

func applySPSettings(cfg *SPConfig, p *APISPSettings) error {
	c := *cfg
	apiName(&c.Name, p.Name, "Test SP")
	setBool(&c.SignAuthnRequests, p.SignAuthnRequests)
	setBool(&c.PublishEncryptionKey, p.PublishEncryptionKey)
	setBool(&c.AllowUnsolicited, p.AllowUnsolicited)
	setBool(&c.AllowSHA1, p.AllowSHA1)
	setBool(&c.AllowUnsignedCBC, p.AllowUnsignedCBC)
	setBool(&c.BackChannelLogout, p.BackChannelLogout)
	setBool(&c.ArtifactForm, p.ArtifactForm)
	binding, responseBinding := apiBindingName(c.Binding), apiResponseBindingName(c.ResponseBinding)
	formats := make([]string, 0, 1+len(nameIDFormats))
	formats = append(formats, "")
	for _, f := range nameIDFormats {
		formats = append(formats, string(f))
	}
	if err := errors.Join(
		apiEnum(&binding, p.Binding, "binding", "auto", "redirect", "post", "simplesign", "artifact"),
		apiEnum(&responseBinding, p.ResponseBinding, "response_binding", "post", "artifact"),
		apiEnum(&c.NameIDFormat, p.NameIDFormat, "nameid_format", formats...),
	); err != nil {
		return err
	}
	c.Binding = strings.TrimPrefix(binding, "auto")
	c.ResponseBinding = strings.TrimPrefix(responseBinding, "post")
	*cfg = c
	return nil
}

func (s *Server) apiGet(w http.ResponseWriter, _ *http.Request, in *store.Instance) {
	v, err := s.apiView(in)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "cannot read the configuration", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) apiPatch(w http.ResponseWriter, r *http.Request, in *store.Instance) {
	switch in.Kind {
	case store.KindIDP:
		s.apiIDP(func(w http.ResponseWriter, r *http.Request, _ *store.Instance, cfg *IDPConfig) (int, any) {
			var p APIIDPSettings
			if !readJSON(w, r, &p) {
				return 0, nil
			}
			if err := applyIDPSettings(cfg, &p); err != nil {
				return http.StatusBadRequest, errorBody(err.Error())
			}
			return http.StatusOK, nil
		})(w, r)
	case store.KindSP:
		s.apiSP(func(w http.ResponseWriter, r *http.Request, _ *store.Instance, cfg *SPConfig) (int, any) {
			var p APISPSettings
			if !readJSON(w, r, &p) {
				return 0, nil
			}
			if err := applySPSettings(cfg, &p); err != nil {
				return http.StatusBadRequest, errorBody(err.Error())
			}
			return http.StatusOK, nil
		})(w, r)
	}
}

func (s *Server) apiDelete(w http.ResponseWriter, r *http.Request, in *store.Instance) {
	if err := s.Store.DeleteInstance(r.Context(), in.ID); err != nil {
		apiError(w, http.StatusInternalServerError, "cannot delete the instance", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiSetProfile(w http.ResponseWriter, r *http.Request, in *store.Instance, cfg *IDPConfig) (int, any) {
	var req struct {
		Profile string `json:"profile"`
	}
	if !readJSON(w, r, &req) {
		return 0, nil
	}
	if profileByKey(req.Profile).Key != req.Profile {
		return http.StatusBadRequest, errorBody("unknown profile " + strconv.Quote(req.Profile) + "; use one of " + strings.Join(profileKeys(), ", "))
	}
	applyProfile(cfg, in.ID, req.Profile)
	return http.StatusOK, nil
}

func (s *Server) apiPutUser(w http.ResponseWriter, r *http.Request, _ *store.Instance, cfg *IDPConfig) (int, any) {
	var u APIUser
	if !readJSON(w, r, &u) {
		return 0, nil
	}
	username := r.PathValue("username")
	if u.Username != "" && u.Username != username {
		return http.StatusBadRequest, errorBody("the username in the body is not the one in the URL")
	}
	user := User{Username: username, NameID: u.NameID, NameIDFormat: u.NameIDFormat}
	if user.NameIDFormat == "" {
		user.NameIDFormat = string(saml.UnspecifiedNameIDFormat)
	}
	for _, a := range u.Attributes {
		if strings.TrimSpace(a.Name) == "" {
			return http.StatusBadRequest, errorBody("every attribute needs a name")
		}
		user.Attributes = append(user.Attributes, samlidp.Attribute{
			Name: a.Name, FriendlyName: a.FriendlyName, NameFormat: a.NameFormat, Values: a.Values,
		})
	}
	err := putUser(cfg, user)
	var lim errLimit
	switch {
	case errors.As(err, &lim):
		return http.StatusConflict, errorBody(err.Error())
	case err != nil:
		return http.StatusBadRequest, errorBody(err.Error())
	}
	for _, saved := range cfg.Users {
		if saved.Username == user.Username {
			return http.StatusOK, apiUser(saved)
		}
	}
	return http.StatusOK, nil
}

func (s *Server) apiDeleteUser(_ http.ResponseWriter, r *http.Request, _ *store.Instance, cfg *IDPConfig) (int, any) {
	if !removeUser(cfg, r.PathValue("username")) {
		return http.StatusNotFound, errorBody("no such user")
	}
	return http.StatusOK, nil
}

func (s *Server) apiAddSP(w http.ResponseWriter, r *http.Request, _ *store.Instance, cfg *IDPConfig) (int, any) {
	var req APIMetadata
	if !readJSON(w, r, &req) {
		return 0, nil
	}
	md, err := s.addSP(r.Context(), cfg, strings.TrimSpace(req.MetadataURL), req.MetadataXML)
	var lim errLimit
	switch {
	case errors.As(err, &lim):
		return http.StatusConflict, errorBody(err.Error())
	case err != nil:
		return http.StatusBadRequest, errorBody("cannot add the service provider: " + err.Error())
	}
	for _, sp := range cfg.ServiceProviders {
		if sp.EntityID == md.EntityID {
			return http.StatusOK, APIRegisteredSP{EntityID: sp.EntityID, Source: sp.Source, Metadata: sp.Metadata, AddedAt: sp.AddedAt.UTC()}
		}
	}
	return http.StatusOK, nil
}

func (s *Server) apiDeleteSP(_ http.ResponseWriter, r *http.Request, _ *store.Instance, cfg *IDPConfig) (int, any) {
	entityID := r.URL.Query().Get("entity_id")
	if entityID == "" {
		return http.StatusBadRequest, errorBody("name the service provider with ?entity_id=")
	}
	if !removeSP(cfg, entityID) {
		return http.StatusNotFound, errorBody("no such service provider")
	}
	return http.StatusOK, nil
}

func (s *Server) apiSetIDP(w http.ResponseWriter, r *http.Request, _ *store.Instance, cfg *SPConfig) (int, any) {
	var req APIMetadata
	if !readJSON(w, r, &req) {
		return 0, nil
	}
	if _, err := s.setIDP(r.Context(), cfg, strings.TrimSpace(req.MetadataURL), req.MetadataXML); err != nil {
		return http.StatusBadRequest, errorBody("cannot use that identity provider: " + err.Error())
	}
	return http.StatusOK, nil
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request, in *store.Instance) {
	var after int64
	if a := r.URL.Query().Get("after"); a != "" {
		var err error
		if after, err = strconv.ParseInt(a, 10, 64); err != nil {
			apiError(w, http.StatusBadRequest, "after must be an event ID", nil)
			return
		}
	}
	events, err := s.Store.EventsAfter(r.Context(), in.ID, after)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "cannot read the log", err)
		return
	}
	out := []APIEvent{}
	for _, e := range events {
		out = append(out, APIEvent{
			ID: e.ID, At: e.At.UTC(), Direction: e.Direction, OK: e.OK,
			Title: e.Title, Detail: e.Detail, XML: e.XML,
			URL: s.BaseURL + "/manage/" + in.Secret + "/log/" + strconv.FormatInt(e.ID, 10),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiClearEvents(w http.ResponseWriter, r *http.Request, in *store.Instance) {
	if err := s.Store.ClearEvents(r.Context(), in.ID); err != nil {
		apiError(w, http.StatusInternalServerError, "cannot clear the log", err)
		return
	}
	s.hub.publish(store.Event{InstanceID: in.ID, ID: clearedEvent})
	w.WriteHeader(http.StatusNoContent)
}
