package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/tools/gosaml/inspect"
	"github.com/crewjam/saml/tools/gosaml/store"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpartifact"
	"github.com/crewjam/saml/x/samlidp/idpslo"
	"github.com/crewjam/saml/xmlenc"
)

// IdPConfig is what a visitor configures about a test IdP.
type IdPConfig struct {
	Name string

	// ServiceProviders are the SPs registered by metadata.
	ServiceProviders []RegisteredSP

	// AutoFetchSPMetadata, if true, accepts a request from an SP that is
	// not registered whose entity ID is a URL, by fetching its metadata
	// from that URL, as many SPs publish it there.
	AutoFetchSPMetadata bool

	Users []User

	// RequireSignedRequests refuses unsigned AuthnRequests.
	RequireSignedRequests bool

	// SignatureMethod is "sha256", "sha384" or "sha512".
	SignatureMethod string

	// Encryption is how assertions are encrypted for SPs that publish an
	// encryption certificate: "auto" (as package saml chooses from the
	// SP's metadata), "gcm" (RSA-OAEP-SHA256 and AES-256-GCM), "cbc"
	// (RSA-OAEP and AES-128-CBC) or "off".
	Encryption string

	// RememberSessions keeps an IdP session after a login, so that the
	// next AuthnRequest from this browser is answered without asking
	// (single sign-on), and IsPassive requests can succeed.
	RememberSessions bool

	// BackChannelLogout advertises a SOAP SingleLogoutService, and logs
	// out SPs that offer one server to server, instead of through the
	// browser.
	BackChannelLogout bool

	// ArtifactForm sends artifacts to SPs with a form the browser posts,
	// instead of a redirect.
	ArtifactForm bool
}

// RegisteredSP is an SP registered with a test IdP.
type RegisteredSP struct {
	EntityID string
	// Source is the URL the metadata was fetched from, or "".
	Source   string
	Metadata string
	AddedAt  time.Time
}

// User is a user of a test IdP.
type User struct {
	Username     string
	NameID       string
	NameIDFormat string
	Attributes   []samlidp.Attribute
}

const (
	maxSPs   = 50
	maxUsers = 50
)

var nameIDFormats = []saml.NameIDFormat{
	saml.EmailAddressNameIDFormat,
	saml.PersistentNameIDFormat,
	saml.TransientNameIDFormat,
	saml.UnspecifiedNameIDFormat,
}

var authnContexts = []saml.AuthnContextClass{
	saml.AuthnContextPasswordProtectedTransport,
	saml.AuthnContextPassword,
	saml.AuthnContextMobileTwoFactorContract,
	saml.AuthnContextSmartcardPKI,
	saml.AuthnContextX509,
	saml.AuthnContextKerberos,
	saml.AuthnContextUnspecified,
}

// statusErrors are the error Responses a visitor can send instead of
// logging in, to test how an SP handles them.
var statusErrors = []struct{ Label, Top, Second string }{
	{"AuthnFailed", saml.StatusResponder, saml.StatusAuthnFailed},
	{"RequestDenied", saml.StatusResponder, saml.StatusRequestDenied},
	{"NoPassive", saml.StatusResponder, saml.StatusNoPassive},
	{"NoAuthnContext", saml.StatusResponder, saml.StatusNoAuthnContext},
	{"UnknownPrincipal", saml.StatusResponder, saml.StatusUnknownPrincipal},
	{"InvalidNameIDPolicy", saml.StatusResponder, saml.StatusInvalidNameIDPolicy},
	{"Responder (no second-level code)", saml.StatusResponder, ""},
	{"Requester (no second-level code)", saml.StatusRequester, ""},
}

func defaultUsers() []User {
	user := func(username, given, family string, groups ...string) User {
		mail := username + "@example.com"
		attrs := []samlidp.Attribute{
			uriAttr("urn:oid:0.9.2342.19200300.100.1.1", "uid", username),
			uriAttr("urn:oid:0.9.2342.19200300.100.1.3", "mail", mail),
			uriAttr("urn:oid:2.5.4.42", "givenName", given),
			uriAttr("urn:oid:2.5.4.4", "sn", family),
			uriAttr("urn:oid:2.16.840.1.113730.3.1.241", "displayName", given+" "+family),
			{Name: "email", Values: []string{mail}},
			{Name: "firstName", Values: []string{given}},
			{Name: "lastName", Values: []string{family}},
		}
		if len(groups) > 0 {
			attrs = append(attrs, samlidp.Attribute{Name: "groups", Values: groups})
		}
		return User{Username: username, NameID: mail, NameIDFormat: string(saml.EmailAddressNameIDFormat), Attributes: attrs}
	}
	return []User{
		user("alice", "Alice", "Anderson", "admins", "users"),
		user("bob", "Bob", "Brown", "users"),
		user("carol", "Carol", "Clark"),
	}
}

func uriAttr(name, friendly, value string) samlidp.Attribute {
	return samlidp.Attribute{
		Name: name, FriendlyName: friendly, Values: []string{value},
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
	}
}

func encodeConfig(v any) (json.RawMessage, error) { return json.Marshal(v) }

func decodeIdPConfig(raw json.RawMessage) (*IdPConfig, error) {
	var c IdPConfig
	err := json.Unmarshal(raw, &c)
	return &c, err
}

func (s *Server) idpEntityID(id string) string { return s.BaseURL + "/idp/" + id + "/metadata" }

func (s *Server) newIdP(w http.ResponseWriter, r *http.Request) {
	s.createInstance(w, r, store.KindIdP, &IdPConfig{
		Name:                "Test IdP",
		AutoFetchSPMetadata: true,
		Users:               defaultUsers(),
		SignatureMethod:     "sha256",
		Encryption:          "auto",
		RememberSessions:    true,
	})
}

// loadIdP returns the instance named in the URL and its configuration.
func (s *Server) loadIdP(ctx context.Context, id string) (*store.Instance, *IdPConfig, error) {
	in, err := s.Store.Instance(ctx, store.KindIdP, id)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := decodeIdPConfig(in.Config)
	return in, cfg, err
}

// samlIdP builds the x/samlidp configuration of an instance.
func (s *Server) samlIdP(in *store.Instance, cfg *IdPConfig) (*samlidp.Config, error) {
	key, cert, err := parseKeyPair(in.KeyPEM, in.CertPEM)
	if err != nil {
		return nil, err
	}
	sps := func(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
		md, err := s.lookupSP(ctx, cfg, entityID)
		if err != nil {
			return nil, err
		}
		if cfg.Encryption == "off" {
			md = withoutEncryptionKeys(md)
		}
		return md, nil
	}
	method := dsig.RSASHA256SignatureMethod
	switch cfg.SignatureMethod {
	case "sha384":
		method = dsig.RSASHA384SignatureMethod
	case "sha512":
		method = dsig.RSASHA512SignatureMethod
	}
	opts := []samlidp.Option{
		samlidp.WithSigningKey(key, cert),
		samlidp.WithSignatureMethod(method),
		samlidp.WithReplayState(s.Store),
		samlidp.WithNameIDFormats(nameIDFormats...),
		samlidp.WithMetadataValidity(time.Until(in.ExpiresAt)),
		idpartifact.ResolutionService(s.BaseURL+"/idp/"+in.ID+"/artifact", 1),
	}
	sloOpts := []idpslo.EndpointOption{idpslo.WithHTTPClient(s.soap)}
	if cfg.BackChannelLogout {
		sloOpts = append(sloOpts, idpslo.BackChannel)
	}
	opts = append(opts, idpslo.Endpoint(s.BaseURL+"/idp/"+in.ID+"/slo", sloOpts...))
	if strings.HasPrefix(s.BaseURL, "http://") {
		// Only for local development, where this server itself is served
		// over http; in production it is https.
		opts = append(opts, samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
			idp.AllowInsecureSOAPEndpoints = true
		}))
	}
	if cfg.RequireSignedRequests {
		opts = append(opts, samlidp.RequireSignedAuthnRequests)
	}
	switch cfg.Encryption {
	case "gcm":
		opts = append(opts, samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
			enc := xmlenc.OAEP_SHA256()
			enc.BlockCipher = xmlenc.AES256GCM
			idp.AssertionEncrypter = enc
		}))
	case "cbc":
		opts = append(opts, samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
			enc := xmlenc.OAEP()
			enc.BlockCipher = xmlenc.AES128CBC
			idp.AssertionEncrypter = enc
		}))
	}
	return samlidp.New(s.idpEntityID(in.ID), sps, opts...)
}

func (s *Server) lookupSP(ctx context.Context, cfg *IdPConfig, entityID string) (*saml.EntityDescriptor, error) {
	for _, sp := range cfg.ServiceProviders {
		if sp.EntityID == entityID {
			return samlidp.ParseMetadata([]byte(sp.Metadata))
		}
	}
	if cfg.AutoFetchSPMetadata && (strings.HasPrefix(entityID, "https://") || strings.HasPrefix(entityID, "http://")) {
		b, err := s.fetchMetadata(ctx, entityID)
		if err != nil {
			return nil, fmt.Errorf("%w: the SP is not registered, and its metadata could not be fetched from its entity ID: %v",
				saml.ErrUnknownServiceProvider, err)
		}
		return samlidp.ParseMetadata(b, samlidp.WithServiceProviderEntityID(entityID))
	}
	return nil, saml.ErrUnknownServiceProvider
}

// withoutEncryptionKeys returns a copy of md whose SPs publish no
// encryption key, so that the IdP does not encrypt assertions for them.
func withoutEncryptionKeys(md *saml.EntityDescriptor) *saml.EntityDescriptor {
	c := *md
	c.SPSSODescriptors = append([]saml.SPSSODescriptor(nil), md.SPSSODescriptors...)
	for i := range c.SPSSODescriptors {
		var keys []saml.KeyDescriptor
		for _, k := range c.SPSSODescriptors[i].KeyDescriptors {
			if k.Use == "encryption" {
				continue
			}
			if k.Use == "" {
				k.Use = "signing"
			}
			keys = append(keys, k)
		}
		c.SPSSODescriptors[i].KeyDescriptors = keys
	}
	return &c
}

func (s *Server) idpMetadata(w http.ResponseWriter, r *http.Request) {
	in, cfg, err := s.loadIdP(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.samlIdP(in, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.ServeMetadata(w, r)
}

// localMetadata answers a metadata URL of one of this server's instances
// without a request. ok is false if the URL is not one.
func (s *Server) localMetadata(ctx context.Context, rawURL string) (b []byte, ok bool, err error) {
	rest, found := strings.CutPrefix(rawURL, s.BaseURL+"/")
	if !found {
		return nil, false, nil
	}
	kind, rest, _ := strings.Cut(rest, "/")
	id, tail, _ := strings.Cut(rest, "/")
	if tail != "metadata" {
		return nil, false, nil
	}
	switch kind {
	case "idp":
		in, cfg, err := s.loadIdP(ctx, id)
		if err != nil {
			return nil, true, errors.New("no such IdP on this server (it may have expired)")
		}
		c, err := s.samlIdP(in, cfg)
		if err != nil {
			return nil, true, err
		}
		b, err := c.MetadataXML()
		return b, true, err
	case "sp":
		in, cfg, err := s.loadSP(ctx, id)
		if err != nil {
			return nil, true, errors.New("no such SP on this server (it may have expired)")
		}
		c, err := s.samlSP(in, cfg)
		if err != nil {
			return nil, true, err
		}
		b, err := c.MetadataXML(ctx)
		return b, true, err
	}
	return nil, false, nil
}

// loginPage is the data of the IdP's login page.
type loginPage struct {
	InstanceID   string
	Name         string
	PendingID    string
	Request      *samlidp.AuthnRequest
	Users        []User
	Formats      []saml.NameIDFormat
	Contexts     []saml.AuthnContextClass
	Errors       []string
	SelectedCtx  string
	ManageSecret string
}

// showLogin keeps req and shows the page where the visitor chooses who to
// log in as.
func (s *Server) showLogin(w http.ResponseWriter, r *http.Request, in *store.Instance, cfg *IdPConfig, req *samlidp.AuthnRequest) {
	pid := rand.Text()
	if err := s.Store.PutPending(r.Context(), pid, in.ID, req, time.Hour); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot keep the login request.", err)
		return
	}
	p := loginPage{
		InstanceID: in.ID, Name: cfg.Name, PendingID: pid, Request: req, Users: cfg.Users,
		Formats: nameIDFormats, Contexts: authnContexts,
	}
	for _, e := range statusErrors {
		p.Errors = append(p.Errors, e.Label)
	}
	if len(req.AuthnContextClasses) > 0 {
		p.SelectedCtx = string(req.AuthnContextClasses[0])
	}
	s.renderStatus(w, r, http.StatusOK, "idp_login", cfg.Name, p)
}

func describeAuthnRequest(req *samlidp.AuthnRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ACS: %s (%s)\n", req.ACSURL, shortURN(req.ACSBinding))
	if req.RelayState != "" {
		fmt.Fprintf(&b, "RelayState: %s\n", req.RelayState)
	}
	if req.NameIDFormat != "" {
		fmt.Fprintf(&b, "NameID format: %s\n", req.NameIDFormat)
	}
	if req.ForceAuthn {
		b.WriteString("ForceAuthn\n")
	}
	if req.IsPassive {
		b.WriteString("IsPassive\n")
	}
	for _, c := range req.AuthnContextClasses {
		fmt.Fprintf(&b, "AuthnContext (%s): %s\n", req.AuthnContextComparison, c)
	}
	return strings.TrimSpace(b.String())
}

// sendIdPMessage logs a Response and sends it to the SP.
func (s *Server) sendIdPMessage(w http.ResponseWriter, r *http.Request, in *store.Instance, msg *samlidp.Message, err error) {
	if err != nil {
		s.logEvent(r.Context(), &store.Event{InstanceID: in.ID, Direction: "out", Title: "Cannot make the Response", Detail: errorChain(err)})
		s.fail(w, r, http.StatusInternalServerError, "The IdP cannot make the Response.", err)
		return
	}
	xml := ""
	if b, err := inspect.DecodeBase64Message(msg.FormValues()["SAMLResponse"]); err == nil {
		xml = inspect.Pretty(b)
	}
	art := msg.FormValues()["SAMLart"]
	if u := msg.RedirectURL(); u != nil && art == "" {
		art = u.Query().Get("SAMLart")
	}
	title := "Response to " + msg.Destination
	ok := true
	if msg.Participant == nil {
		title = "Error Response to " + msg.Destination
		ok = false
	}
	detail := "Binding: " + shortURN(msg.Binding)
	if msg.RelayState != "" {
		detail += "\nRelayState: " + msg.RelayState
	}
	if p := msg.Participant; p != nil {
		detail += "\nNameID: " + p.NameID.Value + " (" + shortURN(p.NameID.Format) + ")"
	}
	if art != "" {
		detail += "\nArtifact: " + art + "\n(the SP resolves it at this IdP's ArtifactResolutionService)"
	}
	s.logEvent(r.Context(), &store.Event{InstanceID: in.ID, Direction: "out", OK: ok, Title: title, Detail: detail, XML: xml})
	msg.Write(w)
}

// idpManagePage is the data of an IdP's management page.
type idpManagePage struct {
	Secret      string
	Max         int
	Instance    *store.Instance
	Config      *IdPConfig
	EntityID    string
	SSOURL      string
	MetadataURL string
	CertURL     string
	SLOURL      string
	ArtifactURL string
	Sessions    []idpSessionView
	Events      []store.Event
	Flash       string
	Formats     []saml.NameIDFormat
	Others      []myInstance
	// Current is this browser's session at the IdP, if any.
	Current *idpSession
}

func (s *Server) manageIdP(w http.ResponseWriter, r *http.Request, in *store.Instance) {
	cfg, err := decodeIdPConfig(in.Config)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the configuration.", err)
		return
	}
	events, err := s.Store.Events(r.Context(), in.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the log.", err)
		return
	}
	p := idpManagePage{
		Secret: in.Secret, Max: store.MaxEventsPerInstance,
		Instance: in, Config: cfg, EntityID: s.idpEntityID(in.ID),
		SSOURL:      s.BaseURL + "/idp/" + in.ID + "/sso",
		MetadataURL: s.idpEntityID(in.ID),
		CertURL:     s.BaseURL + "/idp/" + in.ID + "/certificate.pem",
		SLOURL:      s.BaseURL + "/idp/" + in.ID + "/slo",
		ArtifactURL: s.BaseURL + "/idp/" + in.ID + "/artifact",
		Events:      events, Flash: flashMessage(r), Formats: nameIDFormats,
	}
	if run, err := s.idpRun(r.Context(), in.ID); err == nil {
		p.Current, _ = s.idpSessionFromCookie(r, run)
	}
	p.Sessions, err = s.idpSessionViews(r.Context(), in)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the sessions.", err)
		return
	}
	for _, m := range s.myInstances(r) {
		if m.Kind == store.KindSP {
			p.Others = append(p.Others, m)
		}
	}
	s.renderStatus(w, r, http.StatusOK, "idp_manage", cfg.Name, p)
}

func (s *Server) saveIdPConfig(w http.ResponseWriter, r *http.Request, in *store.Instance, cfg *IdPConfig, msg, anchor string) {
	b, err := encodeConfig(cfg)
	if err == nil {
		err = s.Store.UpdateConfig(r.Context(), in.ID, b)
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot save the configuration.", err)
		return
	}
	flash(w, r, in, msg, anchor)
}

func (s *Server) idpAction(w http.ResponseWriter, r *http.Request, in *store.Instance, action string) {
	ctx := r.Context()
	cfg, err := decodeIdPConfig(in.Config)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the configuration.", err)
		return
	}
	switch action {
	case "settings":
		cfg.Name = limit(strings.TrimSpace(r.FormValue("name")), 100)
		if cfg.Name == "" {
			cfg.Name = "Test IdP"
		}
		cfg.AutoFetchSPMetadata = r.FormValue("auto_fetch") != ""
		cfg.RequireSignedRequests = r.FormValue("require_signed") != ""
		cfg.SignatureMethod = oneOf(r.FormValue("signature_method"), "sha256", "sha384", "sha512")
		cfg.Encryption = oneOf(r.FormValue("encryption"), "auto", "gcm", "cbc", "off")
		cfg.RememberSessions = r.FormValue("remember_sessions") != ""
		cfg.BackChannelLogout = r.FormValue("back_channel") != ""
		cfg.ArtifactForm = r.FormValue("artifact_form") != ""
		s.saveIdPConfig(w, r, in, cfg, "Settings saved.", "settings")

	case "sp-add":
		var data []byte
		source := strings.TrimSpace(r.FormValue("metadata_url"))
		if source != "" {
			data, err = s.fetchMetadata(ctx, source)
		} else {
			data = []byte(strings.TrimSpace(r.FormValue("metadata_xml")))
			if len(data) == 0 {
				err = errors.New("give a metadata URL or paste the metadata XML")
			}
		}
		var md *saml.EntityDescriptor
		if err == nil {
			md, err = samlidp.ParseMetadata(data)
		}
		if err != nil {
			flash(w, r, in, "Cannot add the service provider: "+err.Error(), "sps")
			return
		}
		sp := RegisteredSP{EntityID: md.EntityID, Source: source, Metadata: string(data), AddedAt: time.Now()}
		replaced := false
		for i := range cfg.ServiceProviders {
			if cfg.ServiceProviders[i].EntityID == md.EntityID {
				cfg.ServiceProviders[i] = sp
				replaced = true
			}
		}
		if !replaced {
			if len(cfg.ServiceProviders) >= maxSPs {
				flash(w, r, in, fmt.Sprintf("An IdP can have at most %d service providers.", maxSPs), "sps")
				return
			}
			cfg.ServiceProviders = append(cfg.ServiceProviders, sp)
		}
		s.saveIdPConfig(w, r, in, cfg, "Service provider "+md.EntityID+" saved.", "sps")

	case "sp-refresh":
		entityID := r.FormValue("entity_id")
		for i, sp := range cfg.ServiceProviders {
			if sp.EntityID != entityID || sp.Source == "" {
				continue
			}
			data, err := s.fetchMetadata(ctx, sp.Source)
			if err == nil {
				_, err = samlidp.ParseMetadata(data, samlidp.WithServiceProviderEntityID(entityID))
			}
			if err != nil {
				flash(w, r, in, "Cannot refresh the metadata: "+err.Error(), "sps")
				return
			}
			cfg.ServiceProviders[i].Metadata = string(data)
			cfg.ServiceProviders[i].AddedAt = time.Now()
		}
		s.saveIdPConfig(w, r, in, cfg, "Metadata refreshed.", "sps")

	case "sp-remove":
		entityID := r.FormValue("entity_id")
		var kept []RegisteredSP
		for _, sp := range cfg.ServiceProviders {
			if sp.EntityID != entityID {
				kept = append(kept, sp)
			}
		}
		cfg.ServiceProviders = kept
		s.saveIdPConfig(w, r, in, cfg, "Service provider removed.", "sps")

	case "user-save":
		username := limit(strings.TrimSpace(r.FormValue("username")), 100)
		if username == "" {
			flash(w, r, in, "A user needs a username.", "users")
			return
		}
		attrs, err := parseAttributes(r.FormValue("attributes"))
		if err != nil {
			flash(w, r, in, "Cannot save "+username+": "+err.Error(), "users")
			return
		}
		u := User{
			Username:     username,
			NameID:       limit(strings.TrimSpace(r.FormValue("nameid")), 1000),
			NameIDFormat: r.FormValue("nameid_format"),
			Attributes:   attrs,
		}
		if u.NameID == "" {
			u.NameID = username
		}
		replaced := false
		for i := range cfg.Users {
			if cfg.Users[i].Username == username {
				cfg.Users[i] = u
				replaced = true
			}
		}
		if !replaced {
			if len(cfg.Users) >= maxUsers {
				flash(w, r, in, fmt.Sprintf("An IdP can have at most %d users.", maxUsers), "users")
				return
			}
			cfg.Users = append(cfg.Users, u)
		}
		s.saveIdPConfig(w, r, in, cfg, "User "+username+" saved.", "users")

	case "user-remove":
		var kept []User
		for _, u := range cfg.Users {
			if u.Username != r.FormValue("username") {
				kept = append(kept, u)
			}
		}
		cfg.Users = kept
		s.saveIdPConfig(w, r, in, cfg, "User removed.", "users")

	case "initiate":
		run, err := s.idpRun(ctx, in.ID)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "The IdP is misconfigured.", err)
			return
		}
		req, err := run.c.IDPInitiated(ctx, r.FormValue("entity_id"), r.FormValue("relay_state"), run.binding())
		if err != nil {
			flash(w, r, in, "Cannot start an IdP-initiated login: "+errorChain(err), "initiate")
			return
		}
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, OK: true, Title: "IdP-initiated login to " + req.ServiceProvider, Detail: describeAuthnRequest(req)})
		s.showLogin(w, r, in, cfg, req)

	case "session-logout":
		run, err := s.idpRun(ctx, in.ID)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "The IdP is misconfigured.", err)
			return
		}
		s.startIdPLogout(w, r, run, r.FormValue("session_id"))

	case "session-delete":
		if err := s.Store.DeleteSession(ctx, r.FormValue("session_id"), in.ID); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "Cannot delete the session.", err)
			return
		}
		flash(w, r, in, "Session deleted, without logging out of its service providers.", "sessions")

	default:
		http.NotFound(w, r)
	}
}

func oneOf(v string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return allowed[0]
}

func limit(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// formatAttributes writes attributes in the form parseAttributes reads:
// one value per line, "Name (FriendlyName) = value".
func formatAttributes(attrs []samlidp.Attribute) string {
	var b strings.Builder
	for _, a := range attrs {
		label := a.Name
		if a.FriendlyName != "" {
			label += " (" + a.FriendlyName + ")"
		}
		for _, v := range a.Values {
			b.WriteString(label + " = " + v + "\n")
		}
	}
	return b.String()
}

// parseAttributes reads attributes written one value per line, as
// "Name = value" or "Name (FriendlyName) = value". Lines with the same
// name make a multi-valued attribute. A name that is a URN is given the
// URI name format.
func parseAttributes(text string) ([]samlidp.Attribute, error) {
	var attrs []samlidp.Attribute
	index := map[string]int{}
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d has no \"=\"", n+1)
		}
		label, value = strings.TrimSpace(label), strings.TrimSpace(value)
		name, friendly := label, ""
		if i := strings.Index(label, "("); i > 0 && strings.HasSuffix(label, ")") {
			name = strings.TrimSpace(label[:i])
			friendly = strings.TrimSpace(label[i+1 : len(label)-1])
		}
		if name == "" {
			return nil, fmt.Errorf("line %d has no attribute name", n+1)
		}
		if i, ok := index[name]; ok {
			attrs[i].Values = append(attrs[i].Values, value)
			continue
		}
		a := samlidp.Attribute{Name: name, FriendlyName: friendly, Values: []string{value}}
		if strings.HasPrefix(name, "urn:") {
			a.NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
		}
		index[name] = len(attrs)
		attrs = append(attrs, a)
		if len(attrs) > 100 {
			return nil, errors.New("too many attributes")
		}
	}
	return attrs, nil
}

// userFormData is the data of the "user-fields" template.
type userFormData struct {
	User    *User
	Formats []saml.NameIDFormat
	Text    string
}

func init() {
	funcs["userForm"] = func(u any, _ any) userFormData {
		d := userFormData{Formats: nameIDFormats}
		if user, ok := u.(User); ok {
			d.User = &user
			d.Text = formatAttributes(user.Attributes)
		} else {
			d.Text = "email = someone@example.com\n"
		}
		return d
	}
}
