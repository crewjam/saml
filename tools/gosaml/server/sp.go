package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/tools/gosaml/inspect"
	"github.com/crewjam/saml/tools/gosaml/store"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

// SPConfig is what a visitor configures about a test SP.
type SPConfig struct {
	Name string

	// IdPMetadata is the metadata of the IdP the SP trusts, and
	// IdPMetadataSource the URL it was fetched from, if any.
	IdPMetadata       string
	IdPMetadataSource string
	IdPEntityID       string

	SignAuthnRequests    bool
	PublishEncryptionKey bool

	// Binding is how the AuthnRequest is sent: "" (as the IdP's metadata
	// allows, preferring HTTP-Redirect), "redirect", "post" or
	// "simplesign".
	Binding string

	// NameIDFormat, if not empty, is asked for in the NameIDPolicy.
	NameIDFormat string

	// AllowUnsolicited accepts IdP-initiated Responses.
	AllowUnsolicited bool

	// AllowSHA1 and AllowUnsignedCBC relax checks that x/samlsp makes by
	// default, for IdPs that need it.
	AllowSHA1        bool
	AllowUnsignedCBC bool
}

func decodeSPConfig(raw json.RawMessage) (*SPConfig, error) {
	var c SPConfig
	err := json.Unmarshal(raw, &c)
	return &c, err
}

func (s *Server) spEntityID(id string) string { return s.BaseURL + "/sp/" + id + "/metadata" }

func (s *Server) newSP(w http.ResponseWriter, r *http.Request) {
	s.createInstance(w, r, store.KindSP, &SPConfig{
		Name:                 "Test SP",
		SignAuthnRequests:    true,
		PublishEncryptionKey: true,
		AllowUnsolicited:     true,
	})
}

func (s *Server) loadSP(ctx context.Context, id string) (*store.Instance, *SPConfig, error) {
	in, err := s.Store.Instance(ctx, store.KindSP, id)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := decodeSPConfig(in.Config)
	return in, cfg, err
}

// samlSP builds the x/samlsp configuration of an instance.
func (s *Server) samlSP(in *store.Instance, cfg *SPConfig) (*samlsp.Config, error) {
	key, cert, err := parseKeyPair(in.KeyPEM, in.CertPEM)
	if err != nil {
		return nil, err
	}
	var idp samlsp.MetadataFunc
	if cfg.IdPMetadata != "" {
		idp = samlsp.StaticMetadataBytes([]byte(cfg.IdPMetadata))
	}
	opts := []samlsp.Option{
		samlsp.WithSigningKey(key, cert),
		samlsp.WithReplayState(s.Store),
		samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
			if cfg.AllowSHA1 {
				sp.RejectSHA1Signatures = false
			}
			if cfg.AllowUnsignedCBC {
				sp.RequireSignedResponseForCBC = false
			}
		}),
	}
	if cfg.PublishEncryptionKey {
		opts = append(opts, samlsp.WithEncryptionKey(key, cert))
	}
	if cfg.SignAuthnRequests {
		opts = append(opts, samlsp.SignAuthnRequests)
	}
	// x/samlsp asks for a transient NameID unless told otherwise. With no
	// format chosen, ask for "unspecified", which leaves it to the IdP.
	format := saml.UnspecifiedNameIDFormat
	if cfg.NameIDFormat != "" {
		format = saml.NameIDFormat(cfg.NameIDFormat)
	}
	opts = append(opts, samlsp.WithNameIDFormat(format))
	return samlsp.New(s.spEntityID(in.ID), idp, opts...)
}

func (s *Server) spMetadata(w http.ResponseWriter, r *http.Request) {
	in, cfg, err := s.loadSP(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.samlSP(in, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.ServeMetadata(w, r)
}

func (s *Server) tracker(in *store.Instance, c *samlsp.Config) (*pending.Tracker, error) {
	key, err := pending.DeriveKey(s.cookieKey, "sp:"+in.ID)
	if err != nil {
		return nil, err
	}
	return pending.New(c, key, pending.WithCookiePrefix("gosaml_"+in.ID+"_"))
}

// spLogin sends the browser to the IdP with an AuthnRequest. The options
// come from the form on the management page; with none, as from a plain
// link, the SP's settings apply.
func (s *Server) spLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, cfg, err := s.loadSP(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This SP does not exist. Test SPs expire "+roundDuration(s.TTL)+" after they are created.", nil)
		return
	}
	if cfg.IdPMetadata == "" {
		s.fail(w, r, http.StatusConflict, "This SP has no identity provider yet. Add the IdP's metadata on the SP's management page.", nil)
		return
	}
	c, err := s.samlSP(in, cfg)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "The SP is misconfigured.", err)
		return
	}
	_ = r.ParseForm()
	opts := []samlsp.AuthnOption{samlsp.WithScriptNonce(nonce(r))}
	binding := cfg.Binding
	if b := r.Form.Get("binding"); b != "" {
		binding = b
	}
	switch binding {
	case "redirect":
		opts = append(opts, samlsp.WithBinding(saml.HTTPRedirectBinding))
	case "post":
		opts = append(opts, samlsp.WithBinding(saml.HTTPPostBinding))
	case "simplesign":
		opts = append(opts, samlsp.WithBinding(saml.HTTPPostSimpleSignBinding))
	}
	if r.Form.Get("force_authn") != "" {
		opts = append(opts, samlsp.ForceAuthn)
	}
	if r.Form.Get("is_passive") != "" {
		opts = append(opts, samlsp.IsPassive)
	}
	authnContext := r.Form.Get("authn_context")
	if authnContext != "" {
		opts = append(opts, samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextClass(authnContext)))
	}
	relayState := strings.TrimSpace(r.Form.Get("relay_state"))
	if relayState == "" {
		relayState = rand.Text()
	}
	msg, err := c.AuthnRequest(ctx, relayState, opts...)
	if err != nil {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "out", Title: "Cannot make the AuthnRequest", Detail: errorChain(err)})
		s.fail(w, r, http.StatusInternalServerError, "The SP cannot make the AuthnRequest.", err)
		return
	}
	t, err := s.tracker(in, c)
	if err == nil {
		err = t.Remember(w, msg, authnContext)
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot remember the login.", err)
		return
	}
	value := msg.FormFields().Get("SAMLRequest")
	if u := msg.RedirectURL(); u != nil && value == "" {
		value = u.Query().Get("SAMLRequest")
	}
	xml := ""
	if b, err := inspect.DecodeBase64Message(value); err == nil {
		xml = inspect.Pretty(b)
	}
	s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "out", OK: true,
		Title:  "AuthnRequest to " + msg.Destination,
		Detail: "Binding: " + shortURN(msg.Binding) + "\nID: " + msg.ID + "\nRelayState: " + msg.RelayState, XML: xml})
	msg.Write(w)
}

// spResult is the data of the page the ACS shows.
type spResult struct {
	InstanceID   string
	Name         string
	ManageURL    string
	Assertion    *samlsp.Assertion
	Error        string
	Hints        []string
	ResponseXML  string
	AssertionXML string
	RelayState   string
	Unsolicited  bool
}

func (s *Server) spACS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, cfg, err := s.loadSP(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This SP does not exist or has expired.", nil)
		return
	}
	c, err := s.samlSP(in, cfg)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "The SP is misconfigured.", err)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "Cannot read the request.", err)
		return
	}
	res := spResult{InstanceID: in.ID, Name: cfg.Name, RelayState: r.Form.Get("RelayState")}
	for _, secret := range mine(r) {
		// Link to the management page only for the browser that created
		// the SP: whoever else logs in through it must not learn the URL.
		if secret == in.Secret {
			res.ManageURL = "/manage/" + in.Secret
		}
	}
	if v := r.Form.Get("SAMLResponse"); v != "" {
		if b, err := inspect.DecodeBase64Message(v); err == nil {
			res.ResponseXML = inspect.Pretty(b)
		}
	}

	var opts []samlsp.ResponseOption
	t, err := s.tracker(in, c)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the login.", err)
		return
	}
	if login, err := t.Take(w, r); err == nil {
		opts = append(opts, samlsp.WithRequestID(login.ID))
		if login.Data != "" {
			opts = append(opts, samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextClass(login.Data)))
		}
	} else {
		res.Unsolicited = true
	}
	if cfg.AllowUnsolicited {
		opts = append(opts, samlsp.AllowUnsolicited)
	}

	assertion, err := c.ParseResponse(ctx, r, opts...)
	if err != nil {
		res.Error = errorChain(err)
		res.Hints = hints(err, cfg, res.Unsolicited)
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", Title: "Response refused", Detail: res.Error, XML: res.ResponseXML})
		s.renderStatus(w, r, http.StatusForbidden, "sp_result", cfg.Name, res)
		return
	}
	res.Assertion = assertion
	if assertion.Raw != nil {
		doc := etree.NewDocument()
		doc.SetRoot(assertion.Raw.Element())
		doc.Indent(2)
		res.AssertionXML, _ = doc.WriteToString()
	}
	detail := "Subject: " + assertion.Subject + " (" + shortURN(assertion.NameID.Format) + ")\nIssuer: " + assertion.Issuer
	if assertion.InResponseTo == "" {
		detail += "\nUnsolicited (IdP-initiated)"
	}
	s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", OK: true, Title: "Logged in " + assertion.Subject, Detail: detail, XML: res.ResponseXML})
	s.renderStatus(w, r, http.StatusOK, "sp_result", cfg.Name, res)
}

// hints suggests causes for common ways a Response is refused.
func hints(err error, cfg *SPConfig, unsolicited bool) []string {
	var out []string
	var status saml.ErrBadStatus
	switch {
	case errors.As(err, &status):
		out = append(out, "The IdP answered with an error status instead of logging the user in. Its log may say why.")
	case errors.Is(err, saml.ErrUntrustedCertificate):
		out = append(out, "The Response is signed with a certificate that is not in the IdP metadata this SP has. If the IdP rotated its key, refresh the metadata.")
	case errors.Is(err, saml.ErrExpired), errors.Is(err, saml.ErrNotYetValid):
		out = append(out, "The assertion is outside its validity window: check the IdP's clock, or the Response was sent again later.")
	case errors.Is(err, saml.ErrAssertionReplayed):
		out = append(out, "This assertion was already accepted once. Reloading the ACS page sends the same Response again.")
	case errors.Is(err, saml.ErrUnsupported) && !cfg.AllowSHA1:
		out = append(out, "If the IdP signs with SHA-1, turn on \"Accept SHA-1 signatures\" in the SP's settings.")
	}
	msg := errorChain(err)
	if unsolicited && !cfg.AllowUnsolicited {
		out = append(out, "No login was started from this browser, so the Response is unsolicited, and this SP refuses those. Turn on \"Accept IdP-initiated logins\".")
	}
	if strings.Contains(msg, "CBC") && !cfg.AllowUnsignedCBC {
		out = append(out, "The assertion is encrypted with AES-CBC in a Response that is not signed. Have the IdP sign the Response, or turn on \"Accept AES-CBC in unsigned Responses\".")
	}
	if strings.Contains(msg, "InResponseTo") && unsolicited {
		out = append(out, "The login this Response answers is not in progress in this browser: it was already completed (reloading this page sends the same Response again), started in another browser, or more than ten minutes ago.")
	}
	return out
}

// spManagePage is the data of an SP's management page.
type spManagePage struct {
	Secret      string
	Max         int
	Instance    *store.Instance
	Config      *SPConfig
	EntityID    string
	ACSURL      string
	MetadataURL string
	LoginURL    string
	CertURL     string
	Events      []store.Event
	Flash       string
	Formats     []saml.NameIDFormat
	Contexts    []saml.AuthnContextClass
	Others      []myInstance
}

func (s *Server) manageSP(w http.ResponseWriter, r *http.Request, in *store.Instance) {
	cfg, err := decodeSPConfig(in.Config)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the configuration.", err)
		return
	}
	events, err := s.Store.Events(r.Context(), in.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the log.", err)
		return
	}
	p := spManagePage{
		Secret: in.Secret, Max: store.MaxEventsPerInstance,
		Instance: in, Config: cfg, EntityID: s.spEntityID(in.ID),
		ACSURL:      s.BaseURL + "/sp/" + in.ID + "/acs",
		MetadataURL: s.spEntityID(in.ID),
		LoginURL:    s.BaseURL + "/sp/" + in.ID + "/login",
		CertURL:     s.BaseURL + "/sp/" + in.ID + "/certificate.pem",
		Events:      events, Flash: flashMessage(r), Formats: nameIDFormats, Contexts: authnContexts,
	}
	for _, m := range s.myInstances(r) {
		if m.Kind == store.KindIdP {
			p.Others = append(p.Others, m)
		}
	}
	s.renderStatus(w, r, http.StatusOK, "sp_manage", cfg.Name, p)
}

func (s *Server) spAction(w http.ResponseWriter, r *http.Request, in *store.Instance, action string) {
	ctx := r.Context()
	cfg, err := decodeSPConfig(in.Config)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the configuration.", err)
		return
	}
	save := func(msg, anchor string) {
		b, err := encodeConfig(cfg)
		if err == nil {
			err = s.Store.UpdateConfig(ctx, in.ID, b)
		}
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "Cannot save the configuration.", err)
			return
		}
		flash(w, r, in, msg, anchor)
	}
	switch action {
	case "settings":
		cfg.Name = limit(strings.TrimSpace(r.FormValue("name")), 100)
		if cfg.Name == "" {
			cfg.Name = "Test SP"
		}
		cfg.SignAuthnRequests = r.FormValue("sign_requests") != ""
		cfg.PublishEncryptionKey = r.FormValue("encryption_key") != ""
		cfg.AllowUnsolicited = r.FormValue("allow_unsolicited") != ""
		cfg.AllowSHA1 = r.FormValue("allow_sha1") != ""
		cfg.AllowUnsignedCBC = r.FormValue("allow_unsigned_cbc") != ""
		cfg.Binding = oneOf(r.FormValue("binding"), "", "redirect", "post", "simplesign")
		cfg.NameIDFormat = ""
		for _, f := range nameIDFormats {
			if string(f) == r.FormValue("nameid_format") {
				cfg.NameIDFormat = string(f)
			}
		}
		save("Settings saved.", "settings")

	case "idp-set", "idp-refresh":
		var data []byte
		source := strings.TrimSpace(r.FormValue("metadata_url"))
		if action == "idp-refresh" {
			source = cfg.IdPMetadataSource
		}
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
			md, err = samlsp.ParseMetadata(data)
		}
		if err != nil {
			flash(w, r, in, "Cannot use that identity provider: "+err.Error(), "idp")
			return
		}
		cfg.IdPMetadata, cfg.IdPMetadataSource, cfg.IdPEntityID = string(data), source, md.EntityID
		save("Identity provider "+md.EntityID+" saved.", "idp")

	default:
		http.NotFound(w, r)
	}
}
