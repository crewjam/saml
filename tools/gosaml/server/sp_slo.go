package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/tools/gosaml/inspect"
	"github.com/crewjam/saml/tools/gosaml/store"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/artifact"
	"github.com/crewjam/saml/x/samlsp/slo"
)

// spSessionLifetime is how long an SP session lasts, unless the IdP's
// SessionNotOnOrAfter says sooner.
const spSessionLifetime = 8 * time.Hour

// spSession is a user's session at a test SP: what the IdP asserted, and
// what single logout needs to name it.
type spSession struct {
	Subject        string
	NameID         saml.NameID
	SessionIndexes []string
	Issuer         string
	AuthnInstant   time.Time
	Attributes     samlsp.Attributes
}

// spSessionView is a session as the pages show it.
type spSessionView struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	spSession
}

func spCookieName(in *store.Instance) string { return "gosaml_sp_" + in.ID }

func (s *Server) startSPSession(w http.ResponseWriter, r *http.Request, in *store.Instance, a *samlsp.Assertion) error {
	sess := spSession{
		Subject: a.Subject, NameID: a.NameID, SessionIndexes: a.SessionIndexes, Issuer: a.Issuer,
		AuthnInstant: a.AuthnInstant, Attributes: a.Attributes,
	}
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	expires := time.Now().Add(spSessionLifetime)
	if !a.SessionNotOnOrAfter.IsZero() && a.SessionNotOnOrAfter.Before(expires) {
		expires = a.SessionNotOnOrAfter
	}
	if expires.After(in.ExpiresAt) {
		expires = in.ExpiresAt
	}
	id := newID()
	if err := s.Store.PutSession(r.Context(), &store.Session{ID: id, InstanceID: in.ID, Data: b, ExpiresAt: expires}); err != nil {
		return err
	}
	// Replace the browser's previous session here, if any.
	if c, err := r.Cookie(spCookieName(in)); err == nil {
		_ = s.Store.DeleteSession(r.Context(), c.Value, in.ID)
	}
	http.SetCookie(w, &http.Cookie{
		Name: spCookieName(in), Value: id, Path: "/", Expires: expires,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(s.BaseURL, "https://"),
	})
	return nil
}

func (s *Server) clearSPSessionCookie(w http.ResponseWriter, in *store.Instance) {
	http.SetCookie(w, &http.Cookie{
		Name: spCookieName(in), Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: strings.HasPrefix(s.BaseURL, "https://"),
	})
}

func (s *Server) loadSPSession(ctx context.Context, in *store.Instance, id string) (*spSessionView, error) {
	row, err := s.Store.GetSession(ctx, id, in.ID)
	if err != nil {
		return nil, err
	}
	v := &spSessionView{ID: row.ID, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt}
	return v, json.Unmarshal(row.Data, &v.spSession)
}

func (s *Server) spSessionFromCookie(r *http.Request, in *store.Instance) *spSessionView {
	c, err := r.Cookie(spCookieName(in))
	if err != nil {
		return nil
	}
	v, err := s.loadSPSession(r.Context(), in, c.Value)
	if err != nil {
		return nil
	}
	return v
}

func (s *Server) spSessionViews(ctx context.Context, in *store.Instance) ([]spSessionView, error) {
	rows, err := s.Store.Sessions(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	var out []spSessionView
	for _, row := range rows {
		v := spSessionView{ID: row.ID, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt}
		if json.Unmarshal(row.Data, &v.spSession) == nil {
			out = append(out, v)
		}
	}
	return out, nil
}

// spSessionPage is the SP's "application": it shows whether the browser
// is logged in, as whom, and offers to log in or out.
func (s *Server) spSessionPage(w http.ResponseWriter, r *http.Request) {
	in, cfg, err := s.loadSP(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This SP does not exist. Test SPs expire "+roundDuration(s.TTL)+" after they are created.", nil)
		return
	}
	s.renderStatus(w, r, http.StatusOK, "sp_session", cfg.Name, struct {
		InstanceID string
		Name       string
		Session    *spSessionView
		ManageURL  string
	}{in.ID, cfg.Name, s.spSessionFromCookie(r, in), s.manageURLFor(r, in)})
}

// manageURLFor returns the management URL of in if this browser created
// it, or "": others who use the instance must not learn it.
func (s *Server) manageURLFor(r *http.Request, in *store.Instance) string {
	if slices.Contains(mine(r), in.Secret) {
		return "/manage/" + in.Secret
	}
	return ""
}

// spLogoutButton logs the browser's session out: with single logout
// through the IdP, or of this SP only.
func (s *Server) spLogoutButton(w http.ResponseWriter, r *http.Request) {
	in, cfg, err := s.loadSP(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This SP does not exist or has expired.", nil)
		return
	}
	sess := s.spSessionFromCookie(r, in)
	if sess == nil {
		s.fail(w, r, http.StatusBadRequest, "This browser is not logged in to this SP.", nil)
		return
	}
	s.startSPLogout(w, r, in, cfg, sess, r.FormValue("mode") == "local")
}

// spLogoutPage is the data of the page that says how a logout went.
type spLogoutPage struct {
	InstanceID string
	Name       string
	Subject    string
	OK         bool
	Message    string
	Detail     string
	ManageURL  string
}

func (s *Server) startSPLogout(w http.ResponseWriter, r *http.Request, in *store.Instance, cfg *SPConfig, sess *spSessionView, localOnly bool) {
	ctx := r.Context()
	// End the local session first, so that the user is logged out of
	// this SP even if the IdP never answers.
	if err := s.Store.DeleteSession(ctx, sess.ID, in.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot end the session.", err)
		return
	}
	if c, err := r.Cookie(spCookieName(in)); err == nil && c.Value == sess.ID {
		s.clearSPSessionCookie(w, in)
	}
	page := spLogoutPage{InstanceID: in.ID, Name: cfg.Name, Subject: sess.Subject, ManageURL: s.manageURLFor(r, in)}
	if localOnly {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, OK: true, Title: "Local logout of " + sess.Subject, Detail: "The IdP session, if any, is left as it is."})
		page.OK, page.Message = true, "Logged out of this SP only. Your session at the IdP, and at other SPs, is left as it is."
		s.renderStatus(w, r, http.StatusOK, "sp_logout", cfg.Name, page)
		return
	}
	c, err := s.samlSP(in, cfg)
	var logout *slo.Service
	if err == nil {
		logout, err = slo.New(c)
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "The SP is misconfigured.", err)
		return
	}
	relayState := newID()
	msg, err := logout.Request(ctx, sess.NameID, relayState,
		slo.WithSessionIndex(sess.SessionIndexes...), slo.WithReason(saml.LogoutReasonUser), samlsp.WithScriptNonce(nonce(r)))
	if err != nil {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "out", Title: "Cannot start single logout", Detail: errorChain(err)})
		page.Message = "Logged out of this SP, but single logout could not be started."
		if errors.Is(err, samlsp.ErrNoEndpoint) {
			page.Message = "Logged out of this SP. The IdP's metadata has no single logout service, so your session there is left as it is."
		}
		page.Detail = errorChain(err)
		s.renderStatus(w, r, http.StatusOK, "sp_logout", cfg.Name, page)
		return
	}
	if err := s.Store.PutPending(ctx, relayState, in.ID, spPendingLogout{RequestID: msg.ID, Subject: sess.Subject}, 10*time.Minute); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot keep the logout in progress.", err)
		return
	}
	s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "out", OK: true, Title: "LogoutRequest to " + msg.Destination,
		Detail: "Binding: " + shortURN(msg.Binding) + "\nNameID: " + sess.NameID.Value + "\nSessionIndexes: " + strings.Join(sess.SessionIndexes, ", "),
		XML:    spMessageXML(msg, "SAMLRequest")})
	msg.Write(w)
}

// spPendingLogout is an SP-initiated logout waiting for the IdP's
// LogoutResponse, kept under its RelayState.
type spPendingLogout struct {
	RequestID string
	Subject   string
}

// spSLO is the SP's single logout service: the IdP's LogoutRequests, and
// its LogoutResponses to the SP's, arrive here.
func (s *Server) spSLO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, cfg, err := s.loadSP(ctx, r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.samlSP(in, cfg)
	var logout *slo.Service
	if err == nil {
		logout, err = slo.New(c)
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "The SP is misconfigured.", err)
		return
	}
	switch {
	case slo.IsResponse(r):
		_ = r.ParseForm()
		respXML := formMessageXML(r, "SAMLResponse")
		var p spPendingLogout
		if err := s.Store.GetPending(ctx, r.Form.Get("RelayState"), in.ID, &p); err != nil {
			s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", Title: "LogoutResponse for no logout in progress", XML: respXML})
			s.fail(w, r, http.StatusBadRequest, "No logout is in progress for this LogoutResponse: it may have been answered already, or taken more than ten minutes.", nil)
			return
		}
		_ = s.Store.DeletePending(ctx, r.Form.Get("RelayState"))
		page := spLogoutPage{InstanceID: in.ID, Name: cfg.Name, Subject: p.Subject, ManageURL: s.manageURLFor(r, in)}
		resp, err := logout.ParseResponse(ctx, r, p.RequestID)
		if err != nil {
			page.Message = "Logged out of this SP, but the IdP's LogoutResponse was refused or reports a failure."
			page.Detail = errorChain(err)
		} else {
			page.OK = true
			page.Message = "Logged out everywhere: the IdP ended its session and logged you out of its other service providers."
			page.Detail = "Status: " + describeStatus(resp.Status)
			if resp.Status.StatusCode.StatusCode != nil && resp.Status.StatusCode.StatusCode.Value == saml.StatusPartialLogout {
				page.Message = "Logged out, but only partly: the IdP could not log you out of every service provider (PartialLogout)."
			}
		}
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", OK: page.OK, Title: "LogoutResponse from the IdP", Detail: page.Detail, XML: respXML})
		s.renderStatus(w, r, http.StatusOK, "sp_logout", cfg.Name, page)

	case slo.IsRequest(r):
		handle := func(w http.ResponseWriter, r *http.Request) { s.spSLORequest(w, r, in, logout) }
		if isSOAP(r) {
			s.serveSOAP(w, r, in.ID, "LogoutRequest", http.HandlerFunc(handle))
			return
		}
		handle(w, r)

	default:
		s.fail(w, r, http.StatusBadRequest, "This is the SP's single logout service. It expects a LogoutRequest or LogoutResponse.", nil)
	}
}

// spSLORequest ends the sessions an IdP's LogoutRequest names, and
// answers it.
func (s *Server) spSLORequest(w http.ResponseWriter, r *http.Request, in *store.Instance, logout *slo.Service) {
	ctx := r.Context()
	soap := isSOAP(r)
	reqXML := ""
	if !soap {
		_ = r.ParseForm()
		reqXML = formMessageXML(r, "SAMLRequest")
	}
	req, err := logout.ParseRequest(ctx, r)
	if err != nil {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", Title: "LogoutRequest refused", Detail: errorChain(err), XML: reqXML})
		slo.WriteRequestError(w, r)
		return
	}
	sessions, err := s.spSessionViews(ctx, in)
	if err != nil {
		slo.WriteRequestError(w, r)
		return
	}
	var ended []string
	for _, sess := range sessions {
		if sess.NameID.Value != req.NameID.Value {
			continue
		}
		if len(req.SessionIndexes) > 0 && !slices.ContainsFunc(sess.SessionIndexes, func(i string) bool {
			return slices.Contains(req.SessionIndexes, i)
		}) {
			continue
		}
		_ = s.Store.DeleteSession(ctx, sess.ID, in.ID)
		ended = append(ended, sess.Subject)
	}
	if !soap {
		s.clearSPSessionCookie(w, in)
	}
	detail := "NameID: " + req.NameID.Value + "\nSessionIndexes: " + strings.Join(req.SessionIndexes, ", ") + "\nBinding: " + shortURN(req.Binding)
	if len(ended) == 0 {
		detail += "\nNo session matched."
	} else {
		detail += "\nEnded " + strings.Join(ended, ", ")
	}
	if !soap {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", OK: true, Title: "LogoutRequest from the IdP", Detail: detail, XML: reqXML})
	}
	msg, err := logout.Response(ctx, req, samlsp.WithScriptNonce(nonce(r)))
	if err != nil {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "out", Title: "Cannot answer the LogoutRequest", Detail: errorChain(err)})
		slo.WriteRequestError(w, r)
		return
	}
	if !soap {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "out", OK: true, Title: "LogoutResponse to " + msg.Destination,
			XML: spMessageXML(msg, "SAMLResponse")})
	}
	msg.Write(w)
}

// spArtifactBinding sends the SP's messages with the HTTP-Artifact
// binding: the IdP fetches them at /sp/{id}/artifact.
func (s *Server) spArtifactBinding(in *store.Instance, cfg *SPConfig, c *samlsp.Config) (*artifact.Binding, error) {
	b, err := artifact.New(c, artifactStore{s: s, instanceID: in.ID}, 1)
	if err != nil {
		return nil, err
	}
	b.Form = cfg.ArtifactForm
	return b, nil
}

// spArtifact serves the SP's ArtifactResolutionService.
func (s *Server) spArtifact(w http.ResponseWriter, r *http.Request) {
	in, cfg, err := s.loadSP(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.samlSP(in, cfg)
	if err != nil {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	b, err := s.spArtifactBinding(in, cfg, c)
	if err != nil {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	s.serveSOAP(w, r, in.ID, "ArtifactResolve", b)
}

// spMessageXML returns the SAML message a samlsp.Message carries, from
// its form fields or redirect URL, decoded and indented, or "".
func spMessageXML(msg *samlsp.Message, param string) string {
	v := msg.FormFields().Get(param)
	if u := msg.RedirectURL(); u != nil && v == "" {
		v = u.Query().Get(param)
	}
	if v == "" {
		return ""
	}
	b, err := inspect.DecodeBase64Message(v)
	if err != nil {
		return ""
	}
	return inspect.Pretty(b)
}
