package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/tools/gosaml/inspect"
	"github.com/crewjam/saml/tools/gosaml/store"
	"github.com/crewjam/saml/x/samlidp/idpslo"
)

// idpSessionLifetime is how long an IdP session lasts.
const idpSessionLifetime = 8 * time.Hour

// idpSession is a user's session at a test IdP: who logged in, how, and
// the SPs the session was used to log in to, which single logout must
// reach.
type idpSession struct {
	Username     string
	AuthnInstant time.Time
	AuthnContext saml.AuthnContextClass
	SessionIndex string
	Participants []saml.SessionParticipant
}

// addParticipant records a login to an SP, replacing an earlier one to the
// same SP.
func (sess *idpSession) addParticipant(p saml.SessionParticipant) {
	kept := sess.Participants[:0]
	for _, q := range sess.Participants {
		if q.ServiceProviderID != p.ServiceProviderID {
			kept = append(kept, q)
		}
	}
	sess.Participants = append(kept, p)
}

func idpCookieName(in *store.Instance) string { return "gosaml_idp_" + in.ID }

func (s *Server) setIdPSessionCookie(w http.ResponseWriter, in *store.Instance, id string) {
	c := &http.Cookie{
		Name: idpCookieName(in), Value: id, Path: "/",
		MaxAge: int(idpSessionLifetime.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
	if strings.HasPrefix(s.BaseURL, "https://") {
		// AuthnRequests may arrive in a cross-site POST, which carries
		// only SameSite=None cookies.
		c.Secure, c.SameSite = true, http.SameSiteNoneMode
	}
	http.SetCookie(w, c)
}

func (s *Server) clearIdPSessionCookie(w http.ResponseWriter, in *store.Instance) {
	http.SetCookie(w, &http.Cookie{
		Name: idpCookieName(in), Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: strings.HasPrefix(s.BaseURL, "https://"),
	})
}

func (s *Server) saveIdPSession(ctx context.Context, in *store.Instance, id string, sess *idpSession) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	expires := time.Now().Add(idpSessionLifetime)
	if expires.After(in.ExpiresAt) {
		expires = in.ExpiresAt
	}
	return s.Store.PutSession(ctx, &store.Session{ID: id, InstanceID: in.ID, Data: b, ExpiresAt: expires})
}

func (s *Server) loadIdPSession(ctx context.Context, in *store.Instance, id string) (*idpSession, error) {
	row, err := s.Store.GetSession(ctx, id, in.ID)
	if err != nil {
		return nil, err
	}
	var sess idpSession
	return &sess, json.Unmarshal(row.Data, &sess)
}

// idpSessionFromCookie returns the browser's session at this IdP, if it
// has one.
func (s *Server) idpSessionFromCookie(r *http.Request, run *idpRun) (*idpSession, string) {
	if !run.cfg.RememberSessions {
		return nil, ""
	}
	c, err := r.Cookie(idpCookieName(run.in))
	if err != nil {
		return nil, ""
	}
	sess, err := s.loadIdPSession(r.Context(), run.in, c.Value)
	if err != nil {
		return nil, ""
	}
	return sess, c.Value
}

// idpSessionView is a session as the management page shows it.
type idpSessionView struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	idpSession
}

func (s *Server) idpSessionViews(ctx context.Context, in *store.Instance) ([]idpSessionView, error) {
	rows, err := s.Store.Sessions(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	var out []idpSessionView
	for _, row := range rows {
		v := idpSessionView{ID: row.ID, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt}
		if json.Unmarshal(row.Data, &v.idpSession) == nil {
			out = append(out, v)
		}
	}
	return out, nil
}

// idpSessionPage shows the browser its session at the IdP, as an IdP's
// own "my account" page would, with a button to log out everywhere.
func (s *Server) idpSessionPage(w http.ResponseWriter, r *http.Request) {
	run := s.loadIdPRun(w, r)
	if run == nil {
		return
	}
	sess, _ := s.idpSessionFromCookie(r, run)
	s.renderStatus(w, r, http.StatusOK, "idp_session", run.cfg.Name, struct {
		InstanceID string
		Name       string
		Session    *idpSession
		Remember   bool
	}{run.in.ID, run.cfg.Name, sess, run.cfg.RememberSessions})
}

// idpLogoutButton starts IdP-initiated logout of the browser's session.
func (s *Server) idpLogoutButton(w http.ResponseWriter, r *http.Request) {
	run := s.loadIdPRun(w, r)
	if run == nil {
		return
	}
	_, id := s.idpSessionFromCookie(r, run)
	if id == "" {
		s.fail(w, r, http.StatusBadRequest, "This browser has no session at this IdP.", nil)
		return
	}
	s.startIdPLogout(w, r, run, id)
}

// logoutState is a single logout in progress at an IdP: it logs the user
// out of the session's participants one at a time, through the browser,
// and keeps this between them.
type logoutState struct {
	ID string
	// Request is the LogoutRequest of the SP that started the logout, to
	// answer once the others are logged out; nil for a logout the IdP
	// started.
	Request          *idpslo.Request
	Username         string
	Remaining        []saml.SessionParticipant
	Current          *saml.SessionParticipant
	CurrentRequestID string
	Results          []logoutResult
}

// logoutResult is how logging out of one SP went.
type logoutResult struct {
	ServiceProvider string
	How             string
	OK              bool
	Detail          string
}

// startIdPLogout ends the IdP session id and logs its user out of every
// SP it was used for.
func (s *Server) startIdPLogout(w http.ResponseWriter, r *http.Request, run *idpRun, id string) {
	ctx := r.Context()
	sess, err := s.loadIdPSession(ctx, run.in, id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "That session has ended.", nil)
		return
	}
	if err := s.Store.DeleteSession(ctx, id, run.in.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot end the session.", err)
		return
	}
	if c, err := r.Cookie(idpCookieName(run.in)); err == nil && c.Value == id {
		s.clearIdPSessionCookie(w, run.in)
	}
	s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, OK: true, Title: "IdP-initiated logout of " + sess.Username,
		Detail: participantList(sess.Participants)})
	s.continueLogout(w, r, run, &logoutState{ID: newID(), Username: sess.Username, Remaining: sess.Participants})
}

func participantList(ps []saml.SessionParticipant) string {
	if len(ps) == 0 {
		return "No service providers to log out of."
	}
	var lines []string
	for _, p := range ps {
		lines = append(lines, "Participant: "+p.ServiceProviderID+" (NameID "+p.NameID.Value+")")
	}
	return strings.Join(lines, "\n")
}

// idpSLO is the IdP's single logout service: SPs' LogoutRequests, and
// their LogoutResponses to the IdP's, arrive here.
func (s *Server) idpSLO(w http.ResponseWriter, r *http.Request) {
	run, err := s.idpRun(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case idpslo.IsResponse(r):
		s.idpSLOResponse(w, r, run)
	case idpslo.IsRequest(r):
		if isSOAP(r) {
			s.serveSOAP(w, r, run.in.ID, "LogoutRequest", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s.idpSLORequest(w, r, run)
			}))
			return
		}
		s.idpSLORequest(w, r, run)
	default:
		s.fail(w, r, http.StatusBadRequest, "This is the IdP's single logout service. It expects a LogoutRequest or LogoutResponse.", nil)
	}
}

func isSOAP(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "xml")
}

func (s *Server) idpSLORequest(w http.ResponseWriter, r *http.Request, run *idpRun) {
	ctx := r.Context()
	soap := isSOAP(r)
	reqXML := ""
	if !soap {
		_ = r.ParseForm()
		reqXML = formMessageXML(r, "SAMLRequest")
	}
	req, err := run.slo.ParseRequest(ctx, r)
	if err != nil {
		s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "in", Title: "LogoutRequest refused", Detail: errorChain(err), XML: reqXML})
		idpslo.WriteRequestError(w, r)
		return
	}
	if !soap {
		s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "in", OK: true, Title: "LogoutRequest from " + req.ServiceProvider,
			Detail: "NameID: " + req.NameID.Value + "\nSessionIndexes: " + strings.Join(req.SessionIndexes, ", ") + "\nBinding: " + shortURN(req.Binding),
			XML:    reqXML})
	}

	// End every IdP session the request names, and log the user out of
	// the other SPs those sessions were used for.
	rows, err := s.Store.Sessions(ctx, run.in.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the sessions.", err)
		return
	}
	st := &logoutState{ID: newID(), Request: req}
	ended := 0
	for _, row := range rows {
		var sess idpSession
		if json.Unmarshal(row.Data, &sess) != nil {
			continue
		}
		matched := false
		for _, p := range sess.Participants {
			if req.Matches(p) {
				matched = true
			}
		}
		if !matched {
			continue
		}
		ended++
		st.Username = sess.Username
		for _, p := range sess.Participants {
			if !req.Matches(p) {
				st.Remaining = append(st.Remaining, p)
			}
		}
		_ = s.Store.DeleteSession(ctx, row.ID, run.in.ID)
	}
	if !soap {
		s.clearIdPSessionCookie(w, run.in)
	}
	detail := "Ended no IdP session: none was used for this SP with that NameID and SessionIndex."
	if ended > 0 {
		detail = "Ended the IdP session of " + st.Username + ".\n" + participantList(st.Remaining)
	}
	s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, OK: ended > 0, Title: "Single logout started by " + req.ServiceProvider, Detail: detail})
	s.continueLogout(w, r, run, st)
}

func (s *Server) idpSLOResponse(w http.ResponseWriter, r *http.Request, run *idpRun) {
	ctx := r.Context()
	_ = r.ParseForm()
	respXML := formMessageXML(r, "SAMLResponse")
	var st logoutState
	if err := s.Store.GetPending(ctx, r.Form.Get("RelayState"), run.in.ID, &st); err != nil || st.Current == nil {
		s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "in", Title: "LogoutResponse for no logout in progress", XML: respXML})
		s.fail(w, r, http.StatusBadRequest, "No logout is in progress for this LogoutResponse: it may have been answered already, or taken more than ten minutes.", nil)
		return
	}
	res := logoutResult{ServiceProvider: st.Current.ServiceProviderID, How: "front-channel (browser)"}
	resp, err := run.slo.ParseResponse(ctx, r, st.Current.ServiceProviderID, st.CurrentRequestID)
	if err != nil {
		res.Detail = errorChain(err)
	} else {
		res.OK = true
		res.Detail = describeStatus(resp.Status)
	}
	s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "in", OK: res.OK, Title: "LogoutResponse from " + res.ServiceProvider, Detail: res.Detail, XML: respXML})
	st.Results = append(st.Results, res)
	st.Current, st.CurrentRequestID = nil, ""
	s.continueLogout(w, r, run, &st)
}

func describeStatus(st saml.Status) string {
	out := shortURN(st.StatusCode.Value)
	if st.StatusCode.StatusCode != nil {
		out += " / " + shortURN(st.StatusCode.StatusCode.Value)
	}
	if st.StatusMessage != nil && st.StatusMessage.Value != "" {
		out += ": " + st.StatusMessage.Value
	}
	return out
}

// continueLogout logs the user out of the next participant, or, when
// none is left, finishes: it answers the SP that started the logout, or
// shows the result.
func (s *Server) continueLogout(w http.ResponseWriter, r *http.Request, run *idpRun, st *logoutState) {
	ctx := r.Context()
	soapOnly := st.Request != nil && st.Request.Binding == saml.SOAPBinding
	for len(st.Remaining) > 0 {
		p := st.Remaining[0]
		st.Remaining = st.Remaining[1:]
		if run.cfg.BackChannelLogout || soapOnly {
			resp, err := run.slo.SendRequest(ctx, p)
			if err == nil || !errors.Is(err, idpslo.ErrNoEndpoint) || soapOnly {
				res := logoutResult{ServiceProvider: p.ServiceProviderID, How: "back-channel (SOAP)", OK: err == nil}
				if err != nil {
					res.Detail = errorChain(err)
					if soapOnly && errors.Is(err, idpslo.ErrNoEndpoint) {
						res.Detail = "The logout came without the browser, and this SP has no SOAP single logout service."
					}
				} else {
					res.Detail = describeStatus(resp.Status)
				}
				s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "out", OK: res.OK, Title: "Back-channel LogoutRequest to " + p.ServiceProviderID, Detail: res.Detail})
				st.Results = append(st.Results, res)
				continue
			}
			// No SOAP endpoint: try through the browser.
		}
		msg, err := run.slo.Request(ctx, p, st.ID, idpslo.WithScriptNonce(nonce(r)))
		if err != nil {
			res := logoutResult{ServiceProvider: p.ServiceProviderID, How: "front-channel (browser)", Detail: errorChain(err)}
			if errors.Is(err, idpslo.ErrNoEndpoint) {
				res.Detail = "This SP's metadata has no single logout service, so it cannot be logged out."
			}
			s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "out", Title: "Cannot log out of " + p.ServiceProviderID, Detail: res.Detail})
			st.Results = append(st.Results, res)
			continue
		}
		st.Current, st.CurrentRequestID = &p, msg.ID
		if err := s.Store.PutPending(ctx, st.ID, run.in.ID, st, 10*time.Minute); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "Cannot keep the logout in progress.", err)
			return
		}
		s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "out", OK: true, Title: "LogoutRequest to " + msg.Destination,
			Detail: "Binding: " + shortURN(msg.Binding) + "\nNameID: " + p.NameID.Value + "\nSessionIndex: " + p.SessionIndex,
			XML:    idpMessageXML(msg.FormValues(), msg.RedirectURL(), "SAMLRequest")})
		msg.Write(w)
		return
	}

	_ = s.Store.DeletePending(ctx, st.ID)
	partial := false
	for _, res := range st.Results {
		if !res.OK {
			partial = true
		}
	}
	if st.Request != nil {
		opts := []idpslo.ResponseOption{idpslo.WithResponseScriptNonce(nonce(r))}
		if partial {
			opts = append(opts, idpslo.PartialLogout)
		}
		msg, err := run.slo.Response(ctx, st.Request, opts...)
		if err != nil {
			s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "out", Title: "Cannot answer the LogoutRequest of " + st.Request.ServiceProvider, Detail: errorChain(err)})
			if soapOnly {
				idpslo.WriteRequestError(w, r)
				return
			}
			s.fail(w, r, http.StatusInternalServerError, "The IdP cannot answer the LogoutRequest.", err)
			return
		}
		title := "LogoutResponse to " + st.Request.ServiceProvider
		if partial {
			title += " (PartialLogout)"
		}
		if !soapOnly {
			s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Direction: "out", OK: !partial, Title: title,
				XML: idpMessageXML(msg.FormValues(), msg.RedirectURL(), "SAMLResponse")})
		}
		msg.Write(w)
		return
	}
	s.renderStatus(w, r, http.StatusOK, "idp_logout", run.cfg.Name, struct {
		Name     string
		Username string
		Results  []logoutResult
		Partial  bool
	}{run.cfg.Name, st.Username, st.Results, partial})
}

// idpMessageXML returns the SAML message a samlidp.Message carries, from
// its form values or redirect URL, decoded and indented, or "".
func idpMessageXML(form map[string]string, redirect *url.URL, param string) string {
	v := form[param]
	if v == "" && redirect != nil {
		v = redirect.Query().Get(param)
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
