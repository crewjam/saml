package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/tools/gosaml/inspect"
	"github.com/crewjam/saml/tools/gosaml/store"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpartifact"
	"github.com/crewjam/saml/x/samlidp/idpslo"
)

// idpRun is what an IdP's handlers work with: the instance, its
// configuration, and the x/samlidp objects built from them.
type idpRun struct {
	in        *store.Instance
	cfg       *IdPConfig
	c         *samlidp.Config
	artifacts *idpartifact.Binding
	slo       *idpslo.Service
}

// binding is the option that lets SPs ask for the HTTP-Artifact binding:
// a Response to such a request is kept, and the browser carries only an
// artifact, which the SP resolves at /idp/{id}/artifact.
func (run *idpRun) binding() samlidp.CustomBindingOption {
	return samlidp.WithCustomBinding(run.artifacts)
}

func (s *Server) idpRun(ctx context.Context, id string) (*idpRun, error) {
	in, cfg, err := s.loadIdP(ctx, id)
	if err != nil {
		return nil, err
	}
	c, err := s.samlIdP(in, cfg)
	if err != nil {
		return nil, err
	}
	logout, err := idpslo.New(c)
	if err != nil {
		return nil, err
	}
	b, err := idpartifact.New(c, artifactStore{s: s, instanceID: in.ID}, 1)
	if err != nil {
		return nil, err
	}
	b.Form = cfg.ArtifactForm
	return &idpRun{in: in, cfg: cfg, c: c, artifacts: b, slo: logout}, nil
}

// loadIdPRun is idpRun for a handler: it answers the request itself if
// the IdP cannot be loaded.
func (s *Server) loadIdPRun(w http.ResponseWriter, r *http.Request) *idpRun {
	run, err := s.idpRun(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "This IdP does not exist. Test IdPs expire "+roundDuration(s.TTL)+" after they are created.", nil)
		return nil
	case err != nil:
		s.fail(w, r, http.StatusInternalServerError, "The IdP is misconfigured.", err)
		return nil
	}
	return run
}

func (s *Server) idpSSO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	run := s.loadIdPRun(w, r)
	if run == nil {
		return
	}
	in := run.in
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "Cannot read the request.", err)
		return
	}
	reqXML := formMessageXML(r, "SAMLRequest")

	req, err := run.c.ParseAuthnRequest(ctx, r, run.binding())
	var status *saml.StatusError
	if errors.As(err, &status) && req != nil {
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", Title: "AuthnRequest from " + req.ServiceProvider + " refused with a SAML error",
			Detail: errorChain(err), XML: reqXML})
		msg, err := run.c.ErrorResponse(ctx, req, status, samlidp.WithScriptNonce(nonce(r)), run.binding())
		s.sendIdPMessage(w, r, in, msg, err)
		return
	}
	if err != nil {
		detail := errorChain(err)
		if r.Form.Get("SAMLart") != "" {
			detail += "\n\nThe test IdPs do not resolve artifacts that carry AuthnRequests: send the AuthnRequest with HTTP-Redirect or HTTP-POST."
		}
		s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", Title: "AuthnRequest refused", Detail: detail, XML: reqXML})
		s.fail(w, r, http.StatusBadRequest, "The IdP refused the login request.", errors.New(detail))
		return
	}
	s.logEvent(ctx, &store.Event{InstanceID: in.ID, Direction: "in", OK: true,
		Title: "AuthnRequest from " + req.ServiceProvider, Detail: describeAuthnRequest(req), XML: reqXML})

	// Single sign-on: answer from the browser's IdP session, if it has
	// one that satisfies the request.
	if sess, sessID := s.idpSessionFromCookie(r, run); sess != nil && !req.ForceAuthn && sess.satisfies(req) {
		if user := run.cfg.user(sess.Username); user != nil {
			s.logEvent(ctx, &store.Event{InstanceID: in.ID, OK: true, Title: "Answered from the IdP session of " + user.Username,
				Detail: "SessionIndex: " + sess.SessionIndex + "\nAuthenticated: " + sess.AuthnInstant.UTC().Format(time.RFC3339)})
			subject := buildSubject(req, user, "", sess.AuthnContext, sess.AuthnInstant, sess.SessionIndex, 0)
			s.respond(w, r, run, req, subject, sess, sessID)
			return
		}
	}

	if req.IsPassive {
		// No session to answer from, and the user may not be asked.
		msg, err := run.c.ErrorResponse(ctx, req, &saml.StatusError{TopLevel: saml.StatusResponder, SecondLevel: saml.StatusNoPassive},
			samlidp.WithScriptNonce(nonce(r)), run.binding())
		s.sendIdPMessage(w, r, in, msg, err)
		return
	}
	s.showLogin(w, r, in, run.cfg, req)
}

func (c *IdPConfig) user(username string) *User {
	for i := range c.Users {
		if c.Users[i].Username == username {
			return &c.Users[i]
		}
	}
	return nil
}

// idpLogin answers a pending AuthnRequest as the visitor chose: logged
// in as a user, or with a SAML error.
func (s *Server) idpLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	run := s.loadIdPRun(w, r)
	if run == nil {
		return
	}
	in, cfg := run.in, run.cfg
	pid := r.FormValue("pending")
	var req samlidp.AuthnRequest
	if err := s.Store.GetPending(ctx, pid, in.ID, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, "This login is no longer in progress: it was answered already, or more than an hour ago. Start again from the service provider.", nil)
		return
	}

	if r.FormValue("action") == "error" {
		label := r.FormValue("error_status")
		for _, e := range statusErrors {
			if e.Label == label {
				_ = s.Store.DeletePending(ctx, pid)
				msg, err := run.c.ErrorResponse(ctx, &req, &saml.StatusError{TopLevel: e.Top, SecondLevel: e.Second,
					Message: strings.TrimSpace(r.FormValue("status_message"))}, samlidp.WithScriptNonce(nonce(r)), run.binding())
				s.sendIdPMessage(w, r, in, msg, err)
				return
			}
		}
		s.fail(w, r, http.StatusBadRequest, "Unknown error status.", nil)
		return
	}

	user := cfg.user(r.FormValue("user"))
	if user == nil {
		s.fail(w, r, http.StatusBadRequest, "Choose a user to log in as.", nil)
		return
	}
	hours, _ := strconv.Atoi(r.FormValue("session_hours"))
	authnContext := saml.AuthnContextClass(r.FormValue("authn_context"))
	if authnContext == "" {
		authnContext = saml.AuthnContextPasswordProtectedTransport
	}
	sessionIndex := newID()
	if p := profileByKey(cfg.Profile); p.NewSessionIndex != nil {
		sessionIndex = p.NewSessionIndex()
	}
	sess := &idpSession{Username: user.Username, AuthnInstant: time.Now(), AuthnContext: authnContext, SessionIndex: sessionIndex}
	subject := buildSubject(&req, user, r.FormValue("nameid_format"), sess.AuthnContext, sess.AuthnInstant, sess.SessionIndex, hours)
	_ = s.Store.DeletePending(ctx, pid)
	// A login, as opposed to single sign-on, starts a new IdP session.
	s.respond(w, r, run, &req, subject, sess, newID())
}

// buildSubject makes what the IdP asserts about user in answer to req.
// format is the visitor's choice of NameID format: "" for the one the SP
// asks for (else the user's own), "user" for the user's own, or a format.
func buildSubject(req *samlidp.AuthnRequest, user *User, format string, authnContext saml.AuthnContextClass,
	authnInstant time.Time, sessionIndex string, sessionHours int) samlidp.Subject {
	subject := samlidp.Subject{
		NameID:               user.NameID,
		NameIDFormat:         saml.NameIDFormat(user.NameIDFormat),
		AuthnInstant:         authnInstant,
		AuthnContextClassRef: authnContext,
		SessionIndex:         sessionIndex,
		Attributes:           user.Attributes,
	}
	switch format {
	case "user":
	case "":
		// As the SP asks, if it asks for a particular format.
		if req.NameIDFormat != "" && req.NameIDFormat != saml.UnspecifiedNameIDFormat &&
			req.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted" {
			subject.NameIDFormat = req.NameIDFormat
		}
	default:
		subject.NameIDFormat = saml.NameIDFormat(format)
	}
	if subject.NameIDFormat == saml.TransientNameIDFormat {
		// A transient NameID is new at every login.
		subject.NameID = "_" + newID()
	}
	if sessionHours > 0 && sessionHours <= 720 {
		subject.SessionNotOnOrAfter = time.Now().Add(time.Duration(sessionHours) * time.Hour)
	}
	return subject
}

// respond answers req with an assertion of subject, and records the SP as
// a participant of the IdP session sess (stored under sessID), so that
// single logout reaches it.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, run *idpRun, req *samlidp.AuthnRequest,
	subject samlidp.Subject, sess *idpSession, sessID string) {
	ctx := r.Context()
	// A pairwise-id is different for each SP.
	subject.Attributes = pairwiseAttributes(subject.Attributes, run.in.ID, sess.Username, req.ServiceProvider)
	opts := []samlidp.ResponseOption{samlidp.WithScriptNonce(nonce(r)), run.binding()}
	respOpts := opts
	if o := profileByKey(run.cfg.Profile).assertionOption(); o != nil {
		respOpts = append(respOpts[:len(respOpts):len(respOpts)], o)
	}
	msg, err := run.c.Response(ctx, req, subject, respOpts...)
	var status *saml.StatusError
	if errors.As(err, &status) {
		// The SP asked for what this user cannot be asserted with: tell
		// it so, as a real IdP would.
		s.logEvent(ctx, &store.Event{InstanceID: run.in.ID, Title: "Cannot assert " + sess.Username + " as requested", Detail: errorChain(err)})
		msg, err = run.c.ErrorResponse(ctx, req, status, opts...)
	}
	if err == nil && msg.Participant != nil && run.cfg.RememberSessions {
		sess.addParticipant(*msg.Participant)
		if err := s.saveIdPSession(ctx, run.in, sessID, sess); err != nil {
			s.Logger.Error("cannot save the IdP session", "err", err)
		} else {
			s.setIdPSessionCookie(w, run.in, sessID)
		}
	}
	s.sendIdPMessage(w, r, run.in, msg, err)
}

// idpArtifact serves the IdP's ArtifactResolutionService, where SPs fetch
// the Responses sent to them with the HTTP-Artifact binding.
func (s *Server) idpArtifact(w http.ResponseWriter, r *http.Request) {
	run, err := s.idpRun(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.serveSOAP(w, r, run.in.ID, "ArtifactResolve", run.artifacts)
}

// formMessageXML returns the SAML message in the parameter param of r's
// query or form, decoded and indented, or "".
func formMessageXML(r *http.Request, param string) string {
	if v := r.Form.Get(param); v != "" {
		if b, err := inspect.DecodeBase64Message(v); err == nil {
			return inspect.Pretty(b)
		}
	}
	return ""
}

// satisfies reports whether a session can answer req without asking the
// user again: it must have been authenticated as req asks, if it asks.
func (sess *idpSession) satisfies(req *samlidp.AuthnRequest) bool {
	return len(req.AuthnContextClasses) == 0 || slices.Contains(req.AuthnContextClasses, sess.AuthnContext)
}
