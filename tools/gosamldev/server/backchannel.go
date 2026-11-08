package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/crewjam/saml/tools/gosamldev/inspect"
	"github.com/crewjam/saml/tools/gosamldev/store"
	"github.com/crewjam/saml/x/samlsp/artifact"
)

// localTransport sends requests for this server's own URLs to the server
// in-process, and others to next. The test IdPs and SPs talk to each other
// server to server, to resolve artifacts and for SOAP logout, and this
// keeps those requests off the network: the server need not reach its own
// public address, and the public-only dialer of next still guards every
// request that leaves it.
type localTransport struct {
	s    *Server
	base *url.URL
	next http.RoundTripper
}

func (t *localTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != t.base.Scheme || req.URL.Host != t.base.Host {
		return t.next.RoundTrip(req)
	}
	in := req.Clone(req.Context())
	in.RequestURI = req.URL.RequestURI()
	in.RemoteAddr = "127.0.0.1:0"
	if in.Body == nil {
		in.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	t.s.ServeHTTP(rec, in)
	return rec.Result(), nil
}

// newBackChannelClient returns the client the instances send SOAP
// messages with: ArtifactResolve and back-channel LogoutRequests. It does
// not follow redirects, as the SOAP binding has none.
func (s *Server) newBackChannelClient() *http.Client {
	base, _ := url.Parse(s.BaseURL)
	return &http.Client{
		Transport: &localTransport{s: s, base: base, next: s.fetch.Transport},
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// artifactStore is the artifact.Store (and idpartifact.Store) of one
// instance: it keeps messages in the database, and logs each one, since
// the browser carries only the artifact.
type artifactStore struct {
	s          *Server
	instanceID string
}

func (a artifactStore) Save(ctx context.Context, art string, m artifact.StoredMessage) error {
	if err := a.s.Store.SaveArtifact(ctx, a.instanceID, art, m.Recipient, m.XML, m.ExpiresAt); err != nil {
		return err
	}
	a.s.logEvent(ctx, &store.Event{InstanceID: a.instanceID, Direction: "out", OK: true,
		Title:  "Message kept for artifact resolution by " + m.Recipient,
		Detail: "Artifact: " + art + "\nResolvable until: " + m.ExpiresAt.UTC().Format(time.RFC3339),
		XML:    inspect.Pretty(m.XML)})
	return nil
}

func (a artifactStore) Take(ctx context.Context, art, recipient string) (*artifact.StoredMessage, error) {
	xml, expires, found, err := a.s.Store.TakeArtifact(ctx, a.instanceID, art, recipient)
	if err != nil || !found {
		return nil, err
	}
	return &artifact.StoredMessage{XML: xml, Recipient: recipient, ExpiresAt: expires}, nil
}

// serveSOAP serves h, a SOAP endpoint (artifact resolution or back-channel
// logout), and logs the request and the answer.
func (s *Server) serveSOAP(w http.ResponseWriter, r *http.Request, instanceID, what string, h http.Handler) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	resp := rec.Result()
	answer := rec.Body.Bytes()
	s.logEvent(r.Context(), &store.Event{InstanceID: instanceID, Direction: "in", OK: resp.StatusCode == http.StatusOK,
		Title: what + " (SOAP)", Detail: "Answered " + resp.Status, XML: inspect.Pretty(body)})
	if resp.StatusCode == http.StatusOK && len(answer) > 0 {
		s.logEvent(r.Context(), &store.Event{InstanceID: instanceID, Direction: "out", OK: true,
			Title: "Answer to " + what + " (SOAP)", XML: inspect.Pretty(answer)})
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(answer)
}
