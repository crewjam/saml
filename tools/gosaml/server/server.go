// Package server is the gosaml.dev web application: test identity
// providers and service providers that visitors create and configure,
// and the page that hosts the in-browser SAML inspector.
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml/tools/gosaml/store"
	"github.com/crewjam/saml/tools/gosaml/web"
)

// Config configures a Server.
type Config struct {
	// BaseURL is the URL the server is reached at, without a trailing
	// slash, such as "https://gosaml.dev". Entity IDs and endpoints are
	// made from it, so it must be what browsers and other SAML parties
	// use.
	BaseURL string

	Store *store.Store

	// TTL is how long an instance lives after it is created.
	TTL time.Duration

	// MaxInstances is the most instances that may exist at once.
	MaxInstances int

	Logger *slog.Logger
}

// Server is the web application.
type Server struct {
	Config
	mux       *http.ServeMux
	pages     map[string]*template.Template
	fetch     *http.Client
	soap      *http.Client
	hub       *hub
	cookieKey []byte
	static    *staticFiles
}

// New returns a Server.
func New(cfg Config) (*Server, error) {
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		Config:    cfg,
		mux:       http.NewServeMux(),
		fetch:     newFetchClient(),
		cookieKey: make([]byte, 32),
		hub:       newHub(),
	}
	// The key of the cookies that remember SP logins in progress. A new
	// one at each start is enough: everything else is forgotten then too.
	if _, err := rand.Read(s.cookieKey); err != nil {
		return nil, err
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	s.pages = pages
	s.static = newStaticFiles(web.Static)
	s.soap = s.newBackChannelClient()
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /{$}", s.home)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	m.Handle("GET /static/", s.static)
	m.HandleFunc("GET /inspect", s.inspectPage)
	m.HandleFunc("POST /inspect", s.inspectPage)
	m.HandleFunc("GET /about", func(w http.ResponseWriter, r *http.Request) { s.render(w, r, "about", nil) })

	m.HandleFunc("POST /new/idp", s.newIdP)
	m.HandleFunc("POST /new/sp", s.newSP)
	m.HandleFunc("GET /manage/{secret}", s.manage)
	m.HandleFunc("POST /manage/{secret}/{action}", s.manageAction)
	m.HandleFunc("GET /manage/{secret}/live", s.liveLog)

	m.HandleFunc("GET /idp/{id}/metadata", s.idpMetadata)
	m.HandleFunc("GET /idp/{id}/sso", s.idpSSO)
	m.HandleFunc("POST /idp/{id}/sso", s.idpSSO)
	m.HandleFunc("POST /idp/{id}/login", s.idpLogin)
	m.HandleFunc("GET /idp/{id}/certificate.pem", s.certificate(store.KindIdP))
	m.HandleFunc("GET /idp/{id}/slo", s.idpSLO)
	m.HandleFunc("POST /idp/{id}/slo", s.idpSLO)
	m.HandleFunc("POST /idp/{id}/artifact", s.idpArtifact)
	m.HandleFunc("GET /idp/{id}/session", s.idpSessionPage)
	m.HandleFunc("POST /idp/{id}/logout", s.idpLogoutButton)

	m.HandleFunc("GET /sp/{id}/metadata", s.spMetadata)
	m.HandleFunc("GET /sp/{id}/login", s.spLogin)
	m.HandleFunc("POST /sp/{id}/login", s.spLogin)
	m.HandleFunc("GET /sp/{id}/acs", s.spACS)
	m.HandleFunc("POST /sp/{id}/acs", s.spACS)
	m.HandleFunc("GET /sp/{id}/certificate.pem", s.certificate(store.KindSP))
	m.HandleFunc("GET /sp/{id}/{$}", s.spSessionPage)
	m.HandleFunc("POST /sp/{id}/logout", s.spLogoutButton)
	m.HandleFunc("GET /sp/{id}/slo", s.spSLO)
	m.HandleFunc("POST /sp/{id}/slo", s.spSLO)
	m.HandleFunc("POST /sp/{id}/artifact", s.spArtifact)
}

type ctxKey int

const nonceKey ctxKey = iota

func nonce(r *http.Request) string {
	n, _ := r.Context().Value(nonceKey).(string)
	return n
}

// ServeHTTP serves the application with its security headers. Pages may
// run only the server's own scripts, and the inline scripts that submit
// SAML forms, which carry the request's nonce.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := rand.Text()
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-"+n+"' 'wasm-unsafe-eval'; "+
		"style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	// The management pages' URLs are their only credential: never send
	// them to another site.
	h.Set("Referrer-Policy", "same-origin")
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		h.Set("Cache-Control", "no-store")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey, n)))
}

// page is what every template is given.
type page struct {
	Nonce   string
	BaseURL string
	TTL     time.Duration
	Title   string
	Data    any
}

var funcs = template.FuncMap{
	"since": func(t time.Time) string {
		return roundDuration(time.Since(t)) + " ago"
	},
	"until": func(t time.Time) string {
		return roundDuration(time.Until(t))
	},
	"clock": func(t time.Time) string { return t.UTC().Format("15:04:05 UTC") },
	"join":  strings.Join,
	"short": shortURN,
	"dur":   roundDuration,
	"kv":    func(k, v string) KV { return KV{k, v} },
	"oks": func(results []logoutResult) int {
		n := 0
		for _, r := range results {
			if r.OK {
				n++
			}
		}
		return n
	},
}

// KV is a label and a value, for the "copy" template.
type KV struct{ K, V string }

func roundDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d.Truncate(time.Minute)%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func shortURN(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 && strings.HasPrefix(s, "urn:") {
		return s[i+1:]
	}
	return s
}

func parsePages() (map[string]*template.Template, error) {
	layout, err := template.New("layout.html").Funcs(funcs).ParseFS(web.Templates, "templates/layout.html", "templates/partials.html")
	if err != nil {
		return nil, err
	}
	names, err := fs.Glob(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{}
	for _, name := range names {
		base := strings.TrimSuffix(path.Base(name), ".html")
		if base == "layout" || base == "partials" {
			continue
		}
		t, err := template.Must(layout.Clone()).ParseFS(web.Templates, name)
		if err != nil {
			return nil, err
		}
		pages[base] = t
	}
	return pages, nil
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	s.renderStatus(w, r, http.StatusOK, name, "", data)
}

func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, status int, name, title string, data any) {
	t, ok := s.pages[name]
	if !ok {
		http.Error(w, "no template "+name, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", page{
		Nonce: nonce(r), BaseURL: s.BaseURL, TTL: s.TTL, Title: title, Data: data,
	}); err != nil {
		s.Logger.Error("template", "name", name, "err", err)
		http.Error(w, "cannot render the page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// problem is the data of the error page.
type problem struct {
	Message string
	Detail  string
	Back    string
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	p := problem{Message: msg}
	if err != nil {
		// This is a tool for debugging SAML: it says exactly what went
		// wrong, which a production service provider would not.
		p.Detail = errorChain(err)
	}
	s.renderStatus(w, r, status, "error", "Error", p)
}

// errorChain writes an error with what it wraps, since the library's
// errors for users ("Authentication failed") hide the detail in the
// error they wrap.
func errorChain(err error) string {
	lines := []string{err.Error()}
	seen := map[string]bool{err.Error(): true}
	for e := errors.Unwrap(err); e != nil; e = errors.Unwrap(e) {
		if msg := e.Error(); !seen[msg] {
			seen[msg] = true
			lines = append(lines, "caused by: "+msg)
		}
	}
	return strings.Join(lines, "\n")
}

// The "mine" cookie remembers the management secrets of the instances
// this browser created, so that the home page can list them.
const mineCookie = "gosaml_mine"

const maxMine = 20

func mine(r *http.Request) []string {
	c, err := r.Cookie(mineCookie)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range strings.Split(c.Value, ".") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) setMine(w http.ResponseWriter, secrets []string) {
	if len(secrets) > maxMine {
		secrets = secrets[len(secrets)-maxMine:]
	}
	http.SetCookie(w, &http.Cookie{
		Name: mineCookie, Value: strings.Join(secrets, "."), Path: "/",
		MaxAge: int(s.TTL.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(s.BaseURL, "https://"),
	})
}

// myInstance is an instance listed on the home page or offered for
// pairing.
type myInstance struct {
	Kind        store.Kind
	Name        string
	Secret      string
	MetadataURL string
	ExpiresAt   time.Time
}

func (s *Server) myInstances(r *http.Request) []myInstance {
	var out []myInstance
	for _, secret := range mine(r) {
		in, err := s.Store.InstanceBySecret(r.Context(), secret)
		if err != nil {
			continue
		}
		mi := myInstance{Kind: in.Kind, Secret: secret, ExpiresAt: in.ExpiresAt}
		switch in.Kind {
		case store.KindIdP:
			if cfg, err := decodeIdPConfig(in.Config); err == nil {
				mi.Name = cfg.Name
			}
			mi.MetadataURL = s.idpEntityID(in.ID)
		case store.KindSP:
			if cfg, err := decodeSPConfig(in.Config); err == nil {
				mi.Name = cfg.Name
			}
			mi.MetadataURL = s.spEntityID(in.ID)
		}
		out = append(out, mi)
	}
	// Newest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "home", struct{ Mine []myInstance }{s.myInstances(r)})
}

// inspectPage serves the inspector. A message POSTed to it, as by an IdP
// whose ACS URL is set to this page, is put in the page for the browser
// to decode; it is not stored or decoded by the server.
func (s *Server) inspectPage(w http.ResponseWriter, r *http.Request) {
	var posted string
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			posted = r.PostForm.Encode()
		}
	}
	s.renderStatus(w, r, http.StatusOK, "inspect", "Inspector", struct{ Posted string }{posted})
}

// createInstance stores a new instance with a fresh key pair.
func (s *Server) createInstance(w http.ResponseWriter, r *http.Request, kind store.Kind, config any) {
	n, err := s.Store.CountInstances(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot create the instance.", err)
		return
	}
	if n >= s.MaxInstances {
		s.fail(w, r, http.StatusServiceUnavailable, "Too many instances exist right now. Try again later: they expire after "+roundDuration(s.TTL)+".", nil)
		return
	}
	id := strings.ToLower(rand.Text()[:16])
	secret := rand.Text()
	keyPEM, certPEM, err := newKeyPair(s.BaseURL+"/"+string(kind)+"/"+id, s.TTL+24*time.Hour)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot create a key.", err)
		return
	}
	b, err := encodeConfig(config)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot create the instance.", err)
		return
	}
	now := time.Now()
	in := &store.Instance{
		ID: id, Secret: secret, Kind: kind, KeyPEM: keyPEM, CertPEM: certPEM,
		Config: b, CreatedAt: now, ExpiresAt: now.Add(s.TTL),
	}
	if err := s.Store.CreateInstance(r.Context(), in); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot create the instance.", err)
		return
	}
	s.setMine(w, append(mine(r), secret))
	http.Redirect(w, r, "/manage/"+secret, http.StatusSeeOther)
}

func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	in, err := s.Store.InstanceBySecret(r.Context(), r.PathValue("secret"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This instance does not exist. Instances are deleted "+roundDuration(s.TTL)+" after they are created, and whenever the server restarts.", nil)
		return
	}
	switch in.Kind {
	case store.KindIdP:
		s.manageIdP(w, r, in)
	case store.KindSP:
		s.manageSP(w, r, in)
	}
}

func (s *Server) manageAction(w http.ResponseWriter, r *http.Request) {
	in, err := s.Store.InstanceBySecret(r.Context(), r.PathValue("secret"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This instance does not exist or has expired.", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "Cannot read the form.", err)
		return
	}
	action := r.PathValue("action")
	switch action {
	case "delete":
		if err := s.Store.DeleteInstance(r.Context(), in.ID); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "Cannot delete the instance.", err)
			return
		}
		var kept []string
		for _, sec := range mine(r) {
			if sec != in.Secret {
				kept = append(kept, sec)
			}
		}
		s.setMine(w, kept)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	case "clear-events":
		if err := s.Store.ClearEvents(r.Context(), in.ID); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "Cannot clear the log.", err)
			return
		}
		s.hub.publish(store.Event{InstanceID: in.ID, ID: clearedEvent})
		http.Redirect(w, r, "/manage/"+in.Secret+"#log", http.StatusSeeOther)
		return
	}
	switch in.Kind {
	case store.KindIdP:
		s.idpAction(w, r, in, action)
	case store.KindSP:
		s.spAction(w, r, in, action)
	}
}

// flash redirects back to the management page with a message.
func flash(w http.ResponseWriter, r *http.Request, in *store.Instance, msg, anchor string) {
	target := "/manage/" + in.Secret
	if msg != "" {
		target += "?msg=" + base64.RawURLEncoding.EncodeToString([]byte(msg))
	}
	if anchor != "" {
		target += "#" + anchor
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func flashMessage(r *http.Request) string {
	b, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("msg"))
	if err != nil || len(b) > 2000 {
		return ""
	}
	return string(b)
}

func (s *Server) certificate(kind store.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		in, err := s.Store.Instance(r.Context(), kind, r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="`+string(kind)+"-"+in.ID+`.pem"`)
		_, _ = w.Write([]byte(in.CertPEM))
	}
}

func (s *Server) logEvent(ctx context.Context, e *store.Event) {
	if err := s.Store.AddEvent(ctx, e); err != nil {
		s.Logger.Error("cannot record event", "instance", e.InstanceID, "err", err)
		return
	}
	s.hub.publish(*e)
}

// staticFiles serves the embedded static files, gzipped when the browser
// accepts it. The WebAssembly inspector is large and compresses well.
type staticFiles struct {
	fs   fs.FS
	mu   sync.Mutex
	gzip map[string][]byte
}

func newStaticFiles(fsys fs.FS) *staticFiles {
	return &staticFiles{fs: fsys, gzip: map[string][]byte{}}
}

func (sf *staticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	b, err := fs.ReadFile(sf.fs, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	switch path.Ext(name) {
	case ".wasm":
		h.Set("Content-Type", "application/wasm")
	case ".js":
		h.Set("Content-Type", "text/javascript; charset=utf-8")
	case ".css":
		h.Set("Content-Type", "text/css; charset=utf-8")
	case ".svg":
		h.Set("Content-Type", "image/svg+xml")
	}
	// The files change only with a deploy, which restarts the server.
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("Vary", "Accept-Encoding")
	if len(b) > 1024 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		_, _ = w.Write(sf.gzipped(name, b))
		return
	}
	_, _ = w.Write(b)
}

func (sf *staticFiles) gzipped(name string, b []byte) []byte {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	if z, ok := sf.gzip[name]; ok {
		return z
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(b)
	_ = zw.Close()
	sf.gzip[name] = buf.Bytes()
	return buf.Bytes()
}
