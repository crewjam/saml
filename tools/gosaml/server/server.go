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
	"io"
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
	m.HandleFunc("GET /about", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "about", struct {
			MaxUsers, MaxSPs, MaxEvents int
			Lifetime                    string
		}{maxUsers, maxSPs, store.MaxEventsPerInstance, roundDuration(s.TTL)})
	})

	m.HandleFunc("POST /new/idp", s.newIDP)
	m.HandleFunc("POST /new/sp", s.newSP)
	m.HandleFunc("GET /manage/{secret}", s.manage)
	m.HandleFunc("POST /manage/{secret}/{action}", s.manageAction)
	m.HandleFunc("GET /manage/{secret}/live", s.liveLog)
	m.HandleFunc("GET /manage/{secret}/log/{id}", s.logEntry)

	m.HandleFunc("GET /idp/{id}/metadata", s.idpMetadata)
	m.HandleFunc("GET /idp/{id}/sso", s.idpSSO)
	m.HandleFunc("POST /idp/{id}/sso", s.idpSSO)
	m.HandleFunc("POST /idp/{id}/login", s.idpLogin)
	m.HandleFunc("GET /idp/{id}/certificate.pem", s.certificate(store.KindIDP))
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

	s.apiRoutes()
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
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-"+n+"' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "+
		"style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "+
		"img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	// The management pages' URLs are their only credential: never send
	// them to another site.
	h.Set("Referrer-Policy", "same-origin")
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		h.Set("Cache-Control", "no-store")
	}
	if r.Method == http.MethodPost && r.Header.Get("HX-Request") == "true" {
		// A boosted form post that is answered with a page, not
		// seeOther, must not put its URL in the history: reloading it
		// would GET a POST-only route.
		h.Set("HX-Push-Url", "false")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	r = r.WithContext(context.WithValue(r.Context(), nonceKey, n))
	if protocolPath.MatchString(r.URL.Path) {
		s.recordExchange(w, r, s.mux)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// page is what every template is given.
type page struct {
	Nonce   string
	BaseURL string
	TTL     time.Duration
	Title   string
	Data    any

	// Nav is the current item of the header's navigation, and NavIDP and
	// NavSP where its IdP and SP items go: the newest instance of that
	// kind made in this browser, or the create blocks of the home page.
	Nav    string
	NavIDP string
	NavSP  string
}

// navItems maps a template to the navigation item it is under.
var navItems = map[string]string{
	"home": "home", "inspect": "inspect", "about": "about", "api": "api",
	"idp_manage": "idp", "idp_session": "idp", "idp_logout": "idp",
	"sp_manage": "sp", "sp_session": "sp", "sp_logout": "sp", "sp_result": "sp",
}

var funcs = template.FuncMap{
	"since": func(t time.Time) string {
		return roundDuration(time.Since(t)) + " ago"
	},
	"until": func(t time.Time) string {
		return roundDuration(time.Until(t))
	},
	"clock": func(t time.Time) string { return t.UTC().Format("15:04:05 UTC") },
	// rel says how far a time is from now, for a time's tooltip.
	"rel": func(t time.Time) string {
		if d := time.Until(t); d > 0 {
			return "in " + roundDuration(d)
		}
		return roundDuration(time.Since(t)) + " ago"
	},
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
	p := page{
		Nonce: nonce(r), BaseURL: s.BaseURL, TTL: s.TTL, Title: title, Data: data,
		Nav: navItems[name], NavIDP: "/#create", NavSP: "/#create",
	}
	if name == "logentry" {
		if le, ok := data.(*logEntryPage); ok {
			p.Nav = string(le.Kind)
		}
	}
	for _, m := range s.myInstances(r) { // newest first
		if m.Kind == store.KindIDP && p.NavIDP == "/#create" {
			p.NavIDP = "/manage/" + m.Secret
		}
		if m.Kind == store.KindSP && p.NavSP == "/#create" {
			p.NavSP = "/manage/" + m.Secret
		}
	}
	if err := t.ExecuteTemplate(&buf, "layout.html", p); err != nil {
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
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set when served over https
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
		case store.KindIDP:
			if cfg, err := decodeIDPConfig(in.Config); err == nil {
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

// homePage is the data of the home page.
type homePage struct {
	Mine []myInstance
	// Log is the latest events of this browser's instances, newest
	// first, each linking to its log entry.
	Log []logRow
	// Lifetime is how long an instance lives, in words.
	Lifetime string
}

// homeLogRows is how many events the home page's Logs shows.
const homeLogRows = 20

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := homePage{Mine: s.myInstances(r), Lifetime: roundDuration(s.TTL)}
	byID := map[string]*store.Instance{}
	for _, secret := range mine(r) {
		if in, err := s.Store.InstanceBySecret(ctx, secret); err == nil {
			byID[in.ID] = in
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	if events, err := s.Store.RecentEvents(ctx, ids, homeLogRows); err == nil {
		n := s.names(ctx)
		for _, e := range events {
			if in := byID[e.InstanceID]; in != nil {
				row := n.row(in, e)
				row.Instance = n.of(string(in.Kind), in.ID)
				p.Log = append(p.Log, row)
			}
		}
	}
	s.render(w, r, "home", p)
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

// errTooManyInstances is returned by newInstance when MaxInstances exist.
var errTooManyInstances = errors.New("too many instances")

// newInstance stores a new instance with a fresh key pair, and the
// configuration config makes given the instance's ID.
func (s *Server) newInstance(ctx context.Context, kind store.Kind, config func(id string) any) (*store.Instance, error) {
	n, err := s.Store.CountInstances(ctx)
	if err != nil {
		return nil, err
	}
	if n >= s.MaxInstances {
		return nil, errTooManyInstances
	}
	// Names are memorable words (see names.go), so a new one may be taken:
	// try again with another.
	for attempt := 0; ; attempt++ {
		id, secret := newInstanceID(attempt), newInstanceSecret(attempt)
		keyPEM, certPEM, err := newKeyPair(s.BaseURL+"/"+string(kind)+"/"+id, s.TTL+24*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("cannot create a key: %w", err)
		}
		b, err := encodeConfig(config(id))
		if err != nil {
			return nil, err
		}
		now := time.Now()
		in := &store.Instance{
			ID: id, Secret: secret, Kind: kind, KeyPEM: keyPEM, CertPEM: certPEM,
			Config: b, CreatedAt: now, ExpiresAt: now.Add(s.TTL),
		}
		err = s.Store.CreateInstance(ctx, in)
		if errors.Is(err, store.ErrTaken) && attempt < 10 {
			continue
		}
		if err != nil {
			return nil, err
		}
		return in, nil
	}
}

// tooManyMessage says why an instance cannot be created.
func (s *Server) tooManyMessage() string {
	return "Too many instances exist right now. Try again later: they expire after " + roundDuration(s.TTL) + "."
}

// createInstance creates an instance from a form post, remembers it in
// this browser, and sends the browser to its management page.
func (s *Server) createInstance(w http.ResponseWriter, r *http.Request, kind store.Kind, config func(id string) any) {
	in, err := s.newInstance(r.Context(), kind, config)
	if errors.Is(err, errTooManyInstances) {
		s.fail(w, r, http.StatusServiceUnavailable, s.tooManyMessage(), nil)
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot create the instance.", err)
		return
	}
	s.setMine(w, append(mine(r), in.Secret))
	seeOther(w, r, "/manage/"+in.Secret)
}

func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	in, err := s.Store.InstanceBySecret(r.Context(), r.PathValue("secret"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This instance does not exist. Instances are deleted "+roundDuration(s.TTL)+" after they are created.", nil)
		return
	}
	switch in.Kind {
	case store.KindIDP:
		s.manageIDP(w, r, in)
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
		seeOther(w, r, "/")
		return
	case "clear-events":
		if err := s.Store.ClearEvents(r.Context(), in.ID); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "Cannot clear the log.", err)
			return
		}
		s.hub.publish(store.Event{InstanceID: in.ID, ID: clearedEvent})
		if r.Header.Get("HX-Request") == "true" {
			// The Clear button posts with htmx and swaps nothing but
			// this empty list, out of band, so the page stays put.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, clearedLogList) //nolint:errcheck // nothing to do
			return
		}
		seeOther(w, r, "/manage/"+in.Secret+"#log")
		return
	}
	switch in.Kind {
	case store.KindIDP:
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
	seeOther(w, r, target)
}

// seeOther sends the browser to one of this site's pages after a form
// post. A post made by htmx (the forms are boosted) is answered with
// HX-Location instead of a redirect, because a redirect followed by
// XMLHttpRequest loses the target's #fragment, which many of these
// carry to bring the changed section into view.
func seeOther(w http.ResponseWriter, r *http.Request, target string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Location", target)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther) //nolint:gosec // G710: targets are paths this server builds
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
		_, _ = w.Write([]byte(in.CertPEM)) //nolint:gosec // G705: a PEM certificate served as a download, not HTML
	}
}

func (s *Server) logEvent(ctx context.Context, e *store.Event) {
	if err := s.Store.AddEvent(ctx, e); err != nil {
		s.Logger.Error("cannot record event", "instance", e.InstanceID, "err", err)
		return
	}
	noteEvent(ctx, e)
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
	_, _ = w.Write(b) //nolint:gosec // G705: embedded static files
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
