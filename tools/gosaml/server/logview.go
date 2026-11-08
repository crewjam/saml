package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"html/template"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml/tools/gosaml/inspect"
	"github.com/crewjam/saml/tools/gosaml/store"
)

// logRow is one event as the Log shows it: a link to its log entry, with
// a short title and a detail line.
type logRow struct {
	ID    int64
	Href  string
	At    time.Time
	Title string
	// Dir is "in", "out" or "local", and DirClass the colour of the
	// counterparty: "idp" on an SP's log, "sp" on an IdP's, "local".
	Dir      string
	DirClass string
	Parts    []logPart
	OK       bool
	// Instance names the event's instance, for the home page's feed.
	Instance     string
	InstanceKind store.Kind
}

// logPart is a piece of a log row's detail line; paths, URLs and other
// technical values are set in monospace.
type logPart struct {
	Text string
	Mono bool
}

// names finds the names of this server's instances from their URLs, so
// that titles say "Test SP" rather than a long URL. It caches what it
// looks up for the life of one request.
type names struct {
	s     *Server
	ctx   context.Context
	cache map[string]string
}

func (s *Server) names(ctx context.Context) *names {
	return &names{s: s, ctx: ctx, cache: map[string]string{}}
}

func (n *names) of(kind, id string) string {
	key := kind + "/" + id
	if name, ok := n.cache[key]; ok {
		return name
	}
	name := ""
	switch kind {
	case "idp":
		if _, cfg, err := n.s.loadIdP(n.ctx, id); err == nil {
			name = cfg.Name
		}
	case "sp":
		if _, cfg, err := n.s.loadSP(n.ctx, id); err == nil {
			name = cfg.Name
		}
	}
	n.cache[key] = name
	return name
}

var ownURL = regexp.MustCompile(`https?://\S+?/(idp|sp)/([a-z0-9-]+)(/\S*)?`)

// title replaces the URLs of this server's instances in a title with
// their names.
func (n *names) title(t string) string {
	return ownURL.ReplaceAllStringFunc(t, func(u string) string {
		if !strings.HasPrefix(u, n.s.BaseURL+"/") {
			return u
		}
		m := ownURL.FindStringSubmatch(u)
		if name := n.of(m[1], m[2]); name != "" {
			return name
		}
		return u
	})
}

// short shortens a URL of this server to its path, after an ellipsis.
func (n *names) short(v string) string {
	if strings.HasPrefix(v, n.s.BaseURL+"/") {
		return "…" + strings.TrimPrefix(v, n.s.BaseURL)
	}
	return v
}

// logRows makes the Log of an instance.
func (s *Server) logRows(ctx context.Context, in *store.Instance, events []store.Event) []logRow {
	n := s.names(ctx)
	rows := make([]logRow, 0, len(events))
	for _, e := range events {
		rows = append(rows, n.row(in, e))
	}
	return rows
}

func (n *names) row(in *store.Instance, e store.Event) logRow {
	r := logRow{
		ID: e.ID, Href: "/manage/" + in.Secret + "/log/" + strconv.FormatInt(e.ID, 10),
		At: e.At, Title: n.title(e.Title), Dir: e.Direction, OK: e.OK,
		InstanceKind: in.Kind,
	}
	switch {
	case e.Direction == "":
		r.Dir, r.DirClass = "local", "local"
	case in.Kind == store.KindIdP:
		r.DirClass = "sp"
	default:
		r.DirClass = "idp"
	}
	for _, line := range strings.Split(e.Detail, "\n") {
		if len(r.Parts) == 3 {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "Binding: HTTP-POST" shows as its value.
		if k, v, ok := strings.Cut(line, ": "); ok && len(k) <= 24 {
			line = v
		}
		line = n.short(line)
		if len(line) > 70 {
			line = line[:69] + "…"
		}
		r.Parts = append(r.Parts, logPart{Text: line, Mono: isTechnicalPart(line)})
	}
	return r
}

func isTechnicalPart(v string) bool {
	return strings.HasPrefix(v, "…/") || strings.HasPrefix(v, "/") || strings.Contains(v, "://") ||
		strings.HasPrefix(v, "urn:") || (strings.Contains(v, "@") && !strings.Contains(v, " ")) ||
		(!strings.Contains(v, " ") && len(v) >= 16)
}

// xmlHTML renders highlighting tokens as HTML, escaping their text.
func xmlHTML(tokens []inspect.XMLToken) template.HTML {
	var b strings.Builder
	for _, t := range tokens {
		text := template.HTMLEscapeString(t.Text)
		if t.Kind == "text" {
			b.WriteString(text)
			continue
		}
		b.WriteString(`<span class="x-` + t.Kind + `">` + text + `</span>`)
	}
	return template.HTML(b.String()) //nolint:gosec // every piece of text is escaped above
}

// endpoint is a row of the "Give these to…" sections: a URL to copy, with
// its binding.
type endpoint struct {
	Label, Binding, URL string
	// Plain says the binding is words, not binding names.
	Plain bool
}

// logData is the data of the "log" template.
type logData struct {
	Secret string
	Rows   []logRow
	Max    int
}

// certInfo describes a certificate in PEM for the "Give these" sections,
// such as "RSA 2048, expires in 25 hours".
func certInfo(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		return ""
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return ""
	}
	key := c.PublicKeyAlgorithm.String()
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok {
		key = "RSA " + strconv.Itoa(k.N.BitLen())
	}
	return key + ", expires in " + roundDuration(time.Until(c.NotAfter))
}

func init() {
	funcs["logData"] = func(secret string, rows []logRow, max int) logData { return logData{secret, rows, max} }
	funcs["ep"] = func(label, binding, url string) endpoint {
		return endpoint{Label: label, Binding: binding, URL: url, Plain: strings.HasPrefix(binding, "same as")}
	}
	funcs["xml"] = func(xml string) template.HTML { return xmlHTML(inspect.HighlightXML(xml)) }
	funcs["xmlTokens"] = xmlHTML
	funcs["clockTZ"] = func(t time.Time) string { return t.UTC().Format("15:04:05") }
	funcs["iso"] = func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
}
