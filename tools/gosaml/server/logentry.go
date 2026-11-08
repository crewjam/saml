package server

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml/tools/gosaml/inspect"
	"github.com/crewjam/saml/tools/gosaml/store"
)

// logEntryPage is the data of the log entry page: one event of an
// instance's log in full, with the HTTP exchange it happened in.
type logEntryPage struct {
	Kind         store.Kind
	Secret       string
	InstanceName string
	Row          logRow
	Event        *store.Event
	Older, Newer string

	// Verb is "Received", "Sent" or "Recorded"; Binding how the message
	// came or went, if known; Outcome a sentence on what came of it.
	Verb, Binding, Outcome string

	// RequestLine and Answered describe the exchange, if there is one.
	RequestLine  string
	Answered     string
	Checks       []inspect.ViewCheck
	HTTPRequest  string
	HTTPResponse string
	ParamsLabel  string
	Params       []KV
	Curl         string
	InspectHref  string
	Decoded      []*inspect.View
}

// rawHTTP is an exchange's request or response, split up.
type rawHTTP struct {
	StartLine string
	Header    http.Header
	Body      string
}

func splitRaw(raw string) rawHTTP {
	head, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	r := rawHTTP{StartLine: lines[0], Header: http.Header{}}
	for _, l := range lines[1:] {
		if k, v, ok := strings.Cut(l, ": "); ok {
			r.Header.Add(k, v)
		}
	}
	if body != "(empty body)" {
		r.Body = body
	}
	return r
}

func (s *Server) logEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := s.Store.InstanceBySecret(ctx, r.PathValue("secret"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This instance does not exist or has expired.", nil)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ev, err := s.Store.GetEvent(ctx, in.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, "That log entry is gone: only the last 50 are kept, and Clear deletes them.", nil)
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Cannot read the log.", err)
		return
	}
	n := s.names(ctx)
	p := &logEntryPage{Kind: in.Kind, Secret: in.Secret, Event: ev, Row: n.row(in, *ev)}
	switch in.Kind {
	case store.KindIdP:
		if _, cfg, err := s.loadIdP(ctx, in.ID); err == nil {
			p.InstanceName = cfg.Name
		}
	case store.KindSP:
		if _, cfg, err := s.loadSP(ctx, in.ID); err == nil {
			p.InstanceName = cfg.Name
		}
	}
	if older, newer, err := s.Store.AdjacentEvents(ctx, in.ID, id); err == nil {
		if older != 0 {
			p.Older = "/manage/" + in.Secret + "/log/" + strconv.FormatInt(older, 10)
		}
		if newer != 0 {
			p.Newer = "/manage/" + in.Secret + "/log/" + strconv.FormatInt(newer, 10)
		}
	}
	switch ev.Direction {
	case "in":
		p.Verb = "Received"
	case "out":
		p.Verb = "Sent"
	default:
		p.Verb = "Recorded"
	}

	inspectInput := ev.XML
	if ev.ExchangeID != 0 {
		if x, err := s.Store.GetExchange(ctx, in.ID, ev.ExchangeID); err == nil {
			p.HTTPRequest, p.HTTPResponse = x.Request, x.Response
			s.describeExchange(p, x)
			if inspectInput == "" {
				inspectInput = x.Request
			}
		}
	}

	if ev.XML != "" {
		for _, v := range decodedViews(ev, p.HTTPRequest) {
			p.Decoded = append(p.Decoded, v)
			p.Checks = append(p.Checks, v.Checks...)
		}
	}
	reason := lastCause(ev.Detail)
	switch {
	case !ev.OK && ev.Direction == "in":
		p.Checks = append([]inspect.ViewCheck{{Level: "bad", Text: "Refused: " + reason}}, p.Checks...)
		p.Outcome = "It was refused: " + reason
	case !ev.OK:
		p.Checks = append([]inspect.ViewCheck{{Level: "bad", Text: reason}}, p.Checks...)
	case ev.Direction == "in":
		p.Checks = append([]inspect.ViewCheck{{Level: "ok", Text: "Accepted"}}, p.Checks...)
		p.Outcome = "It was accepted."
	}
	if inspectInput != "" {
		p.InspectHref = "/inspect#m=" + strings.ReplaceAll(url.QueryEscape(inspectInput), "+", "%20")
	}
	s.renderStatus(w, r, http.StatusOK, "logentry", p.Row.Title, p)
}

// decodedViews decodes an event's message for its log entry. The XML an
// event keeps is indented for reading, which breaks its signatures, so a
// message the instance received is decoded from the raw request it came
// in, when that was kept. Otherwise signatures are not judged: the page
// says so instead of calling them broken.
func decodedViews(ev *store.Event, rawRequest string) []*inspect.View {
	if ev.Direction == "in" && rawRequest != "" {
		res := inspect.Parse(rawRequest, ev.At)
		if res.Error == "" && len(res.Messages) > 0 && res.Messages[0].Error == "" {
			return viewsOf(res)
		}
	}
	views := viewsOf(inspect.Parse(ev.XML, ev.At))
	for _, v := range views {
		checks := v.Checks[:0:0]
		dropped := false
		for _, c := range v.Checks {
			if strings.Contains(c.Text, "signature broken") || strings.HasSuffix(c.Text, " signed") {
				dropped = true
				continue
			}
			checks = append(checks, c)
		}
		if dropped {
			checks = append(checks, inspect.ViewCheck{Level: "warn", Text: "Signatures not checked: only an indented copy was kept"})
		}
		v.Checks = checks
	}
	return views
}

func viewsOf(res *inspect.Result) []*inspect.View {
	var out []*inspect.View
	for _, m := range res.Messages {
		if m.View != nil {
			out = append(out, m.View)
		}
	}
	return out
}

// lastCause returns the most specific line of an error chain in an
// event's detail ("caused by: …"), or its first line.
func lastCause(detail string) string {
	lines := strings.Split(strings.TrimSpace(detail), "\n")
	reason := lines[0]
	for _, l := range lines {
		if c, ok := strings.CutPrefix(strings.TrimSpace(l), "caused by: "); ok {
			reason = c
		}
	}
	return reason
}

// describeExchange fills in what the page says about an exchange.
func (s *Server) describeExchange(p *logEntryPage, x *store.Exchange) {
	req, resp := splitRaw(x.Request), splitRaw(x.Response)
	method, uri, _ := strings.Cut(req.StartLine, " ")
	uri, _, _ = strings.Cut(uri, " ")
	base, _ := url.Parse(s.BaseURL)
	full := base.Scheme + "://" + req.Header.Get("Host") + uri
	p.RequestLine = method + " " + full

	values := url.Values{}
	if u, err := url.Parse(uri); err == nil {
		values = u.Query()
	}
	p.ParamsLabel = "Query parameters, decoded"
	ctype := req.Header.Get("Content-Type")
	switch {
	case strings.Contains(ctype, "xml"):
		p.Binding = "SOAP"
		p.ParamsLabel = ""
	case method == http.MethodPost && strings.HasPrefix(ctype, "application/x-www-form-urlencoded"):
		if v, err := url.ParseQuery(req.Body); err == nil {
			values = v
			p.ParamsLabel = "Form parameters, decoded"
		}
	}
	if p.Binding == "" {
		switch {
		case values.Get("SAMLart") != "":
			p.Binding = "HTTP-Artifact"
		case values.Get("SAMLRequest") == "" && values.Get("SAMLResponse") == "":
		case method == http.MethodGet:
			p.Binding = "HTTP-Redirect"
		case values.Get("SigAlg") != "":
			p.Binding = "HTTP-POST-SimpleSign"
		default:
			p.Binding = "HTTP-POST"
		}
	}
	for _, k := range sortedKeys(values) {
		for _, v := range values[k] {
			if (k == "SAMLRequest" || k == "SAMLResponse" || k == "Signature") && len(v) > 96 {
				v = v[:96] + "… (" + byteSizeOf(len(v)) + ")"
			}
			p.Params = append(p.Params, KV{k, v})
		}
	}

	_, status, _ := strings.Cut(resp.StartLine, " ")
	p.Answered = status
	switch loc := resp.Header.Get("Location"); {
	case loc != "":
		p.Answered += ", redirected to " + loc
	case strings.Contains(resp.Body, `name="SAMLResponse"`) || strings.Contains(resp.Body, `name="SAMLRequest"`) || strings.Contains(resp.Body, `name="SAMLart"`):
		p.Answered += ", with a form the browser posts on"
	case strings.Contains(resp.Header.Get("Content-Type"), "xml"):
		p.Answered += ", with a SOAP message"
	case strings.Contains(resp.Header.Get("Content-Type"), "text/html"):
		p.Answered += ", with a page"
	}
	p.Curl = curlCommand(method, full, req)
}

func sortedKeys(v url.Values) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	// SAML parameters first, in the order the bindings list them.
	order := map[string]int{"SAMLRequest": 0, "SAMLResponse": 0, "SAMLart": 0, "RelayState": 1, "SigAlg": 2, "Signature": 3}
	rank := func(k string) int {
		if r, ok := order[k]; ok {
			return r
		}
		return 9
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && (rank(keys[j]) < rank(keys[j-1]) || rank(keys[j]) == rank(keys[j-1]) && keys[j] < keys[j-1]); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func byteSizeOf(n int) string {
	if n < 1024 {
		return strconv.Itoa(n) + " B"
	}
	return strconv.FormatFloat(float64(n)/1024, 'f', 1, 64) + " KB"
}

// curlCommand writes a request as a curl command. Cookies are left out:
// their values were shortened when the exchange was kept.
func curlCommand(method, target string, req rawHTTP) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	parts := []string{"curl -i"}
	if method != http.MethodGet {
		parts = append(parts, "-X "+method)
	}
	parts = append(parts, q(target))
	for _, k := range []string{"Content-Type", "Soapaction", "User-Agent"} {
		if v := req.Header.Get(k); v != "" {
			parts = append(parts, "-H "+q(k+": "+v))
		}
	}
	if req.Body != "" {
		parts = append(parts, "--data-raw "+q(req.Body))
	}
	return strings.Join(parts, " \\\n  ")
}

// eventDate formats when an event happened, for the log entry's summary.
func eventDate(t time.Time) string { return t.UTC().Format("2 January 2006") }

func init() {
	funcs["eventDate"] = eventDate
}
