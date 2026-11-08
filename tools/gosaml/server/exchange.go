package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/crewjam/saml/tools/gosaml/store"
)

// The log entry page shows the HTTP exchange each event happened in: the
// request an instance received, and its answer. exchangeRecorder captures
// them for the protocol endpoints, and keeps them for the events logged
// while the request was handled.

// maxExchangeBody is how much of a request or response body is kept.
const maxExchangeBody = 64 << 10

// protocolPath matches the endpoints whose exchanges are recorded: the
// ones other SAML parties and browsers send messages to.
var protocolPath = regexp.MustCompile(`^/(idp|sp)/[a-z0-9-]+/(sso|login|slo|artifact|logout|acs)$`)

type exchangeKey struct{}

// exchangeRecorder holds what an exchange needs while its request is
// handled.
type exchangeRecorder struct {
	mu       sync.Mutex
	instance string
	eventIDs []int64
}

// noteEvent records that an event was logged during the request.
func noteEvent(ctx context.Context, e *store.Event) {
	rec, _ := ctx.Value(exchangeKey{}).(*exchangeRecorder)
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.instance == "" {
		rec.instance = e.InstanceID
	}
	if e.InstanceID == rec.instance {
		rec.eventIDs = append(rec.eventIDs, e.ID)
	}
}

// recordingWriter passes a response through, keeping a copy.
type recordingWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
	size   int
}

func (w *recordingWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.size += len(b)
	if room := maxExchangeBody - w.body.Len(); room > 0 {
		w.body.Write(b[:min(room, len(b))])
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// recordExchange serves r with next, and stores the exchange if events
// were logged while it was handled.
func (s *Server) recordExchange(w http.ResponseWriter, r *http.Request, next http.Handler) {
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(r.Body, 4<<20))
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	rec := &exchangeRecorder{}
	rw := &recordingWriter{ResponseWriter: w}
	next.ServeHTTP(rw, r.WithContext(context.WithValue(r.Context(), exchangeKey{}, rec)))

	rec.mu.Lock()
	instance, ids := rec.instance, append([]int64(nil), rec.eventIDs...)
	rec.mu.Unlock()
	if instance == "" || len(ids) == 0 {
		return
	}
	x := &store.Exchange{
		InstanceID: instance,
		Request:    rawRequest(r, reqBody),
		Response:   rawResponse(rw),
	}
	// The request's own context may be done (the client may have gone);
	// the exchange is still worth keeping.
	if err := s.Store.AddExchange(context.WithoutCancel(r.Context()), x, ids); err != nil {
		s.Logger.Error("cannot record the exchange", "instance", instance, "err", err)
	}
}

// rawRequest writes r as HTTP/1.1 text.
func rawRequest(r *http.Request, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", r.Method, r.URL.RequestURI())
	fmt.Fprintf(&b, "Host: %s\n", r.Host)
	writeHeaders(&b, r.Header)
	b.WriteString("\n")
	writeBody(&b, body, len(body))
	return b.String()
}

// rawResponse writes the recorded response as HTTP/1.1 text.
func rawResponse(w *recordingWriter) string {
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\n", status, http.StatusText(status))
	writeHeaders(&b, w.Header())
	b.WriteString("\n")
	writeBody(&b, w.body.Bytes(), w.size)
	return b.String()
}

func writeHeaders(b *strings.Builder, h http.Header) {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\n", k, redactHeader(k, v))
		}
	}
}

func writeBody(b *strings.Builder, body []byte, size int) {
	if size == 0 {
		b.WriteString("(empty body)")
		return
	}
	b.Write(bytes.ToValidUTF8(body, []byte("�")))
	if size > len(body) {
		fmt.Fprintf(b, "\n… (%d more bytes not kept)", size-len(body))
	}
}

// redactHeader shortens the values of headers that carry secrets: cookies
// and credentials. The names stay, so the exchange can still be read.
func redactHeader(name, value string) string {
	switch strings.ToLower(name) {
	case "cookie":
		parts := strings.Split(value, ";")
		for i, p := range parts {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok {
				parts[i] = k + "=" + shorten(v)
			}
		}
		return strings.Join(parts, "; ")
	case "set-cookie":
		first, rest, _ := strings.Cut(value, ";")
		if k, v, ok := strings.Cut(first, "="); ok {
			first = k + "=" + shorten(v)
		}
		if rest != "" {
			return first + ";" + rest
		}
		return first
	case "authorization", "proxy-authorization":
		scheme, _, _ := strings.Cut(value, " ")
		return scheme + " …"
	}
	return value
}

// shorten keeps the first characters of a secret value.
func shorten(v string) string {
	if len(v) <= 8 {
		return v
	}
	return v[:8] + "…"
}
