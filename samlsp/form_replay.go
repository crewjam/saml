package samlsp

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// ErrFormTooLarge is returned by MemoryFormReplayStore.SaveForm when the body
// of a POST request is larger than its MaxFormSize. The middleware passes it
// to OnError, and does not start the auth flow.
var ErrFormTooLarge = errors.New("saml: form is too large to save for replay after login")

// SavedForm is a form saved by a FormReplayStore.
type SavedForm struct {
	// URI is the URI of the request the form was posted to, as r.URL.String().
	URI string

	// Form holds the fields of the form.
	Form url.Values
}

// FormReplayStore saves the form of a POST request that starts the SAML auth
// flow, so that the middleware can post it again once the user has logged in.
// See Middleware.FormReplayStore.
//
// A FormReplayStore must keep the forms on the server, or encrypt them: they
// can hold passwords, tokens or personal data.
type FormReplayStore interface {
	// SaveForm is called by HandleStartAuthFlow for a same-origin POST
	// request r that has no session. index is the RelayState of the auth
	// flow, as returned by the RequestTracker. SaveForm may save the form of
	// r under index, and reports whether it did.
	//
	// If it returns false and a nil error, the form is not replayed, and the
	// user is redirected to the URI of r with a GET request after login, as
	// when Middleware.FormReplayStore is nil. A non-nil error is passed to
	// OnError, and the auth flow does not start.
	SaveForm(r *http.Request, index string) (bool, error)

	// TakeForm returns and deletes the form saved under index. It reports
	// false if there is no such form, or if it has expired.
	TakeForm(r *http.Request, index string) (form *SavedForm, ok bool, err error)
}

// Defaults of MemoryFormReplayStore.
const (
	DefaultFormReplayMaxFormSize = 64 << 10
	DefaultFormReplayMaxEntries  = 1000
	DefaultFormReplayMaxAge      = 5 * time.Minute
)

var _ FormReplayStore = &MemoryFormReplayStore{}

// MemoryFormReplayStore is a FormReplayStore that keeps forms in memory. It
// saves only application/x-www-form-urlencoded forms: a multipart form, which
// may carry files, is not replayed.
//
// The forms are kept in the memory of one process, so an application that
// runs more than one instance behind a load balancer needs sticky sessions,
// or a FormReplayStore of its own backed by shared storage.
//
// The zero value is ready to use. A MemoryFormReplayStore must not be copied
// after first use.
type MemoryFormReplayStore struct {
	// MaxFormSize is the largest form body, in bytes, that is saved. A larger
	// form makes SaveForm return ErrFormTooLarge. If zero,
	// DefaultFormReplayMaxFormSize is used.
	MaxFormSize int64

	// MaxEntries is the largest number of forms kept at once. When the store
	// is full, forms are not saved, and the user is redirected with a GET
	// request after login. If zero, DefaultFormReplayMaxEntries is used.
	MaxEntries int

	// MaxAge is how long a saved form is kept. If zero,
	// DefaultFormReplayMaxAge is used.
	MaxAge time.Duration

	// Allow, if set, decides which requests have their form saved. It
	// should accept only forms that are safe to post again once the user
	// has logged in. If nil, every application/x-www-form-urlencoded form
	// is saved.
	Allow func(r *http.Request) bool

	mu    sync.Mutex
	forms map[string]memoryFormEntry
}

type memoryFormEntry struct {
	form    SavedForm
	expires time.Time
}

func (s *MemoryFormReplayStore) maxFormSize() int64 {
	if s.MaxFormSize > 0 {
		return s.MaxFormSize
	}
	return DefaultFormReplayMaxFormSize
}

func (s *MemoryFormReplayStore) maxEntries() int {
	if s.MaxEntries > 0 {
		return s.MaxEntries
	}
	return DefaultFormReplayMaxEntries
}

func (s *MemoryFormReplayStore) maxAge() time.Duration {
	if s.MaxAge > 0 {
		return s.MaxAge
	}
	return DefaultFormReplayMaxAge
}

// SaveForm implements FormReplayStore.
func (s *MemoryFormReplayStore) SaveForm(r *http.Request, index string) (bool, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return false, nil
	}
	if s.Allow != nil && !s.Allow(r) {
		return false, nil
	}

	form, err := readPostForm(r, s.maxFormSize())
	if err != nil {
		return false, err
	}

	now := saml.TimeNow()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forms == nil {
		s.forms = map[string]memoryFormEntry{}
	}
	if len(s.forms) >= s.maxEntries() {
		for k, entry := range s.forms {
			if !now.Before(entry.expires) {
				delete(s.forms, k)
			}
		}
		if len(s.forms) >= s.maxEntries() {
			return false, nil
		}
	}
	s.forms[index] = memoryFormEntry{
		form:    SavedForm{URI: r.URL.String(), Form: form},
		expires: now.Add(s.maxAge()),
	}
	return true, nil
}

// TakeForm implements FormReplayStore.
func (s *MemoryFormReplayStore) TakeForm(_ *http.Request, index string) (*SavedForm, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.forms[index]
	if !ok {
		return nil, false, nil
	}
	delete(s.forms, index)
	if !saml.TimeNow().Before(entry.expires) {
		return nil, false, nil
	}
	return &entry.form, true, nil
}

// readPostForm returns the fields of the url-encoded body of r, or
// ErrFormTooLarge if the body is longer than maxSize bytes.
func readPostForm(r *http.Request, maxSize int64) (url.Values, error) {
	if r.PostForm != nil {
		// The application has parsed the body already.
		if int64(len(r.PostForm.Encode())) > maxSize {
			return nil, ErrFormTooLarge
		}
		return r.PostForm, nil
	}
	if r.Body == nil {
		return url.Values{}, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxSize {
		return nil, ErrFormTooLarge
	}
	return url.ParseQuery(string(body))
}

// isSameOriginRequest reports whether the browser says that r comes from a
// page on the same origin. Forms posted from another site are never replayed:
// that would turn a cross-site POST into a same-site one carrying the new
// session cookie, defeating SameSite cookie protection.
func isSameOriginRequest(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host != "" && u.Host == r.Host
}

// replayScript is the auto-submit script of the form replay page. It is
// fixed, so that the page can be served with a hash-based CSP.
const replayScript = `document.getElementById('SAMLReplaySubmitButton').style.visibility="hidden";` +
	`document.getElementById('SAMLReplayForm').submit();`

// replayScriptHash is the SHA-256 hash of replayScript.
const replayScriptHash = "sha256-I8l7aKMSgv1YWiTwangBLTltE6YZ+jVqT+us/ofukIw="

var replayFormTemplate = template.Must(template.New("saml-replay-form").Parse(`` +
	`<form method="post" action="{{.URL}}" id="SAMLReplayForm">` +
	`{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}" />{{end}}` +
	`<input id="SAMLReplaySubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script{{with .Nonce}} nonce="{{.}}"{{end}}>` + replayScript + `</script>`))

type replayField struct {
	Name, Value string
}

// replayForm renders the auto-submitting form that posts form to uri.
func replayForm(uri string, form url.Values, nonce string) ([]byte, error) {
	names := make([]string, 0, len(form))
	for name := range form {
		names = append(names, name)
	}
	sort.Strings(names)
	var fields []replayField
	for _, name := range names {
		for _, value := range form[name] {
			fields = append(fields, replayField{Name: name, Value: value})
		}
	}
	var buf bytes.Buffer
	err := replayFormTemplate.Execute(&buf, struct {
		URL    string
		Fields []replayField
		Nonce  string
	}{URL: uri, Fields: fields, Nonce: nonce})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
