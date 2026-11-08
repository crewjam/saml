package samlmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/safehttp"
)

// FetchTimeout bounds a fetch that a Remote makes, which no caller's
// context cancels.
const FetchTimeout = 2 * time.Minute

// RetryInterval is the least time a Remote waits between fetches: before
// it retries a fetch that failed, and before it fetches again metadata
// whose cacheDuration or validUntil would make it due at once.
const RetryInterval = time.Minute

// Remote fetches metadata from a URL and caches it. Set its fields before
// the first call of Get, and do not change them after.
//
// The metadata is fetched when first needed. It is due again once
// RefreshInterval, its cacheDuration or its validUntil has passed (those
// of the entity and of its Roles). While the cached metadata is still
// valid, callers get it at once and a single refresh runs in the
// background; callers wait only when there is no valid metadata, and then
// share one fetch. If a refresh fails, the cached metadata is kept until
// its validUntil (or, if it has none, for MaxStale after it was fetched),
// and the fetch is retried RetryInterval later. When a fetch fails and
// there is no valid metadata, calls before the retry get its error without
// fetching again.
type Remote struct {
	// URL is fetched with GET.
	URL string
	// Prefix starts the messages of the errors Remote makes, such as
	// "samlsp".
	Prefix string
	// Parse parses fetched metadata and checks it: its signature, that it
	// describes the entity wanted, and that it is not expired at now.
	Parse func(data []byte, now time.Time) (*saml.EntityDescriptor, error)
	// Roles are the roles whose validUntil and cacheDuration count.
	Roles Roles
	// Signed reports that Parse checks a signature on the metadata, which
	// then may be fetched from a plain http URL. Otherwise URL, and any
	// redirect followed, must be https. Signed metadata must have a
	// validUntil (of the entity, an EntitiesDescriptor around it, or one
	// of its Roles): the signature, unlike TLS, does not show that the
	// metadata is current, so without one an old signed copy, with keys
	// since rotated out, would be accepted forever.
	Signed bool
	// Client fetches the metadata; a copy of it is used. If nil, one that
	// times out after FetchTimeout and connects only to public addresses.
	Client *http.Client
	// Accept, if set, is the Accept header of the request.
	Accept string
	// MaxSize is the size in bytes of the largest document read.
	MaxSize int64
	// RefreshInterval is how long metadata is kept before it is fetched
	// again, unless its cacheDuration or validUntil is sooner.
	RefreshInterval time.Duration
	// MaxStale is how long metadata without a validUntil is used after it
	// was fetched, while refreshes fail.
	MaxStale time.Duration
	// OnFetchError, if set, is called with the error of every failed
	// fetch, from the goroutine of the fetch, never concurrently.
	OnFetchError func(error)
	// Now is the clock. If nil, time.Now.
	Now func() time.Time

	mu        sync.Mutex
	md        *saml.EntityDescriptor
	expiresAt time.Time // when md stops being usable (see expiry)
	refreshAt time.Time
	inflight  *fetch // the fetch in progress, or nil

	// lastErr is the error of the last fetch, if it failed and there was
	// no valid metadata to fall back on; calls get it until retryAt.
	lastErr error
	retryAt time.Time
}

// fetch is a fetch in progress; done is closed when it ends.
type fetch struct {
	done chan struct{}
	md   *saml.EntityDescriptor
	err  error
}

func (r *Remote) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Get returns the cached metadata, fetching it if there is none that is
// valid. If ctx ends first, it returns ctx's error; the fetch goes on.
func (r *Remote) Get(ctx context.Context) (*saml.EntityDescriptor, error) {
	r.mu.Lock()
	now := r.now()
	if r.md != nil && now.Before(r.refreshAt) {
		md := r.md
		r.mu.Unlock()
		return md, nil
	}
	if r.lastErr != nil && now.Before(r.retryAt) && r.inflight == nil {
		err := r.lastErr
		r.mu.Unlock()
		return nil, err
	}
	f := r.startFetch(ctx)
	if r.md != nil && r.usable(now) {
		// Due for a refresh, but still valid: refresh in the background.
		md := r.md
		r.mu.Unlock()
		return md, nil
	}
	r.mu.Unlock()

	select {
	case <-f.done:
		return f.md, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Wait waits for the fetch in progress, if any, to end.
func (r *Remote) Wait() {
	r.mu.Lock()
	f := r.inflight
	r.mu.Unlock()
	if f != nil {
		<-f.done
	}
}

// Valid reports whether r holds metadata it may still return.
func (r *Remote) Valid() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.md != nil && r.usable(r.now())
}

// usable reports whether the cached metadata may still be used at now.
// r.mu must be held.
func (r *Remote) usable(now time.Time) bool {
	return now.Before(r.expiresAt)
}

// expiry returns when md, fetched at now, stops being usable: at its
// earliest validUntil, or if it has none, once MaxStale has passed.
func (r *Remote) expiry(md *saml.EntityDescriptor, now time.Time) time.Time {
	if validUntil, _ := Validity(md, r.Roles); !validUntil.IsZero() {
		return validUntil
	}
	return now.Add(r.MaxStale)
}

// startFetch returns the fetch in progress, starting one if there is none.
// r.mu must be held.
func (r *Remote) startFetch(ctx context.Context) *fetch {
	if r.inflight != nil {
		return r.inflight
	}
	f := &fetch{done: make(chan struct{})}
	r.inflight = f
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), FetchTimeout)
	go func() {
		defer cancel()
		md, err := r.fetch(fetchCtx)
		if err != nil && r.OnFetchError != nil {
			// Still in flight, so that calls for one Remote are never
			// concurrent.
			r.OnFetchError(err)
		}

		r.mu.Lock()
		now := r.now()
		r.lastErr = nil
		switch {
		case err == nil:
			r.md = md
			r.expiresAt = r.expiry(md, now)
			r.refreshAt = r.NextRefresh(md, now)
		case r.md != nil && r.usable(now):
			// Keep the cached metadata and retry later.
			r.refreshAt = now.Add(r.retryInterval())
			md, err = r.md, nil
		default:
			// Nothing to fall back on: give this error until the retry.
			r.lastErr = err
			r.retryAt = now.Add(r.retryInterval())
		}
		r.inflight = nil
		r.mu.Unlock()

		f.md, f.err = md, err
		close(f.done)
	}()
	return f
}

func (r *Remote) fetch(ctx context.Context) (*saml.EntityDescriptor, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid metadata URL: %w", r.Prefix, err)
	}
	if !r.Signed && u.Scheme != "https" {
		return nil, fmt.Errorf("%s: refusing to fetch metadata from %q: not an https URL, and no WithMetadataSigners", r.Prefix, u.Redacted())
	}
	data, err := Fetch(ctx, r.httpClient(), *u, r.MaxSize, r.Accept)
	if err != nil {
		return nil, err
	}
	md, err := r.Parse(data, r.now())
	if err != nil {
		return nil, err
	}
	if r.Signed {
		if validUntil, _ := Validity(md, r.Roles); validUntil.IsZero() {
			return nil, fmt.Errorf("%s: signed metadata for %q has no validUntil, so an old copy could be replayed", r.Prefix, md.EntityID)
		}
	}
	return md, nil
}

// httpClient returns the client to fetch metadata with: a copy of Client,
// or one that times out after FetchTimeout, whose redirect policy, unless
// Signed, also refuses to follow a redirect to a URL that is not https.
// Without that, a redirect from https to http would let anyone on the
// network path supply the metadata.
func (r *Remote) httpClient() *http.Client {
	c := *safehttp.Client(FetchTimeout, nil)
	if r.Client != nil {
		c = *r.Client
	}
	if r.Signed {
		return &c
	}
	next := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("%s: refusing to follow a redirect to %q: not an https URL, and no WithMetadataSigners", r.Prefix, req.URL.Redacted())
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &c
}

// NextRefresh returns when md, fetched at now, is due to be fetched again.
func (r *Remote) NextRefresh(md *saml.EntityDescriptor, now time.Time) time.Time {
	validUntil, cacheDuration := Validity(md, r.Roles)
	next := now.Add(r.RefreshInterval)
	if cacheDuration > 0 && cacheDuration < r.RefreshInterval {
		next = now.Add(cacheDuration)
	}
	if !validUntil.IsZero() && validUntil.Before(next) {
		next = validUntil
	}
	// Refresh before metadata without a validUntil goes stale.
	if expiresAt := r.expiry(md, now); expiresAt.Before(next) {
		next = expiresAt
	}
	// Metadata that is already (or nearly) expired or stale when it
	// arrives must not make every call fetch it again.
	return later(next, now.Add(r.retryInterval()))
}

// retryInterval is the least time between fetches.
func (r *Remote) retryInterval() time.Duration {
	return min(r.RefreshInterval, RetryInterval)
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
