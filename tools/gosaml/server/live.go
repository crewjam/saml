package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/crewjam/saml/tools/gosaml/store"
)

// Live logs: the management pages follow their instance's log with
// Server-Sent Events. Everything runs in one process (see fly.toml), so
// the hub is in memory.

const (
	maxSubscribersPerInstance = 20
	maxSubscribers            = 500
	livePing                  = 25 * time.Second
)

// errTooManySubscribers is returned when a page cannot follow a log
// because too many already do.
var errTooManySubscribers = errors.New("too many pages are following logs")

// clearedEvent is published, with this ID, when an instance's log is
// cleared.
const clearedEvent = -1

// hub fans out the events each instance logs to the pages following it.
type hub struct {
	mu    sync.Mutex
	subs  map[string]map[chan store.Event]struct{}
	total int
	done  chan struct{}
	once  sync.Once
}

func newHub() *hub {
	return &hub{subs: map[string]map[chan store.Event]struct{}{}, done: make(chan struct{})}
}

// subscribe returns a channel of the events instanceID logs from now on,
// and a function to stop.
func (h *hub) subscribe(instanceID string) (<-chan store.Event, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.total >= maxSubscribers || len(h.subs[instanceID]) >= maxSubscribersPerInstance {
		return nil, nil, errTooManySubscribers
	}
	ch := make(chan store.Event, 64)
	if h.subs[instanceID] == nil {
		h.subs[instanceID] = map[chan store.Event]struct{}{}
	}
	h.subs[instanceID][ch] = struct{}{}
	h.total++
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			delete(h.subs[instanceID], ch)
			if len(h.subs[instanceID]) == 0 {
				delete(h.subs, instanceID)
			}
			h.total--
		})
	}, nil
}

// publish sends e to the pages following its instance. A page too slow
// to keep up misses it, and gets it when it reconnects (Last-Event-ID).
func (h *hub) publish(e store.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[e.InstanceID] {
		select {
		case ch <- e:
		default:
		}
	}
}

// close ends every stream, for shutdown.
func (h *hub) close() { h.once.Do(func() { close(h.done) }) }

// CloseLive ends the live log streams, which would otherwise keep
// http.Server.Shutdown waiting. Register it with RegisterOnShutdown.
func (s *Server) CloseLive() { s.hub.close() }

// liveLog streams an instance's new log events as Server-Sent Events.
// Each "log" event's data is JSON: the event's ID and its rendered
// list item. A "clear" event says the log was cleared, and "gone" that
// the instance no longer exists.
func (s *Server) liveLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := s.Store.InstanceBySecret(ctx, r.PathValue("secret"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	events, stop, err := s.hub.subscribe(in.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer stop()

	// The stream outlives the server's WriteTimeout.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event, id, data string) bool {
		var b bytes.Buffer
		if id != "" {
			fmt.Fprintf(&b, "id: %s\n", id)
		}
		fmt.Fprintf(&b, "event: %s\ndata: %s\n\n", event, data)
		if _, err := w.Write(b.Bytes()); err != nil {
			return false
		}
		return rc.Flush() == nil
	}

	// Catch up from the last event the page has: its Last-Event-ID when
	// the browser reconnects, or the newest the page was rendered with.
	last, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	if last == 0 {
		last, _ = strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	}
	if _, err := w.Write([]byte("retry: 3000\n\n")); err != nil {
		return
	}
	if last > 0 {
		missed, err := s.Store.EventsAfter(ctx, in.ID, last)
		if err != nil {
			return
		}
		for i := len(missed) - 1; i >= 0; i-- {
			if !s.sendEvent(send, missed[i]) {
				return
			}
			last = missed[i].ID
		}
	}
	if !send("ready", "", "{}") {
		return
	}

	ping := time.NewTicker(livePing)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.hub.done:
			return
		case <-ping.C:
			// Keep proxies from closing an idle stream, and notice when
			// the instance is gone.
			if _, err := s.Store.Instance(ctx, in.Kind, in.ID); errors.Is(err, store.ErrNotFound) {
				send("gone", "", "{}")
				return
			}
			if _, err := w.Write([]byte(": ping\n\n")); err != nil || rc.Flush() != nil {
				return
			}
		case e := <-events:
			if e.ID == clearedEvent {
				if !send("clear", "", "{}") {
					return
				}
				continue
			}
			if e.ID <= last {
				continue // already sent while catching up
			}
			if !s.sendEvent(send, e) {
				return
			}
			last = e.ID
		}
	}
}

func (s *Server) sendEvent(send func(event, id, data string) bool, e store.Event) bool {
	var html bytes.Buffer
	if err := s.pages["home"].ExecuteTemplate(&html, "event", e); err != nil {
		s.Logger.Error("cannot render a log event", "err", err)
		return true
	}
	data, _ := json.Marshal(struct {
		ID   int64  `json:"id"`
		HTML string `json:"html"`
	}{e.ID, html.String()})
	return send("log", strconv.FormatInt(e.ID, 10), string(data))
}
