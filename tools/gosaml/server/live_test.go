package server

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type sseEvent struct{ event, id, data string }

// readSSE reads Server-Sent Events from the body of resp into a channel.
func readSSE(t *testing.T, resp *http.Response) <-chan sseEvent {
	t.Helper()
	ch := make(chan sseEvent, 16)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.event != "" {
					ch <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "event: "):
				ev.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "id: "):
				ev.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "data: "):
				// Data lines join with newlines, as browsers join them.
				if ev.data != "" {
					ev.data += "\n"
				}
				ev.data += strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return ch
}

func next(t *testing.T, ch <-chan sseEvent, want string) sseEvent {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("stream ended waiting for %q", want)
			}
			if ev.event == want {
				return ev
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func (h *harness) stream(path string, lastEventID string) (<-chan sseEvent, func()) {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.base+path, nil)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		h.t.Fatalf("content type %q", ct)
	}
	return readSSE(h.t, resp), func() { cancel(); _ = resp.Body.Close() }
}

func TestLiveLog(t *testing.T) {
	h := newHarness(t)
	_, _, spSecrets, spIDs := pair(h, 1)
	secret, id := spSecrets[0], spIDs[0]

	events, stop := h.stream("/manage/"+secret+"/live", "")
	defer stop()
	next(t, events, "ready")

	// A login logs its AuthnRequest, which the page sees as it happens.
	h.do(http.MethodPost, "/sp/"+id+"/login", nil)
	// Its data is the row, as HTML, for htmx to add to the Log.
	ev := next(t, events, "log")
	if ev.id == "" || !strings.HasPrefix(ev.data, `<li data-id="`+ev.id+`">`) ||
		!strings.Contains(ev.data, "AuthnRequest to") || !strings.Contains(ev.data, "/manage/"+secret+"/log/"+ev.id) {
		t.Fatalf("event: id %s, data %s", ev.id, ev.data)
	}

	// A page that reconnects gets what it missed after its Last-Event-ID.
	h.do(http.MethodPost, "/sp/"+id+"/login", nil)
	missed, stop2 := h.stream("/manage/"+secret+"/live", ev.id)
	defer stop2()
	if got := next(t, missed, "log"); got.id == ev.id || got.id == "" {
		t.Fatalf("catch-up sent %q again", got.id)
	}
	next(t, missed, "ready")

	// Clearing the log tells the page.
	h.do(http.MethodPost, "/manage/"+secret+"/clear-events", url.Values{})
	if ev := next(t, events, "clear"); !strings.Contains(ev.data, `hx-swap-oob="true"`) || !strings.Contains(ev.data, `id="log-list"`) || !strings.Contains(ev.data, `hx-disinherit="*"`) {
		t.Errorf("clear: %s", ev.data)
	}

	// An unknown secret has no stream.
	if resp, _ := h.do(http.MethodGet, "/manage/nope/live", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown secret: %d", resp.StatusCode)
	}
}

func TestHubLimits(t *testing.T) {
	h := newHub()
	var stops []func()
	for range maxSubscribersPerInstance {
		_, stop, err := h.subscribe("a")
		if err != nil {
			t.Fatal(err)
		}
		stops = append(stops, stop)
	}
	if _, _, err := h.subscribe("a"); err == nil {
		t.Error("expected the per-instance limit")
	}
	stops[0]()
	stops[0]() // idempotent
	if _, _, err := h.subscribe("a"); err != nil {
		t.Errorf("after unsubscribing: %v", err)
	}
}
