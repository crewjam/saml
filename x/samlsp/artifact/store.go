package artifact

import (
	"context"
	"encoding/xml"
	"errors"
	"sync"
	"time"

	"github.com/beevik/etree"
)

// StoredMessage is a message waiting for its artifact to be resolved.
type StoredMessage struct {
	// XML is the message.
	XML []byte

	// Recipient is the entity ID of the party allowed to resolve the
	// artifact: the IdP the message was sent to.
	Recipient string

	// ExpiresAt is when the artifact stops being resolvable.
	ExpiresAt time.Time
}

// Store keeps messages until their artifacts are resolved. A Binding
// served by several processes needs a Store that they share, since the
// IdP's request may reach any of them.
type Store interface {
	// Save keeps m under artifact.
	Save(ctx context.Context, artifact string, m StoredMessage) error

	// Take returns the message kept under artifact for recipient and
	// forgets it, so that it is given out at most once. It returns nil if
	// there is none, or if the message is for another recipient, which it
	// then keeps: a party that learns an artifact meant for another cannot
	// make it unusable. It may return a message whose ExpiresAt has
	// passed; the Binding refuses it.
	Take(ctx context.Context, artifact, recipient string) (*StoredMessage, error)
}

// DefaultMaxEntries is how many messages a MemoryStore keeps at most,
// unless MemoryStore.MaxEntries says otherwise.
const DefaultMaxEntries = 10000

// ErrStoreFull is returned by MemoryStore.Save when the store already
// keeps as many messages as it may.
var ErrStoreFull = errors.New("artifact: the store is full")

// MemoryStore is a Store in memory, for a single process. Each message is
// forgotten when it expires by Now. It is safe for concurrent use. The
// zero value is ready to use.
//
// A message's timer waits until its expiry, but at most maxTimerDelay by
// the system clock, and then checks again by Now, so that messages are
// still forgotten when Now is not the system clock. Save also forgets the
// expired messages when the store is full.
//
// Anyone who can start a login can make a Binding store a message, so the
// store keeps at most MaxEntries of them: while it is full, Save, and so
// the Binding's Encode, fail with ErrStoreFull, until messages are
// resolved or expire.
type MemoryStore struct {
	// Now is the time source by which messages expire; nil means
	// time.Now. It must be the time source by which ExpiresAt is set: New,
	// and New of github.com/crewjam/saml/x/samlidp/idpartifact, set it to
	// that of the Config if it is nil (see samlsp.WithClock and
	// samlidp.WithClock). Set it before the first Save.
	Now func() time.Time

	// MaxEntries is how many messages the store keeps at most. If zero,
	// DefaultMaxEntries is used.
	MaxEntries int

	afterFunc func(d time.Duration, f func()) (stop func() bool) // for tests; time.AfterFunc if nil

	mu       sync.Mutex
	messages map[string]memoryEntry
}

// maxTimerDelay bounds how long a message's timer waits, by the system
// clock, before it checks again whether the message has expired by Now.
// Now may run apart from the system clock, so a timer set for an expiry
// by Now could otherwise fire long after it, or long before.
const maxTimerDelay = time.Minute

type memoryEntry struct {
	message StoredMessage
	stop    func() bool
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{messages: map[string]memoryEntry{}}
}

// Save implements Store.
func (s *MemoryStore) Save(_ context.Context, artifact string, m StoredMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, replaced := s.messages[artifact]
	if !replaced && len(s.messages) >= s.maxEntries() {
		s.removeExpired(s.now())
		if len(s.messages) >= s.maxEntries() {
			return ErrStoreFull
		}
	}
	if replaced {
		old.stop()
	}
	if s.messages == nil {
		s.messages = map[string]memoryEntry{}
	}
	s.messages[artifact] = memoryEntry{message: m, stop: s.arm(artifact, m.ExpiresAt, s.now())}
	return nil
}

func (s *MemoryStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// arm starts the timer that forgets the message under artifact, which
// expires at expiresAt. s.mu must be held.
func (s *MemoryStore) arm(artifact string, expiresAt, now time.Time) func() bool {
	// A message is resolvable until its expiry inclusive, so fire just
	// after.
	d := min(max(expiresAt.Sub(now)+time.Nanosecond, 0), maxTimerDelay)
	f := func() { s.expire(artifact, expiresAt) }
	if s.afterFunc != nil {
		return s.afterFunc(d, f)
	}
	return time.AfterFunc(d, f).Stop
}

// removeExpired forgets every message that has expired by now. s.mu must
// be held.
func (s *MemoryStore) removeExpired(now time.Time) {
	for artifact, e := range s.messages {
		if now.After(e.message.ExpiresAt) {
			e.stop()
			delete(s.messages, artifact)
		}
	}
}

func (s *MemoryStore) maxEntries() int {
	if s.MaxEntries > 0 {
		return s.MaxEntries
	}
	return DefaultMaxEntries
}

// defaultNow makes the store use now if it has no Now.
func (s *MemoryStore) defaultNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Now == nil {
		s.Now = now
	}
}

// Take implements Store.
func (s *MemoryStore) Take(_ context.Context, artifact, recipient string) (*StoredMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.messages[artifact]
	if !ok || e.message.Recipient != recipient {
		return nil, nil
	}
	e.stop()
	delete(s.messages, artifact)
	return &e.message, nil
}

// expire forgets the message under artifact, if it is the one that
// expires at expiresAt and it has expired by Now, and otherwise sets its
// timer again.
func (s *MemoryStore) expire(artifact string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.messages[artifact]
	if !ok || !e.message.ExpiresAt.Equal(expiresAt) {
		return
	}
	now := s.now()
	if now.After(expiresAt) {
		delete(s.messages, artifact)
		return
	}
	e.stop = s.arm(artifact, expiresAt, now)
	s.messages[artifact] = e
}

// Len returns the number of messages kept.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// unmarshal reads el into v.
func unmarshal(el *etree.Element, v any) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	buf, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(buf, v)
}
