package artifact

import (
	"context"
	"encoding/xml"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
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

// MemoryStore is a Store in memory, for a single process. Each message is
// forgotten when it expires. It is safe for concurrent use. The zero value
// is ready to use.
type MemoryStore struct {
	// Clock is the time source by which messages expire; nil means the
	// system clock. Use the clock passed to samlsp.WithClock. Set it
	// before the first Save.
	Clock *dsig.Clock

	mu       sync.Mutex
	messages map[string]memoryEntry
}

type memoryEntry struct {
	message StoredMessage
	timer   *time.Timer
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{messages: map[string]memoryEntry{}}
}

// Save implements Store.
func (s *MemoryStore) Save(_ context.Context, artifact string, m StoredMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.messages[artifact]; ok {
		old.timer.Stop()
	}
	if s.messages == nil {
		s.messages = map[string]memoryEntry{}
	}
	// The timer runs on the system clock, for as long as m has left by
	// s.Clock.
	timer := time.AfterFunc(m.ExpiresAt.Sub(s.Clock.Now()), func() { s.forget(artifact, m.ExpiresAt) })
	s.messages[artifact] = memoryEntry{message: m, timer: timer}
	return nil
}

// Take implements Store.
func (s *MemoryStore) Take(_ context.Context, artifact, recipient string) (*StoredMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.messages[artifact]
	if !ok || e.message.Recipient != recipient {
		return nil, nil
	}
	e.timer.Stop()
	delete(s.messages, artifact)
	return &e.message, nil
}

// forget removes the message under artifact, if it is the one that
// expires at expiresAt.
func (s *MemoryStore) forget(artifact string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.messages[artifact]; ok && e.message.ExpiresAt.Equal(expiresAt) {
		delete(s.messages, artifact)
	}
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
