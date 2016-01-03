package saml

import "sync"

// User represents a stored user. The data here are used to
// populate session once the user has authenticated.
type User struct {
	Name     string
	Password string // XXX !!!
	Groups   []string
	Email    string

	CommonName string
	Surname    string
	GivenName  string
}

// UserStore is an interface that describes how session
// objects are stored. It must be
type UserStore interface {
	Put(u User) error
	Get(id string) (*User, error)
	Delete(id string) error
}

// MemoryUserStore is an in-memory, non-persistent implementation
// of UserStore.
type MemoryUserStore struct {
	mu   sync.RWMutex
	data map[string]User
}

// Put stores a user
func (m *MemoryUserStore) Put(u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = map[string]User{}
	}
	m.data[u.Name] = u
	return nil
}

// Get fetches a user
func (m *MemoryUserStore) Get(id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.data[id]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

// Delete removes a user
func (m *MemoryUserStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
	return nil
}
