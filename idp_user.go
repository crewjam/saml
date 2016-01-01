package saml

import "sync"

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

type MemoryUserStore struct {
	mu   sync.RWMutex
	data map[string]User
}

func (m *MemoryUserStore) Put(u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = map[string]User{}
	}
	m.data[u.Name] = u
	return nil
}

func (m *MemoryUserStore) Get(id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.data[id]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *MemoryUserStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
	return nil
}
