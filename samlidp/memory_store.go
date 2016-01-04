package samlidp

import (
	"encoding/json"
	"strings"
	"sync"
)

type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]string
}

func (s *MemoryStore) Get(key string, value interface{}) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, ok := s.data[key]
	if !ok {
		return ErrNotFound
	}
	return json.Unmarshal([]byte(v), value)
}

func (s *MemoryStore) Put(key string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = map[string]string{}
	}

	buf, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.data[key] = string(buf)
	return nil
}

func (s *MemoryStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *MemoryStore) List(prefix string) ([]string, error) {
	rv := []string{}
	for k, _ := range s.data {
		if strings.HasPrefix(k, prefix) {
			rv = append(rv, strings.TrimPrefix(k, prefix))
		}
	}
	return rv, nil
}
