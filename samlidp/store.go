package samlidp

import "errors"

var ErrNotFound = errors.New("not found")

type Store interface {
	Get(key string, value interface{}) error
	Put(key string, value interface{}) error
	Delete(key string) error
	List(prefix string) ([]string, error)
}
