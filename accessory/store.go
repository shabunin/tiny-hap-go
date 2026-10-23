package accessory

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Store keeps accessory id, keys, pairings and configuration number
// across restarts. On a board, implement it with flash.
type Store interface {
	// Get returns ErrNotFound if key was never set.
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
}

// ErrNotFound is returned by Store.Get for missing key.
var ErrNotFound = errors.New("accessory: not found in store")

type memStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemStore returns store in memory, pairings are lost on restart.
func NewMemStore() Store {
	return &memStore{m: make(map[string][]byte)}
}

func (s *memStore) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (s *memStore) Set(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = append([]byte(nil), value...)
	return nil
}

type fsStore struct {
	dir string
}

// NewFsStore returns store keeping a file per key in directory.
func NewFsStore(dir string) Store {
	return fsStore{dir}
}

func (s fsStore) Get(key string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// Set writes temporary file and renames it, so value is never half written.
func (s fsStore) Set(key string, value []byte) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(s.dir, key)
	if err := os.WriteFile(path+".tmp", value, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
