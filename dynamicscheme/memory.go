// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dynamicscheme

import (
	"fmt"
	"sort"
	"sync"
)

// MemoryStore is an in-memory Store guarded by a read/write mutex. Records are
// deep-copied on the way in and out so the store never shares mutable state with
// callers. Its lock domain is independent of the static scheme registry.
type MemoryStore struct {
	mu        sync.RWMutex
	providers map[string]*Provider
}

// NewMemoryStore returns an empty in-memory provider store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{providers: map[string]*Provider{}}
}

// GetProvider returns a copy of the record for scheme, or (nil, nil) when absent.
func (s *MemoryStore) GetProvider(scheme string) (*Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	provider, ok := s.providers[scheme]
	if !ok {
		return nil, nil
	}
	return provider.clone(), nil
}

// AllProviders returns copies of every record, ordered by scheme name so
// enumeration is deterministic.
func (s *MemoryStore) AllProviders() ([]*Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	schemes := make([]string, 0, len(s.providers))
	for scheme := range s.providers {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	out := make([]*Provider, 0, len(schemes))
	for _, scheme := range schemes {
		out = append(out, s.providers[scheme].clone())
	}
	return out, nil
}

// PutProvider inserts or replaces the record for its scheme. An empty scheme is
// rejected.
func (s *MemoryStore) PutProvider(provider *Provider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}
	if provider.Scheme == "" {
		return fmt.Errorf("provider scheme is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers[provider.Scheme] = provider.clone()
	return nil
}

// DeleteProvider removes the record for scheme; absent is a no-op.
func (s *MemoryStore) DeleteProvider(scheme string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.providers, scheme)
	return nil
}
