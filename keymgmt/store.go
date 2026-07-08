// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt

import "sync"

// MemoryRecordStore is an in-memory RecordStore with an optimistic-concurrency
// marker. It is the default persistence when a host supplies no storage
// provider. All returned records are independent copies.
type MemoryRecordStore struct {
	mu      sync.Mutex
	records map[string]*Record
}

// NewMemoryRecordStore returns an empty in-memory store.
func NewMemoryRecordStore() *MemoryRecordStore {
	return &MemoryRecordStore{records: map[string]*Record{}}
}

func (s *MemoryRecordStore) List() ([]*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, copyRecord(r))
	}
	return out, nil
}

func (s *MemoryRecordStore) Get(handle string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[handle]
	if !ok {
		return nil, ErrRecordNotFound
	}
	return copyRecord(r), nil
}

func (s *MemoryRecordStore) Create(record *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.Handle]; ok {
		return ErrDuplicateKey
	}
	if s.publicIDInUse(record.PublicID, record.Handle) {
		return ErrDuplicateKey
	}
	stored := copyRecord(record)
	stored.Version = 1
	s.records[stored.Handle] = stored
	record.Version = 1
	return nil
}

func (s *MemoryRecordStore) Update(record *Record, expectedVersion uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[record.Handle]
	if !ok {
		return ErrRecordNotFound
	}
	if current.Version != expectedVersion {
		return ErrVersionConflict
	}
	stored := copyRecord(record)
	stored.Version = current.Version + 1
	s.records[stored.Handle] = stored
	record.Version = stored.Version
	return nil
}

func (s *MemoryRecordStore) Delete(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[handle]; !ok {
		return ErrRecordNotFound
	}
	delete(s.records, handle)
	return nil
}

// publicIDInUse reports whether a non-retired record other than exceptHandle
// already publishes publicID. Retired keys no longer appear in JWKS, so their
// public ids do not block reuse.
func (s *MemoryRecordStore) publicIDInUse(publicID, exceptHandle string) bool {
	for handle, r := range s.records {
		if handle == exceptHandle {
			continue
		}
		if r.Phase == PhaseRetired {
			continue
		}
		if r.PublicID == publicID {
			return true
		}
	}
	return false
}
