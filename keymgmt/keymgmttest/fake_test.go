// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmttest

import (
	"context"
	"sync"
	"testing"

	"github.com/gonewx/wicket/keymgmt"
)

// fakeRecordStore is a minimal in-memory adapter written alongside the suite
// as an independent reference. It implements the port contract without
// sharing code with the production store: insert-only create with
// ErrDuplicateKey, optimistic-concurrency update with ErrVersionConflict,
// sentinel misses, deep-copied returns, and no reclamation surface.
type fakeRecordStore struct {
	mu      sync.Mutex
	records map[string]*keymgmt.Record
}

func newFakeRecordStore() *fakeRecordStore {
	return &fakeRecordStore{records: make(map[string]*keymgmt.Record)}
}

func (s *fakeRecordStore) List(_ context.Context) ([]*keymgmt.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*keymgmt.Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, cloneRecord(r))
	}
	return out, nil
}

func (s *fakeRecordStore) Get(_ context.Context, handle string) (*keymgmt.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[handle]
	if !ok {
		return nil, keymgmt.ErrRecordNotFound
	}
	return cloneRecord(r), nil
}

func (s *fakeRecordStore) Create(_ context.Context, record *keymgmt.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.Handle]; ok {
		return keymgmt.ErrDuplicateKey
	}
	if s.publicIDInUse(record.PublicID, record.Handle) {
		return keymgmt.ErrDuplicateKey
	}
	stored := cloneRecord(record)
	stored.Version = 1
	s.records[stored.Handle] = stored
	record.Version = 1
	return nil
}

func (s *fakeRecordStore) Update(_ context.Context, record *keymgmt.Record, expectedVersion uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[record.Handle]
	if !ok {
		return keymgmt.ErrRecordNotFound
	}
	if current.Version != expectedVersion {
		return keymgmt.ErrVersionConflict
	}
	stored := cloneRecord(record)
	stored.Version = current.Version + 1
	s.records[stored.Handle] = stored
	record.Version = stored.Version
	return nil
}

func (s *fakeRecordStore) Delete(_ context.Context, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[handle]; !ok {
		return keymgmt.ErrRecordNotFound
	}
	delete(s.records, handle)
	return nil
}

func (s *fakeRecordStore) publicIDInUse(publicID, exceptHandle string) bool {
	for handle, r := range s.records {
		if handle == exceptHandle {
			continue
		}
		if r.Phase == keymgmt.PhaseRetired {
			continue
		}
		if r.PublicID == publicID {
			return true
		}
	}
	return false
}

func cloneRecord(r *keymgmt.Record) *keymgmt.Record {
	clone := *r
	clone.PublicMaterial = append([]byte(nil), r.PublicMaterial...)
	clone.ProtectedPrivateMaterial = append([]byte(nil), r.ProtectedPrivateMaterial...)
	return &clone
}

// TestFakeRecordStoreConformanceE2E runs the full suite against an
// independent minimal adapter, MUST and MAY alike. This is the reference run
// the discriminative rounds below must stay green on.
func TestFakeRecordStoreConformanceE2E(t *testing.T) {
	t.Parallel()
	RunRecordStoreSuite(t, func() keymgmt.RecordStore {
		return newFakeRecordStore()
	}, WithMay(true))
}
