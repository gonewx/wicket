// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// MemoryPushedAuthorizationRequestStore keeps pushed authorization requests
// in process memory. It implements storage.PushedAuthorizationRequestStore.
// Writes keep a copy and reads return a copy, so a caller changing a record
// or its Payload does not change the store.
type MemoryPushedAuthorizationRequestStore struct {
	mu      sync.Mutex
	records map[string]*models.PushedAuthorizationRequest
}

var _ storage.PushedAuthorizationRequestStore = (*MemoryPushedAuthorizationRequestStore)(nil)

// NewMemoryPushedAuthorizationRequestStore returns an empty store.
func NewMemoryPushedAuthorizationRequestStore() *MemoryPushedAuthorizationRequestStore {
	return &MemoryPushedAuthorizationRequestStore{records: map[string]*models.PushedAuthorizationRequest{}}
}

func copyPushedAuthorizationRequest(request *models.PushedAuthorizationRequest) *models.PushedAuthorizationRequest {
	clone := *request
	clone.Payload = append([]byte(nil), request.Payload...)
	return &clone
}

// StorePushedAuthorizationRequest stores a copy of request under key. An
// existing key fails with storage.ErrDuplicateHandle.
func (s *MemoryPushedAuthorizationRequestStore) StorePushedAuthorizationRequest(ctx context.Context, key string, request *models.PushedAuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if request == nil {
		return errors.New("memory: store pushed authorization request: nil request")
	}
	record := copyPushedAuthorizationRequest(request)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[key]; ok {
		return fmt.Errorf("memory: store pushed authorization request: %w", storage.ErrDuplicateHandle)
	}
	s.records[key] = record
	return nil
}

// GetPushedAuthorizationRequest returns a copy of the request stored under
// key, or storage.ErrNotFound.
func (s *MemoryPushedAuthorizationRequestStore) GetPushedAuthorizationRequest(ctx context.Context, key string) (*models.PushedAuthorizationRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return copyPushedAuthorizationRequest(record), nil
}

// TakePushedAuthorizationRequest removes the request stored under key and
// returns it, or storage.ErrNotFound. Lookup and removal happen under one
// lock, so concurrent takes of a key yield the record exactly once.
func (s *MemoryPushedAuthorizationRequestStore) TakePushedAuthorizationRequest(ctx context.Context, key string) (*models.PushedAuthorizationRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(s.records, key)
	return copyPushedAuthorizationRequest(record), nil
}

// RemoveExpired removes the requests whose RetentionExpiration precedes
// cutoff and returns how many were removed.
func (s *MemoryPushedAuthorizationRequestStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, record := range s.records {
		if record.RetentionExpiration.Before(cutoff) {
			delete(s.records, key)
			removed++
		}
	}
	return removed, nil
}
