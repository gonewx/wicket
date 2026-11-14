// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// fakePushedAuthorizationRequestStore is a minimal independent pushed
// authorization request adapter: it shares nothing with the in-repo store
// and keeps each request as flat columns, the way a database row would.
type fakePushedAuthorizationRequestStore struct {
	mu   sync.Mutex
	rows map[string]fakePushedAuthorizationRequestRow
}

type fakePushedAuthorizationRequestRow struct {
	clientId  string
	created   time.Time
	entry     time.Time
	retention time.Time
	payload   []byte
}

func newFakePushedAuthorizationRequestStore() *fakePushedAuthorizationRequestStore {
	return &fakePushedAuthorizationRequestStore{rows: map[string]fakePushedAuthorizationRequestRow{}}
}

func (r fakePushedAuthorizationRequestRow) request() *models.PushedAuthorizationRequest {
	return &models.PushedAuthorizationRequest{
		ClientId:            r.clientId,
		CreationTime:        r.created,
		EntryExpiration:     r.entry,
		RetentionExpiration: r.retention,
		Payload:             append([]byte(nil), r.payload...),
	}
}

func (s *fakePushedAuthorizationRequestStore) StorePushedAuthorizationRequest(ctx context.Context, key string, request *models.PushedAuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[key]; ok {
		return storage.ErrDuplicateHandle
	}
	s.rows[key] = fakePushedAuthorizationRequestRow{
		clientId:  request.ClientId,
		created:   request.CreationTime,
		entry:     request.EntryExpiration,
		retention: request.RetentionExpiration,
		payload:   append([]byte(nil), request.Payload...),
	}
	return nil
}

func (s *fakePushedAuthorizationRequestStore) GetPushedAuthorizationRequest(ctx context.Context, key string) (*models.PushedAuthorizationRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return row.request(), nil
}

func (s *fakePushedAuthorizationRequestStore) TakePushedAuthorizationRequest(ctx context.Context, key string) (*models.PushedAuthorizationRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(s.rows, key)
	return row.request(), nil
}

func (s *fakePushedAuthorizationRequestStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, row := range s.rows {
		if row.retention.Before(cutoff) {
			delete(s.rows, key)
			removed++
		}
	}
	return removed, nil
}

func (s *fakePushedAuthorizationRequestStore) ConformsTo() string {
	return SuiteVersion
}

func TestFakePushedAuthorizationRequestStoreConformanceE2E(t *testing.T) {
	RunPushedAuthorizationRequestStoreSuite(t, func() storage.PushedAuthorizationRequestStore {
		return newFakePushedAuthorizationRequestStore()
	}, WithMay(true))
}
