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

// fakeClientRegistrationStore is a minimal independent client registration
// adapter: it shares nothing with the in-repo store and keeps each client as
// the opaque codec bytes, the way a database adapter would.
type fakeClientRegistrationStore struct {
	mu      sync.Mutex
	rows    map[string]fakeClientRegistrationRow
	removed map[string]bool
}

type fakeClientRegistrationRow struct {
	data     []byte
	revision int
	digest   string
	at       time.Time
}

func newFakeClientRegistrationStore() *fakeClientRegistrationStore {
	return &fakeClientRegistrationStore{rows: map[string]fakeClientRegistrationRow{}, removed: map[string]bool{}}
}

func (s *fakeClientRegistrationStore) row(registration *models.ClientRegistration, revision int) (fakeClientRegistrationRow, error) {
	data, err := storage.EncodeClient(registration.Client)
	if err != nil {
		return fakeClientRegistrationRow{}, err
	}
	return fakeClientRegistrationRow{data: data, revision: revision, digest: registration.RegistrationAccessTokenDigest, at: registration.RegistrationTime}, nil
}

func (s *fakeClientRegistrationStore) RegisterClient(ctx context.Context, registration *models.ClientRegistration) (int, error) {
	row, err := s.row(registration, 1)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := registration.Client.ClientId
	if _, ok := s.rows[id]; ok || s.removed[id] {
		return 0, storage.ErrDuplicateHandle
	}
	s.rows[id] = row
	return 1, nil
}

func (s *fakeClientRegistrationStore) FindClientRegistration(ctx context.Context, clientId string) (*models.ClientRegistration, error) {
	s.mu.Lock()
	row, ok := s.rows[clientId]
	s.mu.Unlock()
	if !ok {
		return nil, storage.ErrNotFound
	}
	client, err := storage.DecodeClient(row.data)
	if err != nil {
		return nil, err
	}
	return &models.ClientRegistration{Client: client, Revision: row.revision, RegistrationAccessTokenDigest: row.digest, RegistrationTime: row.at}, nil
}

func (s *fakeClientRegistrationStore) FindClientById(ctx context.Context, clientId string) (*models.Client, error) {
	registration, err := s.FindClientRegistration(ctx, clientId)
	if err != nil {
		return nil, err
	}
	return registration.Client, nil
}

func (s *fakeClientRegistrationStore) UpdateClientRegistration(ctx context.Context, registration *models.ClientRegistration, expectedRevision int) (int, error) {
	row, err := s.row(registration, expectedRevision+1)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.rows[registration.Client.ClientId]
	if !ok {
		return 0, storage.ErrNotFound
	}
	if current.revision != expectedRevision {
		return 0, storage.ErrVersionConflict
	}
	s.rows[registration.Client.ClientId] = row
	return row.revision, nil
}

func (s *fakeClientRegistrationStore) RemoveClientRegistration(ctx context.Context, clientId string, expectedRevision int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.rows[clientId]
	if !ok {
		return storage.ErrNotFound
	}
	if current.revision != expectedRevision {
		return storage.ErrVersionConflict
	}
	delete(s.rows, clientId)
	s.removed[clientId] = true
	return nil
}

func (s *fakeClientRegistrationStore) FindClientsByAllowedOrigin(ctx context.Context, origin string) ([]*models.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	matches := []*models.Client{}
	for _, row := range s.rows {
		client, err := storage.DecodeClient(row.data)
		if err != nil {
			return nil, err
		}
		for _, allowed := range client.AllowedCorsOrigins {
			if allowed == origin {
				matches = append(matches, client)
				break
			}
		}
	}
	return matches, nil
}

func (s *fakeClientRegistrationStore) ConformsTo() string {
	return SuiteVersion
}

func TestFakeClientRegistrationStoreConformanceE2E(t *testing.T) {
	RunClientRegistrationStoreSuite(t, func() storage.ClientRegistrationStore {
		return newFakeClientRegistrationStore()
	}, WithMay(true))
}
