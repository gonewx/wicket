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

// clientRegistrationRecord is one stored registration: the client as the
// opaque bytes of storage.EncodeClient next to the visible fields.
type clientRegistrationRecord struct {
	client                        []byte
	revision                      int
	registrationAccessTokenDigest string
	registrationTime              time.Time
}

// MemoryClientRegistrationStore keeps client registrations in process memory.
// It implements storage.ClientRegistrationStore and storage.ClientOriginLookup
// on the same data. Every read decodes a fresh copy, so a caller changing a
// returned client does not change the store.
type MemoryClientRegistrationStore struct {
	mu         sync.Mutex
	records    map[string]*clientRegistrationRecord
	tombstones map[string]struct{}
}

var (
	_ storage.ClientRegistrationStore = (*MemoryClientRegistrationStore)(nil)
	_ storage.ClientOriginLookup      = (*MemoryClientRegistrationStore)(nil)
)

// NewMemoryClientRegistrationStore returns an empty store.
func NewMemoryClientRegistrationStore() *MemoryClientRegistrationStore {
	return &MemoryClientRegistrationStore{
		records:    map[string]*clientRegistrationRecord{},
		tombstones: map[string]struct{}{},
	}
}

func registrationClientId(registration *models.ClientRegistration) (string, error) {
	if registration == nil || registration.Client == nil {
		return "", errors.New("memory: client registration carries no client")
	}
	if registration.Client.ClientId == "" {
		return "", errors.New("memory: client registration carries no client id")
	}
	return registration.Client.ClientId, nil
}

func encodeRegistration(registration *models.ClientRegistration, revision int) (*clientRegistrationRecord, error) {
	data, err := storage.EncodeClient(registration.Client)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}
	return &clientRegistrationRecord{
		client:                        data,
		revision:                      revision,
		registrationAccessTokenDigest: registration.RegistrationAccessTokenDigest,
		registrationTime:              registration.RegistrationTime,
	}, nil
}

func (r *clientRegistrationRecord) decode() (*models.ClientRegistration, error) {
	client, err := storage.DecodeClient(r.client)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}
	return &models.ClientRegistration{
		Client:                        client,
		Revision:                      r.revision,
		RegistrationAccessTokenDigest: r.registrationAccessTokenDigest,
		RegistrationTime:              r.registrationTime,
	}, nil
}

// RegisterClient stores a new registration under its client id and returns
// revision 1. A registered or removed client id fails with
// storage.ErrDuplicateHandle.
func (s *MemoryClientRegistrationStore) RegisterClient(ctx context.Context, registration *models.ClientRegistration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	clientId, err := registrationClientId(registration)
	if err != nil {
		return 0, err
	}
	record, err := encodeRegistration(registration, 1)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[clientId]; ok {
		return 0, fmt.Errorf("memory: register client %q: %w", clientId, storage.ErrDuplicateHandle)
	}
	if _, ok := s.tombstones[clientId]; ok {
		return 0, fmt.Errorf("memory: register removed client %q: %w", clientId, storage.ErrDuplicateHandle)
	}
	s.records[clientId] = record
	return record.revision, nil
}

// FindClientRegistration returns a fresh copy of the registration of a
// client id, or storage.ErrNotFound.
func (s *MemoryClientRegistrationStore) FindClientRegistration(ctx context.Context, clientId string) (*models.ClientRegistration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	record, ok := s.records[clientId]
	s.mu.Unlock()
	if !ok {
		return nil, storage.ErrNotFound
	}
	return record.decode()
}

// FindClientById returns a fresh copy of the registered client, or
// storage.ErrNotFound.
func (s *MemoryClientRegistrationStore) FindClientById(ctx context.Context, clientId string) (*models.Client, error) {
	registration, err := s.FindClientRegistration(ctx, clientId)
	if err != nil {
		return nil, err
	}
	return registration.Client, nil
}

// UpdateClientRegistration replaces the registration of its client id when
// the stored revision equals expectedRevision and returns the new revision.
func (s *MemoryClientRegistrationStore) UpdateClientRegistration(ctx context.Context, registration *models.ClientRegistration, expectedRevision int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	clientId, err := registrationClientId(registration)
	if err != nil {
		return 0, err
	}
	record, err := encodeRegistration(registration, expectedRevision+1)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[clientId]
	if !ok {
		return 0, storage.ErrNotFound
	}
	if current.revision != expectedRevision {
		return 0, fmt.Errorf("memory: update client %q: stored revision %d, expected %d: %w", clientId, current.revision, expectedRevision, storage.ErrVersionConflict)
	}
	s.records[clientId] = record
	return record.revision, nil
}

// RemoveClientRegistration removes the registration of a client id when the
// stored revision equals expectedRevision and leaves a tombstone.
func (s *MemoryClientRegistrationStore) RemoveClientRegistration(ctx context.Context, clientId string, expectedRevision int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[clientId]
	if !ok {
		return storage.ErrNotFound
	}
	if current.revision != expectedRevision {
		return fmt.Errorf("memory: remove client %q: stored revision %d, expected %d: %w", clientId, current.revision, expectedRevision, storage.ErrVersionConflict)
	}
	delete(s.records, clientId)
	s.tombstones[clientId] = struct{}{}
	return nil
}

// FindClientsByAllowedOrigin returns fresh copies of the registered clients
// whose AllowedCorsOrigins contain origin exactly, without filtering on
// Enabled. A miss returns an empty slice.
func (s *MemoryClientRegistrationStore) FindClientsByAllowedOrigin(ctx context.Context, origin string) ([]*models.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	encoded := make([][]byte, 0, len(s.records))
	for _, record := range s.records {
		encoded = append(encoded, record.client)
	}
	s.mu.Unlock()

	matches := []*models.Client{}
	for _, data := range encoded {
		client, err := storage.DecodeClient(data)
		if err != nil {
			return nil, fmt.Errorf("memory: %w", err)
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
