// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"context"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// The fake adapters below are minimal independent store adapters. They
// serve two purposes: they prove the suite passes against an adapter that
// shares nothing with the in-repo stores, and they are the vehicles for the
// discriminative-power self-proof (each MUST case has a deliberately broken
// variant that the suite must catch).

type fakeAuthorizationCodeStore struct {
	items map[string]*models.AuthorizationCode
}

func newFakeAuthorizationCodeStore() *fakeAuthorizationCodeStore {
	return &fakeAuthorizationCodeStore{items: map[string]*models.AuthorizationCode{}}
}

func (s *fakeAuthorizationCodeStore) StoreAuthorizationCode(ctx context.Context, handle string, code *models.AuthorizationCode) error {
	if _, ok := s.items[handle]; ok {
		return storage.ErrDuplicateHandle
	}
	s.items[handle] = code
	return nil
}

func (s *fakeAuthorizationCodeStore) GetAuthorizationCode(ctx context.Context, handle string) (*models.AuthorizationCode, error) {
	code, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return code, nil
}

func (s *fakeAuthorizationCodeStore) RemoveAuthorizationCode(ctx context.Context, handle string) error {
	delete(s.items, handle)
	return nil
}

func (s *fakeAuthorizationCodeStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	count := 0
	for handle, code := range s.items {
		if code.CreationTime.Add(time.Duration(code.Lifetime) * time.Second).Before(cutoff) {
			delete(s.items, handle)
			count++
		}
	}
	return count, nil
}

type fakeRefreshTokenStore struct {
	items map[string]*models.RefreshToken
}

func newFakeRefreshTokenStore() *fakeRefreshTokenStore {
	return &fakeRefreshTokenStore{items: map[string]*models.RefreshToken{}}
}

func (s *fakeRefreshTokenStore) StoreRefreshToken(ctx context.Context, handle string, token *models.RefreshToken) error {
	if _, ok := s.items[handle]; ok {
		return storage.ErrDuplicateHandle
	}
	stored := *token
	stored.Version = 1
	s.items[handle] = &stored
	token.Version = 1
	return nil
}

func (s *fakeRefreshTokenStore) GetRefreshToken(ctx context.Context, handle string) (*models.RefreshToken, error) {
	token, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	stored := *token
	return &stored, nil
}

func (s *fakeRefreshTokenStore) UpdateRefreshToken(ctx context.Context, handle string, token *models.RefreshToken, expectedVersion int) error {
	current, ok := s.items[handle]
	if !ok {
		return storage.ErrNotFound
	}
	if current.Version != expectedVersion {
		return storage.ErrVersionConflict
	}
	stored := *token
	stored.Version = current.Version + 1
	s.items[handle] = &stored
	token.Version = stored.Version
	return nil
}

func (s *fakeRefreshTokenStore) RemoveRefreshToken(ctx context.Context, handle string) error {
	delete(s.items, handle)
	return nil
}

func (s *fakeRefreshTokenStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	count := 0
	for handle, token := range s.items {
		if token.CreationTime.Add(time.Duration(token.Lifetime) * time.Second).Before(cutoff) {
			delete(s.items, handle)
			count++
		}
	}
	return count, nil
}

// ConformsTo exercises the optional credential contract: an adapter that
// exposes the method must report the suite version it was verified against.
func (s *fakeRefreshTokenStore) ConformsTo() string {
	return SuiteVersion
}

// TestFakeAuthorizationCodeStoreConformanceE2E runs the full suite against an
// independent minimal adapter. This is the reference run the discriminative
// rounds below must stay green on.
func TestFakeAuthorizationCodeStoreConformanceE2E(t *testing.T) {
	RunAuthorizationCodeStoreSuite(t, func() storage.AuthorizationCodeStore {
		return newFakeAuthorizationCodeStore()
	}, WithMay(true))
}

func TestFakeRefreshTokenStoreConformanceE2E(t *testing.T) {
	RunRefreshTokenStoreSuite(t, func() storage.RefreshTokenStore {
		return newFakeRefreshTokenStore()
	}, WithMay(true))
}
