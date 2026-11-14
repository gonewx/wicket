// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// sentinelRefreshStore reports every record as missing.
type sentinelRefreshStore struct{}

func (sentinelRefreshStore) StoreRefreshToken(context.Context, string, *models.RefreshToken) error {
	return storage.ErrNotFound
}
func (sentinelRefreshStore) GetRefreshToken(context.Context, string) (*models.RefreshToken, error) {
	return nil, storage.ErrNotFound
}
func (sentinelRefreshStore) UpdateRefreshToken(context.Context, string, *models.RefreshToken, int) error {
	return storage.ErrNotFound
}
func (sentinelRefreshStore) RemoveRefreshToken(context.Context, string) error {
	return storage.ErrNotFound
}
func (sentinelRefreshStore) RemoveRefreshTokensByClient(context.Context, string) (int, error) {
	return 0, nil
}
func (sentinelRefreshStore) RemoveRefreshTokensBySession(context.Context, string) (int, error) {
	return 0, nil
}
func (sentinelRefreshStore) RemoveExpired(context.Context, time.Time) (int, error) {
	return 0, storage.ErrNotFound
}

// failingRefreshStore returns an infrastructure error distinct from the
// not-found sentinel, so the merge-point split can be pinned: only a miss maps
// to the not-found outcome, everything else surfaces as the wrapped error.
type failingRefreshStore struct{}

func (failingRefreshStore) StoreRefreshToken(context.Context, string, *models.RefreshToken) error {
	return errors.New("store unavailable")
}
func (failingRefreshStore) GetRefreshToken(context.Context, string) (*models.RefreshToken, error) {
	return nil, errors.New("store unavailable")
}
func (failingRefreshStore) UpdateRefreshToken(context.Context, string, *models.RefreshToken, int) error {
	return errors.New("store unavailable")
}
func (failingRefreshStore) RemoveRefreshToken(context.Context, string) error {
	return errors.New("store unavailable")
}
func (failingRefreshStore) RemoveRefreshTokensByClient(context.Context, string) (int, error) {
	return 0, errors.New("store unavailable")
}
func (failingRefreshStore) RemoveRefreshTokensBySession(context.Context, string) (int, error) {
	return 0, errors.New("store unavailable")
}
func (failingRefreshStore) RemoveExpired(context.Context, time.Time) (int, error) {
	return 0, errors.New("store unavailable")
}

func TestRefreshTokenValidationDistinguishesMissFromFailure(t *testing.T) {
	t.Parallel()

	client := models.NewClient()

	t.Run("miss maps to not-found outcome", func(t *testing.T) {
		t.Parallel()
		service := NewRefreshTokenService(&sentinelRefreshStore{}, NewHandleGenerationService())
		result := service.ValidateRefreshToken(context.Background(), "missing", client)
		if result.Error == nil || !errors.Is(result.Error, storage.ErrNotFound) {
			t.Fatalf("miss error = %v, want wrapped storage.ErrNotFound", result.Error)
		}
	})

	t.Run("infrastructure failure surfaces as wrapped error", func(t *testing.T) {
		t.Parallel()
		service := NewRefreshTokenService(failingRefreshStore{}, NewHandleGenerationService())
		result := service.ValidateRefreshToken(context.Background(), "handle", client)
		if result.Error == nil || errors.Is(result.Error, storage.ErrNotFound) {
			t.Fatalf("infrastructure error = %v, want non-not-found wrapped error", result.Error)
		}
	})
}
