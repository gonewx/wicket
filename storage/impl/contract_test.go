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

func TestAuthorizationCodeStoreMissReturnsSentinel(t *testing.T) {
	t.Parallel()

	store := NewAuthorizationCodeStore()
	_, err := store.GetAuthorizationCode(context.Background(), "missing")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get miss error = %v, want storage.ErrNotFound", err)
	}
}

func TestAuthorizationCodeStoreRemoveExpired(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewAuthorizationCodeStore()
	old := &models.AuthorizationCode{CreationTime: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Lifetime: 300}
	fresh := &models.AuthorizationCode{CreationTime: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC), Lifetime: 86400 * 4}
	oldHandle, err := store.StoreAuthorizationCode(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	freshHandle, err := store.StoreAuthorizationCode(context.Background(), fresh)
	if err != nil {
		t.Fatal(err)
	}

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("RemoveExpired count = %d, want 1", count)
	}
	if _, err := store.GetAuthorizationCode(context.Background(), oldHandle); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired code still present, err = %v", err)
	}
	if _, err := store.GetAuthorizationCode(context.Background(), freshHandle); err != nil {
		t.Fatalf("fresh code removed: %v", err)
	}
}

func TestRefreshTokenStoreRemoveExpiredAndSentinel(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewRefreshTokenStore()
	if _, err := store.GetRefreshToken(context.Background(), "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get miss error = %v, want storage.ErrNotFound", err)
	}

	old := &models.RefreshToken{CreationTime: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Lifetime: 300}
	fresh := &models.RefreshToken{CreationTime: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC), Lifetime: 86400 * 4}
	oldHandle, err := store.StoreRefreshToken(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	freshHandle, err := store.StoreRefreshToken(context.Background(), fresh)
	if err != nil {
		t.Fatal(err)
	}

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("RemoveExpired count = %d, want 1", count)
	}
	if _, err := store.GetRefreshToken(context.Background(), oldHandle); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired token still present, err = %v", err)
	}
	if _, err := store.GetRefreshToken(context.Background(), freshHandle); err != nil {
		t.Fatalf("fresh token removed: %v", err)
	}
}

func TestReferenceTokenStoreRemoveExpiredAndSentinel(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewReferenceTokenStore()
	if _, err := store.GetReferenceToken(context.Background(), "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get miss error = %v, want storage.ErrNotFound", err)
	}

	old := &models.Token{CreationTime: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Lifetime: 300}
	fresh := &models.Token{CreationTime: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC), Lifetime: 86400 * 4}
	oldHandle, err := store.StoreReferenceToken(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	freshHandle, err := store.StoreReferenceToken(context.Background(), fresh)
	if err != nil {
		t.Fatal(err)
	}

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("RemoveExpired count = %d, want 1", count)
	}
	if _, err := store.GetReferenceToken(context.Background(), oldHandle); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired token still present, err = %v", err)
	}
	if _, err := store.GetReferenceToken(context.Background(), freshHandle); err != nil {
		t.Fatalf("fresh token removed: %v", err)
	}
}

func TestUserConsentStoreRemoveExpiredAndSentinel(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewUserConsentStore()
	if _, err := store.GetUserConsent(context.Background(), "sub", "client"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get miss error = %v, want storage.ErrNotFound", err)
	}

	expired := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := store.StoreUserConsent(context.Background(), &models.Consent{SubjectId: "sub", ClientId: "expired", Expiration: &expired}); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreUserConsent(context.Background(), &models.Consent{SubjectId: "sub", ClientId: "kept", Expiration: &future}); err != nil {
		t.Fatal(err)
	}

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("RemoveExpired count = %d, want 1", count)
	}
	if _, err := store.GetUserConsent(context.Background(), "sub", "expired"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired consent still present, err = %v", err)
	}
	if _, err := store.GetUserConsent(context.Background(), "sub", "kept"); err != nil {
		t.Fatalf("future consent removed: %v", err)
	}
}

// TestExpiredRecordsStillReadable pins the expiry-judgement ownership contract:
// a read returns the record whether or not it is expired, because expiry is the
// core side's call and reclamation only reclaims space.
func TestExpiredRecordsStillReadable(t *testing.T) {
	t.Parallel()

	store := NewAuthorizationCodeStore()
	code := &models.AuthorizationCode{CreationTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Lifetime: 300}
	handle, err := store.StoreAuthorizationCode(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}

	got, err := store.GetAuthorizationCode(context.Background(), handle)
	if err != nil {
		t.Fatalf("Get expired record: %v", err)
	}
	if got == nil {
		t.Fatal("expired record read returned nil")
	}
}
