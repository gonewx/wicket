// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"context"
	"errors"
	"testing"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// RunPersistedGrantStoreSuite runs the conformance suite for a
// storage.PersistedGrantStore. newStore must return a fresh empty store on
// each call.
func RunPersistedGrantStoreSuite(t *testing.T, newStore func() storage.PersistedGrantStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.Get(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		grant := newPersistedGrant("key-1", "subject-1")
		err := store.Store(cancelledContext(), grant)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.Get(context.Background(), "key-1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.Get(context.Background(), "missing")
		if got != nil {
			t.Fatalf("Get(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "EmptyListReturnsEmptySlice", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetAll(context.Background(), &storage.PersistedGrantFilter{SubjectId: "nobody"})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		expectEmptySlice(t, got)
	})
	mustCase(t, "UpsertReplacesByKey", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newPersistedGrant("key-1", "subject-1")
		first.Data = []byte("first")
		if err := store.Store(context.Background(), first); err != nil {
			t.Fatalf("first Store: %v", err)
		}
		second := newPersistedGrant("key-1", "subject-1")
		second.Data = []byte("second")
		if err := store.Store(context.Background(), second); err != nil {
			t.Fatalf("second Store: %v", err)
		}
		got, err := store.Get(context.Background(), "key-1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got.Data) != "second" {
			t.Fatalf("stored Data = %q, want %q", got.Data, "second")
		}
	})
	mustCase(t, "ExpiredRecordStillReadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newPersistedGrant("key-1", "subject-1")
		expired.Expiration = &fixedExpired
		if err := store.Store(context.Background(), expired); err != nil {
			t.Fatalf("Store: %v", err)
		}
		got, err := store.Get(context.Background(), "key-1")
		if err != nil {
			t.Fatalf("expired grant not readable: %v", err)
		}
		if got == nil || got.Key != "key-1" {
			t.Fatalf("Get(expired) = %v, want the stored grant", got)
		}
	})
	mustCase(t, "RemoveExpiredReclaimsExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newPersistedGrant("expired", "subject-1")
		expired.Expiration = &fixedExpired
		alive := newPersistedGrant("alive", "subject-1")
		alive.Expiration = &fixedAlive
		boundary := newPersistedGrant("boundary", "subject-1")
		boundary.Expiration = &fixedNow
		noExpiry := newPersistedGrant("no-expiry", "subject-1")
		for _, g := range []*models.PersistedGrant{expired, alive, boundary, noExpiry} {
			if err := store.Store(context.Background(), g); err != nil {
				t.Fatalf("Store %s: %v", g.Key, err)
			}
		}
		count, err := store.RemoveExpired(context.Background(), fixedNow)
		if err != nil {
			t.Fatalf("RemoveExpired: %v", err)
		}
		if count != 1 {
			t.Fatalf("RemoveExpired count = %d, want 1", count)
		}
		if _, err := store.Get(context.Background(), "expired"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired grant still present: %v", err)
		}
		if _, err := store.Get(context.Background(), "alive"); err != nil {
			t.Fatalf("alive grant removed: %v", err)
		}
		if _, err := store.Get(context.Background(), "boundary"); err != nil {
			t.Fatalf("boundary grant removed: %v", err)
		}
		if _, err := store.Get(context.Background(), "no-expiry"); err != nil {
			t.Fatalf("grant without expiration removed: %v", err)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7009 (token revocation
	// is a host-driven removal by subject and client; the store must remove
	// exactly the matching records).
	mustCase(t, "GetAllFiltersExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		subj1 := newPersistedGrant("key-a", "subject-1")
		subj1.ClientId = "client-a"
		subj1.Type = "refresh_token"
		subj2 := newPersistedGrant("key-b", "subject-2")
		subj2.ClientId = "client-b"
		subj2.Type = "authorization_code"
		for _, g := range []*models.PersistedGrant{subj1, subj2} {
			if err := store.Store(context.Background(), g); err != nil {
				t.Fatalf("Store: %v", err)
			}
		}
		got, err := store.GetAll(context.Background(), &storage.PersistedGrantFilter{SubjectId: "subject-1"})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		if len(got) != 1 || got[0].Key != "key-a" {
			t.Fatalf("GetAll(subject-1) = %v, want only key-a", got)
		}
		got, err = store.GetAll(context.Background(), &storage.PersistedGrantFilter{ClientId: "client-b"})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		if len(got) != 1 || got[0].Key != "key-b" {
			t.Fatalf("GetAll(client-b) = %v, want only key-b", got)
		}
	})
	mustCase(t, "RemoveDeletesByKey", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.Store(context.Background(), newPersistedGrant("key-1", "subject-1")); err != nil {
			t.Fatalf("Store: %v", err)
		}
		if err := store.Remove(context.Background(), "key-1"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		_, err := store.Get(context.Background(), "key-1")
		expectNotFound(t, err)
	})
	mustCase(t, "RemoveAllRevokesByFilter", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		match := newPersistedGrant("key-a", "subject-1")
		match.ClientId = "client-a"
		match.SessionId = "session-1"
		other := newPersistedGrant("key-b", "subject-2")
		other.ClientId = "client-b"
		other.SessionId = "session-1"
		for _, g := range []*models.PersistedGrant{match, other} {
			if err := store.Store(context.Background(), g); err != nil {
				t.Fatalf("Store: %v", err)
			}
		}
		filter := &storage.PersistedGrantFilter{SubjectId: "subject-1", ClientId: "client-a"}
		if err := store.RemoveAll(context.Background(), filter); err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}
		if _, err := store.Get(context.Background(), "key-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("matching grant still present: %v", err)
		}
		if _, err := store.Get(context.Background(), "key-b"); err != nil {
			t.Fatalf("non-matching grant removed: %v", err)
		}
	})
	cfg.mayCase(t, "CombinedFilter", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		subj1 := newPersistedGrant("key-a", "subject-1")
		subj1.ClientId = "client-a"
		subj1.Type = "refresh_token"
		subj2 := newPersistedGrant("key-b", "subject-1")
		subj2.ClientId = "client-b"
		subj2.Type = "refresh_token"
		for _, g := range []*models.PersistedGrant{subj1, subj2} {
			if err := store.Store(context.Background(), g); err != nil {
				t.Fatalf("Store: %v", err)
			}
		}
		got, err := store.GetAll(context.Background(), &storage.PersistedGrantFilter{
			SubjectId: "subject-1",
			ClientId:  "client-a",
			Type:      "refresh_token",
		})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		if len(got) != 1 || got[0].Key != "key-a" {
			t.Fatalf("combined GetAll = %v, want only key-a", got)
		}
	})
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.PersistedGrantStore) {
			grant := newPersistedGrant("key-1", "subject-1")
			_ = store.Store(context.Background(), grant)
			_, _ = store.Get(context.Background(), "key-1")
			_, _ = store.RemoveExpired(context.Background(), fixedNow)
			_ = store.Remove(context.Background(), "key-1")
		})
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newPersistedGrant(key, subject string) *models.PersistedGrant {
	return &models.PersistedGrant{
		Key:          key,
		Type:         "refresh_token",
		SubjectId:    subject,
		ClientId:     "client",
		CreationTime: fixedNow,
		Expiration:   &fixedAlive,
		Data:         []byte("payload"),
	}
}
