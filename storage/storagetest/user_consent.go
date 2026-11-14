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

// RunUserConsentStoreSuite runs the conformance suite for a
// storage.UserConsentStore. newStore must return a fresh empty store on each
// call.
func RunUserConsentStoreSuite(t *testing.T, newStore func() storage.UserConsentStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.GetUserConsent(cancelledContext(), "absent-subject", "client-a")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		consent := newConsent("subject-1", "client-a")
		err := store.StoreUserConsent(cancelledContext(), consent)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.GetUserConsent(context.Background(), "subject-1", "client-a")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetUserConsent(context.Background(), "absent-subject", "client-a")
		if got != nil {
			t.Fatalf("Get(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "EmptyListReturnsEmptySlice", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetAllUserConsents(context.Background(), "absent-subject")
		if err != nil {
			t.Fatalf("GetAllUserConsents: %v", err)
		}
		expectEmptySlice(t, got)
	})
	mustCase(t, "UpsertReplacesBySubjectClient", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newConsent("subject-1", "client-a")
		first.Scopes = []string{"scope-1"}
		if err := store.StoreUserConsent(context.Background(), first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := newConsent("subject-1", "client-a")
		second.Scopes = []string{"scope-2"}
		if err := store.StoreUserConsent(context.Background(), second); err != nil {
			t.Fatalf("second store: %v", err)
		}
		got, err := store.GetUserConsent(context.Background(), "subject-1", "client-a")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(got.Scopes) != 1 || got.Scopes[0] != "scope-2" {
			t.Fatalf("stored Scopes = %v, want [scope-2]", got.Scopes)
		}
	})
	mustCase(t, "ExpiredRecordStillReadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		consent := newConsent("subject-1", "client-a")
		consent.Expiration = &fixedExpired
		if err := store.StoreUserConsent(context.Background(), consent); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.GetUserConsent(context.Background(), "subject-1", "client-a")
		if err != nil {
			t.Fatalf("expired consent not readable: %v", err)
		}
		if got == nil || got.ClientId != "client-a" {
			t.Fatalf("Get(expired) = %v, want the stored consent", got)
		}
	})
	mustCase(t, "RemoveExpiredReclaimsExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newConsent("subject-1", "client-a")
		expired.Expiration = &fixedExpired
		alive := newConsent("subject-2", "client-a")
		alive.Expiration = &fixedAlive
		boundary := newConsent("subject-3", "client-a")
		boundary.Expiration = &fixedNow
		noExpiry := newConsent("subject-4", "client-a")
		for _, c := range []*models.Consent{expired, alive, boundary, noExpiry} {
			if err := store.StoreUserConsent(context.Background(), c); err != nil {
				t.Fatalf("store: %v", err)
			}
		}
		count, err := store.RemoveExpired(context.Background(), fixedNow)
		if err != nil {
			t.Fatalf("RemoveExpired: %v", err)
		}
		if count != 1 {
			t.Fatalf("RemoveExpired count = %d, want 1", count)
		}
		if _, err := store.GetUserConsent(context.Background(), "subject-1", "client-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired consent still present: %v", err)
		}
		if _, err := store.GetUserConsent(context.Background(), "subject-2", "client-a"); err != nil {
			t.Fatalf("alive consent removed: %v", err)
		}
		if _, err := store.GetUserConsent(context.Background(), "subject-3", "client-a"); err != nil {
			t.Fatalf("boundary consent removed: %v", err)
		}
		if _, err := store.GetUserConsent(context.Background(), "subject-4", "client-a"); err != nil {
			t.Fatalf("consent without expiration removed: %v", err)
		}
	})
	mustCase(t, "ListReturnsSubjectConsents", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for _, c := range []*models.Consent{
			newConsent("subject-1", "client-a"),
			newConsent("subject-1", "client-b"),
			newConsent("subject-2", "client-a"),
		} {
			if err := store.StoreUserConsent(context.Background(), c); err != nil {
				t.Fatalf("store: %v", err)
			}
		}
		got, err := store.GetAllUserConsents(context.Background(), "subject-1")
		if err != nil {
			t.Fatalf("GetAllUserConsents: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("GetAllUserConsents(subject-1) len = %d, want 2", len(got))
		}
		clients := map[string]bool{}
		for _, c := range got {
			clients[c.ClientId] = true
		}
		if !clients["client-a"] || !clients["client-b"] {
			t.Fatalf("GetAllUserConsents(subject-1) clients = %v, want client-a and client-b", clients)
		}
	})
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.UserConsentStore) {
			_ = store.StoreUserConsent(context.Background(), newConsent("subject-1", "client-a"))
			_, _ = store.GetUserConsent(context.Background(), "subject-1", "client-a")
			_, _ = store.RemoveExpired(context.Background(), fixedNow)
			_ = store.RemoveUserConsent(context.Background(), "subject-1", "client-a")
		})
	})
	mustCase(t, "RemoveByClientIsolated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for _, c := range []*models.Consent{
			newConsent("subject-1", "client-a"),
			newConsent("subject-2", "client-a"),
			newConsent("subject-1", "client-b"),
		} {
			if err := store.StoreUserConsent(context.Background(), c); err != nil {
				t.Fatalf("store: %v", err)
			}
		}
		count, err := store.RemoveUserConsentsByClient(context.Background(), "client-a")
		expectRemovedCount(t, count, err, 2)
		for _, subject := range []string{"subject-1", "subject-2"} {
			_, err := store.GetUserConsent(context.Background(), subject, "client-a")
			expectNotFound(t, err)
		}
		if _, err := store.GetUserConsent(context.Background(), "subject-1", "client-b"); err != nil {
			t.Fatalf("other client consent removed: %v", err)
		}
		count, err = store.RemoveUserConsentsByClient(context.Background(), "client-a")
		expectRemovedCount(t, count, err, 0)
	})
	mustCase(t, "ScopedRemoveEmptyArgumentMatchesNothing", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreUserConsent(context.Background(), newConsent("subject-1", "")); err != nil {
			t.Fatalf("store: %v", err)
		}
		count, err := store.RemoveUserConsentsByClient(context.Background(), "")
		expectRemovedCount(t, count, err, 0)
		if _, err := store.GetUserConsent(context.Background(), "subject-1", ""); err != nil {
			t.Fatalf("consent with empty client removed by empty argument: %v", err)
		}
	})
	mustCase(t, "RemoveMissingHandleSucceeds", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreUserConsent(context.Background(), newConsent("subject-1", "client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if err := store.RemoveUserConsent(context.Background(), "absent-subject", "client-a"); err != nil {
			t.Fatalf("Remove(missing) = %v, want nil", err)
		}
		if err := store.RemoveUserConsent(context.Background(), "subject-1", "client-a"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if err := store.RemoveUserConsent(context.Background(), "subject-1", "client-a"); err != nil {
			t.Fatalf("Remove(already removed) = %v, want nil", err)
		}
	})
	mustCase(t, "NoBackgroundGoroutinesScopedRemoval", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.UserConsentStore) {
			_ = store.StoreUserConsent(context.Background(), newConsent("subject-1", "client-a"))
			_, _ = store.RemoveUserConsentsByClient(context.Background(), "client-a")
		})
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newConsent(subjectId, clientId string) *models.Consent {
	return &models.Consent{
		SubjectId:    subjectId,
		ClientId:     clientId,
		Scopes:       []string{"openid", "profile"},
		CreationTime: fixedNow,
		Expiration:   &fixedAlive,
	}
}
