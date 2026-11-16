// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// RunRefreshTokenStoreSuite runs the conformance suite for a
// storage.RefreshTokenStore. newStore must return a fresh empty store on each
// call.
func RunRefreshTokenStoreSuite(t *testing.T, newStore func() storage.RefreshTokenStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.GetRefreshToken(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		token := newRefreshToken("client-a")
		err := store.StoreRefreshToken(cancelledContext(), "handle-1", token)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.GetRefreshToken(context.Background(), "handle-1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetRefreshToken(context.Background(), "missing")
		if got != nil {
			t.Fatalf("Get(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "DuplicateHandleRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newRefreshToken("client-a")
		if err := store.StoreRefreshToken(context.Background(), "handle-1", first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := newRefreshToken("client-b")
		if err := store.StoreRefreshToken(context.Background(), "handle-1", second); !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("second store error = %v, want ErrDuplicateHandle", err)
		}
		got, err := store.GetRefreshToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Get after collision: %v", err)
		}
		if got.ClientId != "client-a" {
			t.Fatalf("stored ClientId = %q, want original %q", got.ClientId, "client-a")
		}
	})
	mustCase(t, "VersionConflictKeepsRecord", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		original := newRefreshToken("client-a")
		if err := store.StoreRefreshToken(context.Background(), "handle-1", original); err != nil {
			t.Fatalf("store: %v", err)
		}
		update := newRefreshToken("client-b")
		err := store.UpdateRefreshToken(context.Background(), "handle-1", update, 99)
		if !errors.Is(err, storage.ErrVersionConflict) {
			t.Fatalf("update with wrong version = %v, want ErrVersionConflict", err)
		}
		got, err := store.GetRefreshToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Get after conflict: %v", err)
		}
		if got.ClientId != "client-a" {
			t.Fatalf("stored ClientId = %q, want original %q", got.ClientId, "client-a")
		}
	})
	mustCase(t, "VersionIncrementsAndWritesBack", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		original := newRefreshToken("client-a")
		if err := store.StoreRefreshToken(context.Background(), "handle-1", original); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.GetRefreshToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Version != 1 {
			t.Fatalf("stored Version after store = %d, want 1", got.Version)
		}
		rotated := newRefreshToken("client-a")
		if err := store.UpdateRefreshToken(context.Background(), "handle-1", rotated, 1); err != nil {
			t.Fatalf("update: %v", err)
		}
		if rotated.Version != 2 {
			t.Fatalf("caller Version after update = %d, want 2", rotated.Version)
		}
		got, err = store.GetRefreshToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if got.Version != 2 {
			t.Fatalf("stored Version after update = %d, want 2", got.Version)
		}
	})
	mustCase(t, "ExpiredRecordStillReadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		token := newRefreshToken("client-a")
		token.CreationTime = fixedExpired
		token.Lifetime = 60
		if err := store.StoreRefreshToken(context.Background(), "handle-1", token); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.GetRefreshToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("expired token not readable: %v", err)
		}
		if got == nil || got.ClientId != "client-a" {
			t.Fatalf("Get(expired) = %v, want the stored token", got)
		}
	})
	mustCase(t, "RemoveExpiredReclaimsExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newRefreshToken("client-a")
		expired.CreationTime = fixedExpired
		expired.Lifetime = 60
		alive := newRefreshToken("client-b")
		alive.CreationTime = fixedAlive
		alive.Lifetime = 3600
		boundary := newRefreshToken("client-c")
		boundary.CreationTime = fixedNow.Add(-60 * time.Second)
		boundary.Lifetime = 60
		for _, tok := range []*models.RefreshToken{expired, alive, boundary} {
			if err := store.StoreRefreshToken(context.Background(), tok.ClientId, tok); err != nil {
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
		if _, err := store.GetRefreshToken(context.Background(), "client-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired token still present: %v", err)
		}
		if _, err := store.GetRefreshToken(context.Background(), "client-b"); err != nil {
			t.Fatalf("alive token removed: %v", err)
		}
		if _, err := store.GetRefreshToken(context.Background(), "client-c"); err != nil {
			t.Fatalf("boundary token removed: %v", err)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7009 (revocation)
	// and https://www.rfc-editor.org/rfc/rfc6749#section-6 (rotation).
	// Revocation removes the token entirely; a later lookup must miss.
	mustCase(t, "RevocationRemovesToken", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreRefreshToken(context.Background(), "handle-1", newRefreshToken("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if err := store.RemoveRefreshToken(context.Background(), "handle-1"); err != nil {
			t.Fatalf("remove: %v", err)
		}
		_, err := store.GetRefreshToken(context.Background(), "handle-1")
		expectNotFound(t, err)
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2
	// The storage face of the rotation replay defense: once a token has been
	// rotated, updating with a stale expected version must fail.
	cfg.mayCase(t, "RotationReplayBlocked", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreRefreshToken(context.Background(), "handle-1", newRefreshToken("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if err := store.UpdateRefreshToken(context.Background(), "handle-1", newRefreshToken("client-a"), 1); err != nil {
			t.Fatalf("first rotation: %v", err)
		}
		err := store.UpdateRefreshToken(context.Background(), "handle-1", newRefreshToken("client-a"), 1)
		if !errors.Is(err, storage.ErrVersionConflict) {
			t.Fatalf("replay update error = %v, want ErrVersionConflict", err)
		}
	})
	// The core dates a refresh token stored without a creation time on its
	// first successful redemption, and under sliding expiration rewrites its
	// lifetime on every redemption; both reach the store through an update.
	// The update must therefore write CreationTime and Lifetime back, and
	// RemoveExpired must judge the record by the updated values.
	cfg.mayCase(t, "LifetimeUpdateRoundTrips", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreRefreshToken(context.Background(), "handle-1", newRefreshToken("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		stored, err := store.GetRefreshToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Get after store: %v", err)
		}
		oldExpiry := stored.CreationTime.Add(time.Duration(stored.Lifetime) * time.Second)

		created := fixedNow.Add(30 * time.Minute)
		const lifetime = 7200
		update := newRefreshToken("client-a")
		update.CreationTime = created
		update.Lifetime = lifetime
		if err := store.UpdateRefreshToken(context.Background(), "handle-1", update, stored.Version); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := store.GetRefreshToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if !got.CreationTime.Equal(created) {
			t.Fatalf("CreationTime = %v, want %v", got.CreationTime, created)
		}
		if got.Lifetime != lifetime {
			t.Fatalf("Lifetime = %d, want %d", got.Lifetime, lifetime)
		}

		newExpiry := created.Add(lifetime * time.Second)
		if !newExpiry.After(oldExpiry) {
			t.Fatalf("fixture: updated expiry %v is not after the stored expiry %v", newExpiry, oldExpiry)
		}
		cutoff := oldExpiry.Add(newExpiry.Sub(oldExpiry) / 2)
		removed, err := store.RemoveExpired(context.Background(), cutoff)
		if err != nil {
			t.Fatalf("RemoveExpired: %v", err)
		}
		if removed != 0 {
			t.Fatalf("RemoveExpired between the old and the updated expiry removed %d records, want 0", removed)
		}
		if _, err := store.GetRefreshToken(context.Background(), "handle-1"); err != nil {
			t.Fatalf("Get after RemoveExpired: %v", err)
		}

		removed, err = store.RemoveExpired(context.Background(), newExpiry.Add(time.Second))
		if err != nil {
			t.Fatalf("RemoveExpired past the updated expiry: %v", err)
		}
		if removed != 1 {
			t.Fatalf("RemoveExpired past the updated expiry removed %d records, want 1", removed)
		}
		_, err = store.GetRefreshToken(context.Background(), "handle-1")
		expectNotFound(t, err)
	})
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.RefreshTokenStore) {
			_ = store.StoreRefreshToken(context.Background(), "handle-1", newRefreshToken("client-a"))
			_, _ = store.GetRefreshToken(context.Background(), "handle-1")
			_, _ = store.RemoveExpired(context.Background(), fixedNow)
			_ = store.RemoveRefreshToken(context.Background(), "handle-1")
		})
	})
	mustCase(t, "RemoveByClientIsolated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for handle, clientId := range map[string]string{"a-1": "client-a", "a-2": "client-a", "b-1": "client-b"} {
			if err := store.StoreRefreshToken(context.Background(), handle, newRefreshToken(clientId)); err != nil {
				t.Fatalf("store %s: %v", handle, err)
			}
		}
		count, err := store.RemoveRefreshTokensByClient(context.Background(), "client-a")
		expectRemovedCount(t, count, err, 2)
		for _, handle := range []string{"a-1", "a-2"} {
			_, err := store.GetRefreshToken(context.Background(), handle)
			expectNotFound(t, err)
		}
		if _, err := store.GetRefreshToken(context.Background(), "b-1"); err != nil {
			t.Fatalf("other client token removed: %v", err)
		}
		count, err = store.RemoveRefreshTokensByClient(context.Background(), "client-a")
		expectRemovedCount(t, count, err, 0)
	})
	mustCase(t, "RemoveBySessionIsolated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for handle, sessionId := range map[string]string{"s1-1": "session-1", "s1-2": "session-1", "s2-1": "session-2", "none": ""} {
			token := newRefreshToken("client-a")
			token.SessionId = sessionId
			if err := store.StoreRefreshToken(context.Background(), handle, token); err != nil {
				t.Fatalf("store %s: %v", handle, err)
			}
		}
		count, err := store.RemoveRefreshTokensBySession(context.Background(), "session-1")
		expectRemovedCount(t, count, err, 2)
		for _, handle := range []string{"s1-1", "s1-2"} {
			_, err := store.GetRefreshToken(context.Background(), handle)
			expectNotFound(t, err)
		}
		for _, handle := range []string{"s2-1", "none"} {
			if _, err := store.GetRefreshToken(context.Background(), handle); err != nil {
				t.Fatalf("token %s outside the session removed: %v", handle, err)
			}
		}
		count, err = store.RemoveRefreshTokensBySession(context.Background(), "session-1")
		expectRemovedCount(t, count, err, 0)
	})
	mustCase(t, "ScopedRemoveEmptyArgumentMatchesNothing", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		blank := newRefreshToken("")
		blank.SessionId = ""
		if err := store.StoreRefreshToken(context.Background(), "blank", blank); err != nil {
			t.Fatalf("store: %v", err)
		}
		count, err := store.RemoveRefreshTokensByClient(context.Background(), "")
		expectRemovedCount(t, count, err, 0)
		count, err = store.RemoveRefreshTokensBySession(context.Background(), "")
		expectRemovedCount(t, count, err, 0)
		if _, err := store.GetRefreshToken(context.Background(), "blank"); err != nil {
			t.Fatalf("token with empty fields removed by empty argument: %v", err)
		}
	})
	// Concurrent duplicate revocations race to remove the same handle; the
	// loser must see success, not a failure the endpoint would surface.
	mustCase(t, "RemoveMissingHandleSucceeds", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreRefreshToken(context.Background(), "handle-1", newRefreshToken("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if err := store.RemoveRefreshToken(context.Background(), "missing"); err != nil {
			t.Fatalf("Remove(missing) = %v, want nil", err)
		}
		if err := store.RemoveRefreshToken(context.Background(), "handle-1"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if err := store.RemoveRefreshToken(context.Background(), "handle-1"); err != nil {
			t.Fatalf("Remove(already removed) = %v, want nil", err)
		}
	})
	mustCase(t, "NoBackgroundGoroutinesScopedRemoval", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.RefreshTokenStore) {
			token := newRefreshToken("client-a")
			token.SessionId = "session-1"
			_ = store.StoreRefreshToken(context.Background(), "handle-1", token)
			_, _ = store.RemoveRefreshTokensBySession(context.Background(), "session-1")
			_ = store.StoreRefreshToken(context.Background(), "handle-2", token)
			_, _ = store.RemoveRefreshTokensByClient(context.Background(), "client-a")
		})
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newRefreshToken(clientId string) *models.RefreshToken {
	return &models.RefreshToken{
		CreationTime:     fixedNow,
		Lifetime:         3600,
		ClientId:         clientId,
		AuthorizedScopes: []string{"openid", "profile"},
	}
}
