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

// RunReferenceTokenStoreSuite runs the conformance suite for a
// storage.ReferenceTokenStore. newStore must return a fresh empty store on
// each call.
func RunReferenceTokenStoreSuite(t *testing.T, newStore func() storage.ReferenceTokenStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.GetReferenceToken(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		token := newReferenceToken("client-a")
		err := store.StoreReferenceToken(cancelledContext(), "handle-1", token)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.GetReferenceToken(context.Background(), "handle-1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetReferenceToken(context.Background(), "missing")
		if got != nil {
			t.Fatalf("Get(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "DuplicateHandleRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newReferenceToken("client-a")
		if err := store.StoreReferenceToken(context.Background(), "handle-1", first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := newReferenceToken("client-b")
		if err := store.StoreReferenceToken(context.Background(), "handle-1", second); !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("second store error = %v, want ErrDuplicateHandle", err)
		}
		got, err := store.GetReferenceToken(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Get after collision: %v", err)
		}
		if got.ClientId != "client-a" {
			t.Fatalf("stored ClientId = %q, want original %q", got.ClientId, "client-a")
		}
	})
	mustCase(t, "ExpiredRecordStillReadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		token := newReferenceToken("client-a")
		token.CreationTime = fixedExpired
		token.Lifetime = 60
		if err := store.StoreReferenceToken(context.Background(), "handle-1", token); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.GetReferenceToken(context.Background(), "handle-1")
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
		expired := newReferenceToken("client-a")
		expired.CreationTime = fixedExpired
		expired.Lifetime = 60
		alive := newReferenceToken("client-b")
		alive.CreationTime = fixedAlive
		alive.Lifetime = 3600
		boundary := newReferenceToken("client-c")
		boundary.CreationTime = fixedNow.Add(-60 * time.Second)
		boundary.Lifetime = 60
		for _, tok := range []*models.Token{expired, alive, boundary} {
			if err := store.StoreReferenceToken(context.Background(), tok.ClientId, tok); err != nil {
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
		if _, err := store.GetReferenceToken(context.Background(), "client-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired token still present: %v", err)
		}
		if _, err := store.GetReferenceToken(context.Background(), "client-b"); err != nil {
			t.Fatalf("alive token removed: %v", err)
		}
		if _, err := store.GetReferenceToken(context.Background(), "client-c"); err != nil {
			t.Fatalf("boundary token removed: %v", err)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7009 (revocation).
	// Batch revocation targets a subject/client pair; tokens for other
	// clients must survive. The suite exercises the pair matching with an
	// empty subject, the only value expressible through the shared model
	// without a principal (the model derives SubjectId from claims).
	mustCase(t, "RemoveReferenceTokensRevokesPair", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for _, pair := range []struct {
			handle string
			token  *models.Token
		}{
			{"h1", newReferenceToken("client-a")},
			{"h2", newReferenceToken("client-a")},
			{"h3", newReferenceToken("client-b")},
		} {
			if err := store.StoreReferenceToken(context.Background(), pair.handle, pair.token); err != nil {
				t.Fatalf("store: %v", err)
			}
		}
		// Revoking an unknown subject/client pair changes nothing.
		if err := store.RemoveReferenceTokens(context.Background(), "absent-subject", "client-a"); err != nil {
			t.Fatalf("RemoveReferenceTokens: %v", err)
		}
		if _, err := store.GetReferenceToken(context.Background(), "h1"); err != nil {
			t.Fatalf("token revoked despite subject mismatch: %v", err)
		}
		// Revoking the stored pair removes exactly that client's tokens.
		if err := store.RemoveReferenceTokens(context.Background(), "", "client-a"); err != nil {
			t.Fatalf("RemoveReferenceTokens: %v", err)
		}
		if _, err := store.GetReferenceToken(context.Background(), "h1"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("matching token still present: %v", err)
		}
		if _, err := store.GetReferenceToken(context.Background(), "h2"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("matching token still present: %v", err)
		}
		if _, err := store.GetReferenceToken(context.Background(), "h3"); err != nil {
			t.Fatalf("other client token revoked: %v", err)
		}
	})
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.ReferenceTokenStore) {
			_ = store.StoreReferenceToken(context.Background(), "handle-1", newReferenceToken("client-a"))
			_, _ = store.GetReferenceToken(context.Background(), "handle-1")
			_, _ = store.RemoveExpired(context.Background(), fixedNow)
			_ = store.RemoveReferenceToken(context.Background(), "handle-1")
		})
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newReferenceToken(clientId string) *models.Token {
	return &models.Token{
		CreationTime: fixedNow,
		Lifetime:     3600,
		Type:         "reference",
		ClientId:     clientId,
	}
}
