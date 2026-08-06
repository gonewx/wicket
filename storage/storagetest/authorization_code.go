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

// RunAuthorizationCodeStoreSuite runs the conformance suite for a
// storage.AuthorizationCodeStore. newStore must return a fresh empty store on
// each call.
func RunAuthorizationCodeStoreSuite(t *testing.T, newStore func() storage.AuthorizationCodeStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.GetAuthorizationCode(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		code := newAuthorizationCode("client-a")
		err := store.StoreAuthorizationCode(cancelledContext(), "handle-1", code)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.GetAuthorizationCode(context.Background(), "handle-1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetAuthorizationCode(context.Background(), "missing")
		if got != nil {
			t.Fatalf("Get(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "DuplicateHandleRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newAuthorizationCode("client-a")
		if err := store.StoreAuthorizationCode(context.Background(), "handle-1", first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := newAuthorizationCode("client-b")
		if err := store.StoreAuthorizationCode(context.Background(), "handle-1", second); !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("second store error = %v, want ErrDuplicateHandle", err)
		}
		got, err := store.GetAuthorizationCode(context.Background(), "handle-1")
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
		code := newAuthorizationCode("client-a")
		code.CreationTime = fixedExpired
		code.Lifetime = 60
		if err := store.StoreAuthorizationCode(context.Background(), "handle-1", code); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.GetAuthorizationCode(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("expired code not readable: %v", err)
		}
		if got == nil || got.ClientId != "client-a" {
			t.Fatalf("Get(expired) = %v, want the stored code", got)
		}
	})
	mustCase(t, "RemoveExpiredReclaimsExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newAuthorizationCode("client-a")
		expired.CreationTime = fixedExpired
		expired.Lifetime = 60
		alive := newAuthorizationCode("client-b")
		alive.CreationTime = fixedAlive
		alive.Lifetime = 3600
		boundary := newAuthorizationCode("client-c")
		boundary.CreationTime = fixedNow.Add(-60 * time.Second)
		boundary.Lifetime = 60
		for _, c := range []*models.AuthorizationCode{expired, alive, boundary} {
			if err := store.StoreAuthorizationCode(context.Background(), c.ClientId, c); err != nil {
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
		if _, err := store.GetAuthorizationCode(context.Background(), "client-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired code still present: %v", err)
		}
		if _, err := store.GetAuthorizationCode(context.Background(), "client-b"); err != nil {
			t.Fatalf("alive code removed: %v", err)
		}
		if _, err := store.GetAuthorizationCode(context.Background(), "client-c"); err != nil {
			t.Fatalf("boundary code removed: %v", err)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
	// An authorization code is single-use: redemption removes it and a
	// second lookup must miss. The store must support that one-shot
	// consumption by removal.
	mustCase(t, "OneTimeConsumption", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreAuthorizationCode(context.Background(), "handle-1", newAuthorizationCode("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if _, err := store.GetAuthorizationCode(context.Background(), "handle-1"); err != nil {
			t.Fatalf("get before redemption: %v", err)
		}
		if err := store.RemoveAuthorizationCode(context.Background(), "handle-1"); err != nil {
			t.Fatalf("remove: %v", err)
		}
		_, err := store.GetAuthorizationCode(context.Background(), "handle-1")
		expectNotFound(t, err)
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newAuthorizationCode(clientId string) *models.AuthorizationCode {
	return &models.AuthorizationCode{
		CreationTime:    fixedNow,
		Lifetime:        300,
		ClientId:        clientId,
		IsOpenId:        true,
		RequestedScopes: []string{"openid", "profile"},
		RedirectUri:     "https://client.example/callback",
	}
}
