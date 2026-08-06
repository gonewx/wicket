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

// RunBackchannelAuthenticationRequestStoreSuite runs the conformance suite
// for a storage.BackchannelAuthenticationRequestStore. newStore must return a
// fresh empty store on each call.
func RunBackchannelAuthenticationRequestStoreSuite(t *testing.T, newStore func() storage.BackchannelAuthenticationRequestStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.FindBackchannelAuthenticationRequest(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		req := newBackchannelRequest("client-a")
		err := store.StoreBackchannelAuthenticationRequest(cancelledContext(), "req-1", req)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.FindBackchannelAuthenticationRequest(context.Background(), "req-1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.FindBackchannelAuthenticationRequest(context.Background(), "missing")
		if got != nil {
			t.Fatalf("Find(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "DuplicateRequestIdRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newBackchannelRequest("client-a")
		if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "req-1", first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := newBackchannelRequest("client-b")
		if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "req-1", second); !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("second store error = %v, want ErrDuplicateHandle", err)
		}
		got, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-1")
		if err != nil {
			t.Fatalf("Find after collision: %v", err)
		}
		if got.ClientId != "client-a" {
			t.Fatalf("stored ClientId = %q, want original %q", got.ClientId, "client-a")
		}
	})
	mustCase(t, "ExpiredRecordStillReadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		req := newBackchannelRequest("client-a")
		req.ExpirationTime = fixedExpired
		if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "req-1", req); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-1")
		if err != nil {
			t.Fatalf("expired request not readable: %v", err)
		}
		if got == nil || got.ClientId != "client-a" {
			t.Fatalf("Find(expired) = %v, want the stored request", got)
		}
	})
	mustCase(t, "RemoveExpiredReclaimsExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newBackchannelRequest("client-a")
		expired.ExpirationTime = fixedExpired
		alive := newBackchannelRequest("client-b")
		alive.ExpirationTime = fixedAlive
		boundary := newBackchannelRequest("client-c")
		boundary.ExpirationTime = fixedNow
		noExpiry := newBackchannelRequest("client-d")
		noExpiry.ExpirationTime = time.Time{}
		for _, r := range []*models.BackchannelAuthenticationRequest{expired, alive, boundary, noExpiry} {
			if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "req-"+r.ClientId, r); err != nil {
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
		if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-client-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired request still present: %v", err)
		}
		if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-client-b"); err != nil {
			t.Fatalf("alive request removed: %v", err)
		}
		if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-client-c"); err != nil {
			t.Fatalf("boundary request removed: %v", err)
		}
		if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-client-d"); err != nil {
			t.Fatalf("request without expiration removed: %v", err)
		}
	})
	// The state machine moves the request through pending/approved/denied
	// and consumed; the store must replace the record on update and the new
	// state must be readable back. The update is not version-guarded.
	mustCase(t, "StateMigrationUpdatesReadBack", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		pending := newBackchannelRequest("client-a")
		if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "req-1", pending); err != nil {
			t.Fatalf("store: %v", err)
		}
		approved := newBackchannelRequest("client-a")
		approved.Status = models.BackchannelAuthenticationRequestStatusApproved
		if err := store.UpdateBackchannelAuthenticationRequest(context.Background(), "req-1", approved); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-1")
		if err != nil {
			t.Fatalf("Find after update: %v", err)
		}
		if got.Status != models.BackchannelAuthenticationRequestStatusApproved {
			t.Fatalf("stored Status = %q, want %q", got.Status, models.BackchannelAuthenticationRequestStatusApproved)
		}
	})
	mustCase(t, "RemoveDeletesRequest", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "req-1", newBackchannelRequest("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if err := store.RemoveBackchannelAuthenticationRequest(context.Background(), "req-1"); err != nil {
			t.Fatalf("remove: %v", err)
		}
		_, err := store.FindBackchannelAuthenticationRequest(context.Background(), "req-1")
		expectNotFound(t, err)
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newBackchannelRequest(clientId string) *models.BackchannelAuthenticationRequest {
	return &models.BackchannelAuthenticationRequest{
		RequestId:       "req",
		ClientId:        clientId,
		RequestedScopes: []string{"openid", "profile"},
		Status:          models.BackchannelAuthenticationRequestStatusPending,
		CreationTime:    fixedNow,
		ExpirationTime:  fixedAlive,
	}
}
