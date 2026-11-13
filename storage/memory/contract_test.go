// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// fixedClock is a deterministic time source for expiry semantics tests.
type fixedClock struct {
	now time.Time
}

func (c *fixedClock) Now() time.Time { return c.now }

func TestPersistedGrantStoreMissReturnsSentinel(t *testing.T) {
	t.Parallel()

	store := NewMemoryPersistedGrantStore()
	_, err := store.Get(context.Background(), "missing")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get miss error = %v, want storage.ErrNotFound", err)
	}
}

func TestPersistedGrantStoreRemoveExpired(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewMemoryPersistedGrantStore()
	expired := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	store.Store(context.Background(), &models.PersistedGrant{Key: "expired", Expiration: &expired})
	store.Store(context.Background(), &models.PersistedGrant{Key: "kept", Expiration: &future})
	store.Store(context.Background(), &models.PersistedGrant{Key: "no-expiration"})

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("RemoveExpired count = %d, want 1", count)
	}
	if _, err := store.Get(context.Background(), "expired"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired grant still present, err = %v", err)
	}
	if _, err := store.Get(context.Background(), "kept"); err != nil {
		t.Fatalf("future grant removed: %v", err)
	}
	if _, err := store.Get(context.Background(), "no-expiration"); err != nil {
		t.Fatalf("grant without expiration removed: %v", err)
	}
}

func TestPersistedGrantStoreRemoveExpiredCutoffBoundary(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	exact := cutoff
	store := NewMemoryPersistedGrantStore()
	store.Store(context.Background(), &models.PersistedGrant{Key: "exact", Expiration: &exact})

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	// A record expiring exactly at the cutoff is not yet expired: the core side
	// judges expiry, the reclamation pass removes strictly-before-cutoff data.
	if count != 0 {
		t.Fatalf("RemoveExpired count = %d, want 0 for exact-cutoff record", count)
	}
}

func TestDeviceFlowStoreMissReturnsSentinel(t *testing.T) {
	t.Parallel()

	store := NewMemoryDeviceFlowStore()
	if _, err := store.FindByUserCode(context.Background(), "u"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("FindByUserCode miss error = %v, want storage.ErrNotFound", err)
	}
	if _, err := store.FindByDeviceCode(context.Background(), "d"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("FindByDeviceCode miss error = %v, want storage.ErrNotFound", err)
	}
}

func TestDeviceFlowStoreRemoveExpired(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewMemoryDeviceFlowStore()
	old := &models.DeviceCode{CreationTime: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Lifetime: 600}
	fresh := &models.DeviceCode{CreationTime: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC), Lifetime: 86400 * 4}
	if err := store.StoreDeviceAuthorization(context.Background(), "dev-old", "usr-old", old); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreDeviceAuthorization(context.Background(), "dev-fresh", "usr-fresh", fresh); err != nil {
		t.Fatal(err)
	}

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("RemoveExpired count = %d, want 1", count)
	}
	if _, err := store.FindByDeviceCode(context.Background(), "dev-old"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired device code still present, err = %v", err)
	}
	if _, err := store.FindByUserCode(context.Background(), "usr-old"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired user code still present, err = %v", err)
	}
	if _, err := store.FindByDeviceCode(context.Background(), "dev-fresh"); err != nil {
		t.Fatalf("fresh device code removed: %v", err)
	}
}

func TestBackchannelRequestStoreMissReturnsSentinel(t *testing.T) {
	t.Parallel()

	store := NewMemoryBackchannelAuthenticationRequestStore()
	_, err := store.FindBackchannelAuthenticationRequest(context.Background(), "missing")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Find miss error = %v, want storage.ErrNotFound", err)
	}
}

func TestBackchannelRequestStoreRemoveExpired(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewMemoryBackchannelAuthenticationRequestStore()
	old := &models.BackchannelAuthenticationRequest{RequestId: "old", ExpirationTime: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	fresh := &models.BackchannelAuthenticationRequest{RequestId: "fresh", ExpirationTime: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	noExpiry := &models.BackchannelAuthenticationRequest{RequestId: "no-expiry"}
	if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "old", old); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "fresh", fresh); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "no-expiry", noExpiry); err != nil {
		t.Fatal(err)
	}

	count, err := store.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("RemoveExpired count = %d, want 1", count)
	}
	if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "old"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired request still present, err = %v", err)
	}
	if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "fresh"); err != nil {
		t.Fatalf("fresh request removed: %v", err)
	}
	if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "no-expiry"); err != nil {
		t.Fatalf("request without expiration removed: %v", err)
	}
}

func TestMemoryStoreListReturnsEmptySliceNotSentinel(t *testing.T) {
	t.Parallel()

	store := NewMemoryPersistedGrantStore()
	all, err := store.GetAll(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if all == nil {
		t.Fatal("GetAll returned nil, want empty slice")
	}
	if len(all) != 0 {
		t.Fatalf("GetAll len = %d, want 0", len(all))
	}
}

// TestCtxCancellationPropagatesIntoStore verifies the port contract that
// adapter methods take the caller's context: a cancelled context is accepted
// without panic or behavioural change for the in-memory adapter, proving the
// context parameter is threaded into the store call.
func TestCtxCancellationPropagatesIntoStore(t *testing.T) {
	t.Parallel()

	store := NewMemoryPersistedGrantStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := store.RemoveAll(ctx, nil); err != nil {
		t.Fatalf("RemoveAll with cancelled ctx: %v", err)
	}
	if count, err := store.RemoveExpired(ctx, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)); err != nil || count != 0 {
		t.Fatalf("RemoveExpired with cancelled ctx = (%d, %v)", count, err)
	}
	if _, err := store.Get(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get with cancelled ctx = %v, want ErrNotFound", err)
	}
}

func TestMemoryDeviceFlowStoreUpdateOfUnknownUserCode(t *testing.T) {
	store := NewMemoryDeviceFlowStore()

	err := store.UpdateByUserCode(context.Background(), "missing", &models.DeviceCode{ClientId: "client-a"})
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("UpdateByUserCode(missing) = %v, want ErrNotFound", err)
	}
	if _, err := store.FindByUserCode(context.Background(), "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("FindByUserCode(missing) after update = %v, want ErrNotFound", err)
	}
}
