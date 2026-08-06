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

// RunDeviceFlowStoreSuite runs the conformance suite for a
// storage.DeviceFlowStore. newStore must return a fresh empty store on each
// call.
func RunDeviceFlowStoreSuite(t *testing.T, newStore func() storage.DeviceFlowStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.FindByUserCode(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		data := newDeviceCode("client-a")
		err := store.StoreDeviceAuthorization(cancelledContext(), "device-1", "user-1", data)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.FindByDeviceCode(context.Background(), "device-1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.FindByUserCode(context.Background(), "missing")
		if got != nil {
			t.Fatalf("FindByUserCode(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
		got, err = store.FindByDeviceCode(context.Background(), "missing")
		if got != nil {
			t.Fatalf("FindByDeviceCode(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "DuplicateCodesRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreDeviceAuthorization(context.Background(), "device-1", "user-1", newDeviceCode("client-a")); err != nil {
			t.Fatalf("first store: %v", err)
		}
		// Same device code, different user code.
		err := store.StoreDeviceAuthorization(context.Background(), "device-1", "user-2", newDeviceCode("client-b"))
		if !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("duplicate device code error = %v, want ErrDuplicateHandle", err)
		}
		// Different device code, same user code.
		err = store.StoreDeviceAuthorization(context.Background(), "device-2", "user-1", newDeviceCode("client-b"))
		if !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("duplicate user code error = %v, want ErrDuplicateHandle", err)
		}
		got, err := store.FindByUserCode(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("FindByUserCode after collision: %v", err)
		}
		if got.ClientId != "client-a" {
			t.Fatalf("stored ClientId = %q, want original %q", got.ClientId, "client-a")
		}
	})
	mustCase(t, "ExpiredRecordStillReadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		data := newDeviceCode("client-a")
		data.CreationTime = fixedExpired
		data.Lifetime = 60
		if err := store.StoreDeviceAuthorization(context.Background(), "device-1", "user-1", data); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.FindByDeviceCode(context.Background(), "device-1")
		if err != nil {
			t.Fatalf("expired record not readable: %v", err)
		}
		if got == nil || got.ClientId != "client-a" {
			t.Fatalf("Find(expired) = %v, want the stored record", got)
		}
	})
	mustCase(t, "RemoveExpiredReclaimsExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newDeviceCode("client-a")
		expired.CreationTime = fixedExpired
		expired.Lifetime = 60
		alive := newDeviceCode("client-b")
		alive.CreationTime = fixedAlive
		alive.Lifetime = 3600
		boundary := newDeviceCode("client-c")
		boundary.CreationTime = fixedNow.Add(-60 * time.Second)
		boundary.Lifetime = 60
		for _, d := range []*models.DeviceCode{expired, alive, boundary} {
			if err := store.StoreDeviceAuthorization(context.Background(), "device-"+d.ClientId, "user-"+d.ClientId, d); err != nil {
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
		if _, err := store.FindByDeviceCode(context.Background(), "device-client-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired record still present: %v", err)
		}
		if _, err := store.FindByUserCode(context.Background(), "user-client-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired user code still present: %v", err)
		}
		if _, err := store.FindByDeviceCode(context.Background(), "device-client-b"); err != nil {
			t.Fatalf("alive record removed: %v", err)
		}
		if _, err := store.FindByDeviceCode(context.Background(), "device-client-c"); err != nil {
			t.Fatalf("boundary record removed: %v", err)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc8628#section-3.2
	// The device flow uses two codes: the device code is the client's
	// credential, the user code is what the user types into the browser.
	// Both must resolve to the same pending record.
	mustCase(t, "DualCodeLookup", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		data := newDeviceCode("client-a")
		if err := store.StoreDeviceAuthorization(context.Background(), "device-1", "user-1", data); err != nil {
			t.Fatalf("store: %v", err)
		}
		byUser, err := store.FindByUserCode(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("FindByUserCode: %v", err)
		}
		byDevice, err := store.FindByDeviceCode(context.Background(), "device-1")
		if err != nil {
			t.Fatalf("FindByDeviceCode: %v", err)
		}
		if byUser.ClientId != "client-a" || byDevice.ClientId != "client-a" {
			t.Fatalf("dual lookup mismatch: user=%v device=%v", byUser, byDevice)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc8628#section-3.5
	// On completion the codes are discarded; both lookups must miss after
	// removal.
	mustCase(t, "RemoveByDeviceCodeClearsBothCodes", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreDeviceAuthorization(context.Background(), "device-1", "user-1", newDeviceCode("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if err := store.RemoveByDeviceCode(context.Background(), "device-1"); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if _, err := store.FindByDeviceCode(context.Background(), "device-1"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("device code still present: %v", err)
		}
		if _, err := store.FindByUserCode(context.Background(), "user-1"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("user code still present: %v", err)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc8628#section-3.3 and
	// #section-3.4 (polling sees the authorization state change). The store
	// supports the poll loop by replacing the record under the user code.
	cfg.mayCase(t, "UpdateReadsBackAuthorizedState", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		initial := newDeviceCode("client-a")
		initial.IsAuthorized = false
		if err := store.StoreDeviceAuthorization(context.Background(), "device-1", "user-1", initial); err != nil {
			t.Fatalf("store: %v", err)
		}
		authorized := newDeviceCode("client-a")
		authorized.IsAuthorized = true
		authorized.AuthorizedScopes = []string{"openid"}
		if err := store.UpdateByUserCode(context.Background(), "user-1", authorized); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := store.FindByUserCode(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("FindByUserCode after update: %v", err)
		}
		if !got.IsAuthorized {
			t.Fatal("updated record not authorized")
		}
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newDeviceCode(clientId string) *models.DeviceCode {
	return &models.DeviceCode{
		CreationTime:    fixedNow,
		Lifetime:        300,
		ClientId:        clientId,
		RequestedScopes: []string{"openid", "profile"},
	}
}
