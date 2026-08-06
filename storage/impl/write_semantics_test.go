// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/memory"
	"github.com/gonewx/wicket/storage/models"
)

// writeSemanticsNow is the fixed reference instant for write-semantics tests.
var writeSemanticsNow = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

// TestInsertOnlyStoresRejectDuplicateHandles pins the insert-only contract for
// every store family that keys records by a caller-supplied handle: a second
// write under an existing handle fails with ErrDuplicateHandle and leaves the
// stored record unchanged.
func TestInsertOnlyStoresRejectDuplicateHandles(t *testing.T) {
	t.Parallel()

	newAuthorizationCode := func() *models.AuthorizationCode {
		return &models.AuthorizationCode{CreationTime: writeSemanticsNow, Lifetime: 300, ClientId: "client"}
	}
	newRefreshToken := func() *models.RefreshToken {
		return &models.RefreshToken{CreationTime: writeSemanticsNow, Lifetime: 600, ClientId: "client"}
	}
	newReferenceToken := func() *models.Token {
		return &models.Token{CreationTime: writeSemanticsNow, Lifetime: 3600, ClientId: "client"}
	}
	newDeviceCode := func() *models.DeviceCode {
		return &models.DeviceCode{CreationTime: writeSemanticsNow, Lifetime: 300, ClientId: "client"}
	}
	newBackchannelRequest := func() *models.BackchannelAuthenticationRequest {
		return &models.BackchannelAuthenticationRequest{RequestId: "request", ClientId: "client", ExpirationTime: writeSemanticsNow.Add(time.Minute)}
	}

	tests := map[string]struct {
		run func(t *testing.T)
	}{
		"authorization codes": {
			run: func(t *testing.T) {
				store := NewAuthorizationCodeStore()
				if err := store.StoreAuthorizationCode(context.Background(), "handle", newAuthorizationCode()); err != nil {
					t.Fatalf("first store: %v", err)
				}
				if err := store.StoreAuthorizationCode(context.Background(), "handle", newAuthorizationCode()); !errors.Is(err, storage.ErrDuplicateHandle) {
					t.Fatalf("second store error = %v, want storage.ErrDuplicateHandle", err)
				}
			},
		},
		"refresh tokens": {
			run: func(t *testing.T) {
				store := NewRefreshTokenStore()
				if err := store.StoreRefreshToken(context.Background(), "handle", newRefreshToken()); err != nil {
					t.Fatalf("first store: %v", err)
				}
				if err := store.StoreRefreshToken(context.Background(), "handle", newRefreshToken()); !errors.Is(err, storage.ErrDuplicateHandle) {
					t.Fatalf("second store error = %v, want storage.ErrDuplicateHandle", err)
				}
			},
		},
		"reference tokens": {
			run: func(t *testing.T) {
				store := NewReferenceTokenStore()
				if err := store.StoreReferenceToken(context.Background(), "handle", newReferenceToken()); err != nil {
					t.Fatalf("first store: %v", err)
				}
				if err := store.StoreReferenceToken(context.Background(), "handle", newReferenceToken()); !errors.Is(err, storage.ErrDuplicateHandle) {
					t.Fatalf("second store error = %v, want storage.ErrDuplicateHandle", err)
				}
			},
		},
		"device flows": {
			run: func(t *testing.T) {
				store := memory.NewMemoryDeviceFlowStore()
				if err := store.StoreDeviceAuthorization(context.Background(), "device", "user", newDeviceCode()); err != nil {
					t.Fatalf("first store: %v", err)
				}
				if err := store.StoreDeviceAuthorization(context.Background(), "device", "user", newDeviceCode()); !errors.Is(err, storage.ErrDuplicateHandle) {
					t.Fatalf("second store error = %v, want storage.ErrDuplicateHandle", err)
				}
			},
		},
		"backchannel requests": {
			run: func(t *testing.T) {
				store := memory.NewMemoryBackchannelAuthenticationRequestStore()
				if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "request", newBackchannelRequest()); err != nil {
					t.Fatalf("first store: %v", err)
				}
				if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "request", newBackchannelRequest()); !errors.Is(err, storage.ErrDuplicateHandle) {
					t.Fatalf("second store error = %v, want storage.ErrDuplicateHandle", err)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tt.run(t)
		})
	}
}

// TestDuplicateHandleLeavesRecordUnchanged pins that an insert-only collision
// is non-destructive: the original record survives the rejected write.
func TestDuplicateHandleLeavesRecordUnchanged(t *testing.T) {
	t.Parallel()

	store := NewAuthorizationCodeStore()
	original := newWriteSemanticsAuthorizationCode()
	if err := store.StoreAuthorizationCode(context.Background(), "handle", original); err != nil {
		t.Fatal(err)
	}

	replacement := newWriteSemanticsAuthorizationCode()
	replacement.ClientId = "other-client"
	if err := store.StoreAuthorizationCode(context.Background(), "handle", replacement); !errors.Is(err, storage.ErrDuplicateHandle) {
		t.Fatalf("collision error = %v, want storage.ErrDuplicateHandle", err)
	}

	got, err := store.GetAuthorizationCode(context.Background(), "handle")
	if err != nil {
		t.Fatalf("Get after collision: %v", err)
	}
	if got.ClientId != original.ClientId {
		t.Fatalf("stored client = %q, want %q", got.ClientId, original.ClientId)
	}
}

// TestUpsertStoresOverwriteNaturalKeys pins the upsert contract for the two
// natural-key families: storing again under the same key succeeds and the
// later record replaces the earlier one.
func TestUpsertStoresOverwriteNaturalKeys(t *testing.T) {
	t.Parallel()

	t.Run("persisted grants", func(t *testing.T) {
		t.Parallel()

		store := memory.NewMemoryPersistedGrantStore()
		first := &models.PersistedGrant{Key: "grant", SubjectId: "subject", ClientId: "client"}
		if err := store.Store(context.Background(), first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := &models.PersistedGrant{Key: "grant", SubjectId: "subject", ClientId: "other-client"}
		if err := store.Store(context.Background(), second); err != nil {
			t.Fatalf("second store: %v", err)
		}

		got, err := store.Get(context.Background(), "grant")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ClientId != "other-client" {
			t.Fatalf("stored client = %q, want %q", got.ClientId, "other-client")
		}
	})

	t.Run("user consents", func(t *testing.T) {
		t.Parallel()

		store := NewUserConsentStore()
		first := &models.Consent{SubjectId: "subject", ClientId: "client", CreationTime: writeSemanticsNow}
		if err := store.StoreUserConsent(context.Background(), first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := &models.Consent{SubjectId: "subject", ClientId: "client", CreationTime: writeSemanticsNow.Add(time.Hour)}
		if err := store.StoreUserConsent(context.Background(), second); err != nil {
			t.Fatalf("second store: %v", err)
		}

		got, err := store.GetUserConsent(context.Background(), "subject", "client")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !got.CreationTime.Equal(second.CreationTime) {
			t.Fatalf("stored creation time = %v, want %v", got.CreationTime, second.CreationTime)
		}
	})
}

// TestRefreshTokenStoreVersionManagement pins the optimistic-concurrency
// lifecycle: an insert stores version 1 and writes it back to the caller, a
// matching update increments the stored version and writes it back, and a
// second update with the stale version fails with ErrVersionConflict while
// leaving the stored record unchanged.
func TestRefreshTokenStoreVersionManagement(t *testing.T) {
	t.Parallel()

	store := NewRefreshTokenStore()
	token := newWriteSemanticsRefreshToken()
	if err := store.StoreRefreshToken(context.Background(), "handle", token); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if token.Version != 1 {
		t.Fatalf("insert wrote back version %d, want 1", token.Version)
	}

	got, err := store.GetRefreshToken(context.Background(), "handle")
	if err != nil {
		t.Fatalf("Get after insert: %v", err)
	}
	if got.Version != 1 {
		t.Fatalf("stored version = %d, want 1", got.Version)
	}

	token.Lifetime = 900
	if err := store.UpdateRefreshToken(context.Background(), "handle", token, 1); err != nil {
		t.Fatalf("matching update: %v", err)
	}
	if token.Version != 2 {
		t.Fatalf("update wrote back version %d, want 2", token.Version)
	}

	got, err = store.GetRefreshToken(context.Background(), "handle")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.Version != 2 {
		t.Fatalf("stored version = %d, want 2", got.Version)
	}
	if got.Lifetime != 900 {
		t.Fatalf("stored lifetime = %d, want 900", got.Lifetime)
	}

	token.Lifetime = 1200
	err = store.UpdateRefreshToken(context.Background(), "handle", token, 1)
	if !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("stale update error = %v, want storage.ErrVersionConflict", err)
	}

	got, err = store.GetRefreshToken(context.Background(), "handle")
	if err != nil {
		t.Fatalf("Get after conflict: %v", err)
	}
	if got.Version != 2 {
		t.Fatalf("version changed after conflict: %d, want 2", got.Version)
	}
	if got.Lifetime != 900 {
		t.Fatalf("record changed after conflict: lifetime = %d, want 900", got.Lifetime)
	}
}

// TestRefreshTokenReplayRejected pins the rotation-replay semantics: a second
// update of the same handle with the already-consumed version always fails
// with ErrVersionConflict, so a rotated token cannot be replayed.
func TestRefreshTokenReplayRejected(t *testing.T) {
	t.Parallel()

	store := NewRefreshTokenStore()
	token := newWriteSemanticsRefreshToken()
	if err := store.StoreRefreshToken(context.Background(), "handle", token); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := store.UpdateRefreshToken(context.Background(), "handle", token, token.Version); err != nil {
		t.Fatalf("first rotation: %v", err)
	}

	replay := newWriteSemanticsRefreshToken()
	err := store.UpdateRefreshToken(context.Background(), "handle", replay, 1)
	if !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("replay error = %v, want storage.ErrVersionConflict", err)
	}
}

// TestGetReturnsIndependentCopies pins the deep-copy read contract: mutating
// the returned record's value, slice, and map fields must not affect the
// stored record.
func TestGetReturnsIndependentCopies(t *testing.T) {
	t.Parallel()

	t.Run("authorization codes", func(t *testing.T) {
		t.Parallel()

		store := NewAuthorizationCodeStore()
		if err := store.StoreAuthorizationCode(context.Background(), "handle", newWriteSemanticsAuthorizationCode()); err != nil {
			t.Fatal(err)
		}
		got, err := store.GetAuthorizationCode(context.Background(), "handle")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		got.ClientId = "mutated"
		got.RequestedScopes[0] = "mutated"

		again, err := store.GetAuthorizationCode(context.Background(), "handle")
		if err != nil {
			t.Fatalf("second Get: %v", err)
		}
		if again.ClientId != "client" {
			t.Fatalf("stored client = %q, want %q", again.ClientId, "client")
		}
		if again.RequestedScopes[0] != "orders.read" {
			t.Fatalf("stored scope = %q, want %q", again.RequestedScopes[0], "orders.read")
		}
	})

	t.Run("refresh tokens", func(t *testing.T) {
		t.Parallel()

		store := NewRefreshTokenStore()
		if err := store.StoreRefreshToken(context.Background(), "handle", newWriteSemanticsRefreshToken()); err != nil {
			t.Fatal(err)
		}
		got, err := store.GetRefreshToken(context.Background(), "handle")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		got.ClientId = "mutated"
		got.AuthorizedScopes[0] = "mutated"
		got.AccessTokens["mutated"] = &models.Token{ClientId: "mutated"}
		got.AccessToken.ClientId = "mutated"

		again, err := store.GetRefreshToken(context.Background(), "handle")
		if err != nil {
			t.Fatalf("second Get: %v", err)
		}
		if again.ClientId != "client" {
			t.Fatalf("stored client = %q, want %q", again.ClientId, "client")
		}
		if again.AuthorizedScopes[0] != "orders.read" {
			t.Fatalf("stored scope = %q, want %q", again.AuthorizedScopes[0], "orders.read")
		}
		if _, ok := again.AccessTokens["mutated"]; ok {
			t.Fatal("mutated map entry visible in store")
		}
		if again.AccessToken.ClientId != "client" {
			t.Fatalf("stored access token client = %q, want %q", again.AccessToken.ClientId, "client")
		}
	})

	t.Run("reference tokens", func(t *testing.T) {
		t.Parallel()

		store := NewReferenceTokenStore()
		if err := store.StoreReferenceToken(context.Background(), "handle", newWriteSemanticsReferenceToken()); err != nil {
			t.Fatal(err)
		}
		got, err := store.GetReferenceToken(context.Background(), "handle")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		got.ClientId = "mutated"
		got.Audiences[0] = "mutated"

		again, err := store.GetReferenceToken(context.Background(), "handle")
		if err != nil {
			t.Fatalf("second Get: %v", err)
		}
		if again.ClientId != "client" {
			t.Fatalf("stored client = %q, want %q", again.ClientId, "client")
		}
		if again.Audiences[0] != "https://api.example.com" {
			t.Fatalf("stored audience = %q, want %q", again.Audiences[0], "https://api.example.com")
		}
	})
}

func newWriteSemanticsAuthorizationCode() *models.AuthorizationCode {
	return &models.AuthorizationCode{
		CreationTime:          writeSemanticsNow,
		Lifetime:              300,
		ClientId:              "client",
		RequestedScopes:       []string{"orders.read"},
		RequestedResourceGaps: []string{"https://resources.example.com/orders"},
	}
}

func newWriteSemanticsRefreshToken() *models.RefreshToken {
	return &models.RefreshToken{
		CreationTime:           writeSemanticsNow,
		Lifetime:               600,
		ClientId:               "client",
		AccessToken:            models.Token{ClientId: "client"},
		AccessTokens:           map[string]*models.Token{"": {ClientId: "client"}},
		AuthorizedScopes:       []string{"orders.read"},
		AuthorizedResourceGaps: []string{"https://resources.example.com/orders"},
	}
}

func newWriteSemanticsReferenceToken() *models.Token {
	return &models.Token{
		CreationTime: writeSemanticsNow,
		Lifetime:     3600,
		ClientId:     "client",
		Audiences:    []string{"https://api.example.com"},
	}
}
