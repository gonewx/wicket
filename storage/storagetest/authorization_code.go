// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"context"
	"errors"
	"sync"
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
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.AuthorizationCodeStore) {
			_ = store.StoreAuthorizationCode(context.Background(), "handle-1", newAuthorizationCode("client-a"))
			_, _ = store.GetAuthorizationCode(context.Background(), "handle-1")
			_, _ = store.RemoveExpired(context.Background(), fixedNow)
			_ = store.RemoveAuthorizationCode(context.Background(), "handle-1")
		})
	})
	// Redemption is a one-shot consumption that must hold across replicas
	// and concurrent requests: the take is atomic, so of many simultaneous
	// takes of one handle exactly one obtains the record. Each round
	// releases all takers at once from a closed channel; a store whose take
	// is a lookup followed by a separate delete lets more than one through.
	mustCase(t, "TakeExactlyOnceUnderConcurrency", func(t *testing.T) {
		t.Parallel()
		for round := 0; round < takeRounds; round++ {
			store := newStore()
			if err := store.StoreAuthorizationCode(context.Background(), "handle-1", newAuthorizationCode("client-a")); err != nil {
				t.Fatalf("round %d store: %v", round, err)
			}
			if err := store.StoreAuthorizationCode(context.Background(), "handle-other", newAuthorizationCode("client-b")); err != nil {
				t.Fatalf("round %d store other: %v", round, err)
			}
			start := make(chan struct{})
			type outcome struct {
				code *models.AuthorizationCode
				err  error
			}
			results := make([]outcome, takeConcurrency)
			var wg sync.WaitGroup
			for i := 0; i < takeConcurrency; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					code, err := store.TakeAuthorizationCode(context.Background(), "handle-1")
					results[i] = outcome{code: code, err: err}
				}(i)
			}
			close(start)
			wg.Wait()
			winners := 0
			for i, r := range results {
				switch {
				case r.err == nil:
					if r.code == nil || r.code.ClientId != "client-a" {
						t.Fatalf("round %d taker %d: Take returned %v with nil error, want the stored code", round, i, r.code)
					}
					winners++
				case errors.Is(r.err, storage.ErrNotFound):
					if r.code != nil {
						t.Fatalf("round %d taker %d: Take returned a record alongside ErrNotFound", round, i)
					}
				default:
					t.Fatalf("round %d taker %d: Take error = %v, want nil or ErrNotFound", round, i, r.err)
				}
			}
			if winners != 1 {
				t.Fatalf("round %d: %d of %d concurrent takes obtained the code, want exactly 1", round, winners, takeConcurrency)
			}
			_, err := store.GetAuthorizationCode(context.Background(), "handle-1")
			expectNotFound(t, err)
			other, err := store.GetAuthorizationCode(context.Background(), "handle-other")
			if err != nil || other == nil || other.ClientId != "client-b" {
				t.Fatalf("round %d: untaken handle = %v, %v; want the client-b code", round, other, err)
			}
		}
	})
	mustCase(t, "TakeMissingReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.TakeAuthorizationCode(context.Background(), "missing")
		if got != nil {
			t.Fatalf("Take(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "TakeReturnsExpiredRecord", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		code := newAuthorizationCode("client-a")
		code.CreationTime = fixedExpired
		code.Lifetime = 60
		if err := store.StoreAuthorizationCode(context.Background(), "handle-1", code); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.TakeAuthorizationCode(context.Background(), "handle-1")
		if err != nil {
			t.Fatalf("Take(expired): %v", err)
		}
		if got == nil || got.ClientId != "client-a" {
			t.Fatalf("Take(expired) = %v, want the stored code", got)
		}
		_, err = store.GetAuthorizationCode(context.Background(), "handle-1")
		expectNotFound(t, err)
	})
	mustCase(t, "RemoveByClientIsolated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for handle, clientId := range map[string]string{"a-1": "client-a", "a-2": "client-a", "b-1": "client-b"} {
			if err := store.StoreAuthorizationCode(context.Background(), handle, newAuthorizationCode(clientId)); err != nil {
				t.Fatalf("store %s: %v", handle, err)
			}
		}
		count, err := store.RemoveAuthorizationCodesByClient(context.Background(), "client-a")
		expectRemovedCount(t, count, err, 2)
		for _, handle := range []string{"a-1", "a-2"} {
			_, err := store.GetAuthorizationCode(context.Background(), handle)
			expectNotFound(t, err)
		}
		if _, err := store.GetAuthorizationCode(context.Background(), "b-1"); err != nil {
			t.Fatalf("other client code removed: %v", err)
		}
		count, err = store.RemoveAuthorizationCodesByClient(context.Background(), "client-a")
		expectRemovedCount(t, count, err, 0)
	})
	mustCase(t, "RemoveBySessionIsolated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for handle, sessionId := range map[string]string{"s1-1": "session-1", "s1-2": "session-1", "s2-1": "session-2", "none": ""} {
			code := newAuthorizationCode("client-a")
			code.SessionId = sessionId
			if err := store.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
				t.Fatalf("store %s: %v", handle, err)
			}
		}
		count, err := store.RemoveAuthorizationCodesBySession(context.Background(), "session-1")
		expectRemovedCount(t, count, err, 2)
		for _, handle := range []string{"s1-1", "s1-2"} {
			_, err := store.GetAuthorizationCode(context.Background(), handle)
			expectNotFound(t, err)
		}
		for _, handle := range []string{"s2-1", "none"} {
			if _, err := store.GetAuthorizationCode(context.Background(), handle); err != nil {
				t.Fatalf("code %s outside the session removed: %v", handle, err)
			}
		}
		count, err = store.RemoveAuthorizationCodesBySession(context.Background(), "session-1")
		expectRemovedCount(t, count, err, 0)
	})
	mustCase(t, "ScopedRemoveEmptyArgumentMatchesNothing", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		blank := newAuthorizationCode("")
		blank.SessionId = ""
		if err := store.StoreAuthorizationCode(context.Background(), "blank", blank); err != nil {
			t.Fatalf("store: %v", err)
		}
		count, err := store.RemoveAuthorizationCodesByClient(context.Background(), "")
		expectRemovedCount(t, count, err, 0)
		count, err = store.RemoveAuthorizationCodesBySession(context.Background(), "")
		expectRemovedCount(t, count, err, 0)
		if _, err := store.GetAuthorizationCode(context.Background(), "blank"); err != nil {
			t.Fatalf("code with empty fields removed by empty argument: %v", err)
		}
	})
	mustCase(t, "RemoveMissingHandleSucceeds", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StoreAuthorizationCode(context.Background(), "handle-1", newAuthorizationCode("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		if err := store.RemoveAuthorizationCode(context.Background(), "missing"); err != nil {
			t.Fatalf("Remove(missing) = %v, want nil", err)
		}
		if err := store.RemoveAuthorizationCode(context.Background(), "handle-1"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if err := store.RemoveAuthorizationCode(context.Background(), "handle-1"); err != nil {
			t.Fatalf("Remove(already removed) = %v, want nil", err)
		}
	})
	mustCase(t, "NoBackgroundGoroutinesScopedRemoval", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.AuthorizationCodeStore) {
			code := newAuthorizationCode("client-a")
			code.SessionId = "session-1"
			_ = store.StoreAuthorizationCode(context.Background(), "handle-1", code)
			_, _ = store.TakeAuthorizationCode(context.Background(), "handle-1")
			_ = store.StoreAuthorizationCode(context.Background(), "handle-2", code)
			_, _ = store.RemoveAuthorizationCodesBySession(context.Background(), "session-1")
			_ = store.StoreAuthorizationCode(context.Background(), "handle-3", code)
			_, _ = store.RemoveAuthorizationCodesByClient(context.Background(), "client-a")
		})
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
