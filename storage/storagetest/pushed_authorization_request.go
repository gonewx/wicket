// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// pushedAuthorizationKeyShape is the form of every key
// storage.PushedAuthorizationRequestKey returns.
var pushedAuthorizationKeyShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// RunPushedAuthorizationRequestStoreSuite runs the conformance suite for a
// storage.PushedAuthorizationRequestStore. newStore must return a fresh empty
// store on each call. Every key the suite uses comes from
// storage.PushedAuthorizationRequestKey, the way the core derives them.
func RunPushedAuthorizationRequestStoreSuite(t *testing.T, newStore func() storage.PushedAuthorizationRequestStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "KeyShape", func(t *testing.T) {
		t.Parallel()
		first := pushedAuthorizationKey(t, "first")
		again := pushedAuthorizationKey(t, "first")
		second := pushedAuthorizationKey(t, "second")
		for _, key := range []string{first, second} {
			if !pushedAuthorizationKeyShape.MatchString(key) {
				t.Fatalf("key %q is not 43 characters of [A-Za-z0-9_-]", key)
			}
		}
		if first != again {
			t.Fatalf("key derivation is not deterministic: %q then %q", first, again)
		}
		if first == second {
			t.Fatalf("different request_uris share key %q", first)
		}
	})
	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.GetPushedAuthorizationRequest(cancelledContext(), pushedAuthorizationKey(t, "missing"))
		assertCancellationReadMiss(t, err)
		_, err = store.TakePushedAuthorizationRequest(cancelledContext(), pushedAuthorizationKey(t, "missing"))
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "handle-1")
		err := store.StorePushedAuthorizationRequest(cancelledContext(), key, newPushedAuthorizationRequest("client-a"))
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.GetPushedAuthorizationRequest(context.Background(), key)
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetPushedAuthorizationRequest(context.Background(), pushedAuthorizationKey(t, "missing"))
		if got != nil {
			t.Fatalf("Get(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "TakeMissingReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.TakePushedAuthorizationRequest(context.Background(), pushedAuthorizationKey(t, "missing"))
		if got != nil {
			t.Fatalf("Take(missing) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "MissingReadAfterOtherWriteReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.StorePushedAuthorizationRequest(context.Background(), pushedAuthorizationKey(t, "present"), newPushedAuthorizationRequest("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		missing := pushedAuthorizationKey(t, "absent")
		got, err := store.GetPushedAuthorizationRequest(context.Background(), missing)
		if got != nil {
			t.Fatalf("Get(absent) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
		got, err = store.TakePushedAuthorizationRequest(context.Background(), missing)
		if got != nil {
			t.Fatalf("Take(absent) = %v, want nil record with sentinel", got)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "WriteRoundTrip", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "handle-1")
		want := newPushedAuthorizationRequest("client-a")
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, want); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.GetPushedAuthorizationRequest(context.Background(), key)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		expectPushedAuthorizationRequest(t, got, want)
	})
	mustCase(t, "DuplicateHandleRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "handle-1")
		first := newPushedAuthorizationRequest("client-a")
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, first); err != nil {
			t.Fatalf("first store: %v", err)
		}
		second := newPushedAuthorizationRequest("client-b")
		second.Payload = []byte("other-payload")
		second.EntryExpiration = fixedAlive.Add(time.Hour)
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, second); !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("second store error = %v, want ErrDuplicateHandle", err)
		}
		got, err := store.GetPushedAuthorizationRequest(context.Background(), key)
		if err != nil {
			t.Fatalf("get after collision: %v", err)
		}
		expectPushedAuthorizationRequest(t, got, first)
	})
	mustCase(t, "GetDoesNotConsume", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "handle-1")
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, newPushedAuthorizationRequest("client-a")); err != nil {
			t.Fatalf("store: %v", err)
		}
		for i := 0; i < 2; i++ {
			got, err := store.GetPushedAuthorizationRequest(context.Background(), key)
			if err != nil || got == nil || got.ClientId != "client-a" {
				t.Fatalf("get %d = %v, %v; want the stored request", i+1, got, err)
			}
		}
		got, err := store.TakePushedAuthorizationRequest(context.Background(), key)
		if err != nil || got == nil || got.ClientId != "client-a" {
			t.Fatalf("take after reads = %v, %v; want the stored request", got, err)
		}
	})
	// A pushed request is consumed once: of many simultaneous takes of one
	// key exactly one obtains the record. Each round releases all takers at
	// once from a closed channel; a store whose take is a lookup followed by
	// a separate delete lets more than one through.
	mustCase(t, "TakeExactlyOnceUnderConcurrency", func(t *testing.T) {
		t.Parallel()
		key := pushedAuthorizationKey(t, "handle-1")
		otherKey := pushedAuthorizationKey(t, "handle-other")
		for round := 0; round < takeRounds; round++ {
			store := newStore()
			if err := store.StorePushedAuthorizationRequest(context.Background(), key, newPushedAuthorizationRequest("client-a")); err != nil {
				t.Fatalf("round %d store: %v", round, err)
			}
			if err := store.StorePushedAuthorizationRequest(context.Background(), otherKey, newPushedAuthorizationRequest("client-b")); err != nil {
				t.Fatalf("round %d store other: %v", round, err)
			}
			start := make(chan struct{})
			type outcome struct {
				request *models.PushedAuthorizationRequest
				err     error
			}
			results := make([]outcome, takeConcurrency)
			var wg sync.WaitGroup
			for i := 0; i < takeConcurrency; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					request, err := store.TakePushedAuthorizationRequest(context.Background(), key)
					results[i] = outcome{request: request, err: err}
				}(i)
			}
			close(start)
			wg.Wait()
			winners := 0
			for i, r := range results {
				switch {
				case r.err == nil:
					if r.request == nil || r.request.ClientId != "client-a" {
						t.Fatalf("round %d taker %d: Take returned %v with nil error, want the stored request", round, i, r.request)
					}
					winners++
				case errors.Is(r.err, storage.ErrNotFound):
					if r.request != nil {
						t.Fatalf("round %d taker %d: Take returned a record alongside ErrNotFound", round, i)
					}
				default:
					t.Fatalf("round %d taker %d: Take error = %v, want nil or ErrNotFound", round, i, r.err)
				}
			}
			if winners != 1 {
				t.Fatalf("round %d: %d of %d concurrent takes obtained the request, want exactly 1", round, winners, takeConcurrency)
			}
			_, err := store.GetPushedAuthorizationRequest(context.Background(), key)
			expectNotFound(t, err)
			other, err := store.GetPushedAuthorizationRequest(context.Background(), otherKey)
			if err != nil || other == nil || other.ClientId != "client-b" {
				t.Fatalf("round %d: untaken key = %v, %v; want the client-b request", round, other, err)
			}
		}
	})
	mustCase(t, "TakeConsumes", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "handle-1")
		want := newPushedAuthorizationRequest("client-a")
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, want); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.TakePushedAuthorizationRequest(context.Background(), key)
		if err != nil {
			t.Fatalf("take: %v", err)
		}
		expectPushedAuthorizationRequest(t, got, want)
		_, err = store.GetPushedAuthorizationRequest(context.Background(), key)
		expectNotFound(t, err)
		again, err := store.TakePushedAuthorizationRequest(context.Background(), key)
		if again != nil {
			t.Fatalf("second take = %v, want nil record with sentinel", again)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "ExpiredRecordStillReadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "handle-1")
		request := newPushedAuthorizationRequest("client-a")
		request.CreationTime = fixedExpired
		request.EntryExpiration = fixedExpired.Add(time.Minute)
		request.RetentionExpiration = fixedExpired.Add(10 * time.Minute)
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, request); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, err := store.GetPushedAuthorizationRequest(context.Background(), key)
		if err != nil {
			t.Fatalf("expired request not readable: %v", err)
		}
		expectPushedAuthorizationRequest(t, got, request)
		got, err = store.TakePushedAuthorizationRequest(context.Background(), key)
		if err != nil {
			t.Fatalf("expired request not takeable: %v", err)
		}
		expectPushedAuthorizationRequest(t, got, request)
	})
	// RetentionExpiration, not EntryExpiration, drives reclamation: a
	// handle whose entry validity has lapsed may still be mid interaction
	// round trip, and its record must survive until the retention ends.
	mustCase(t, "RemoveExpiredKeepsRecordsInRoundTrip", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "in-round-trip")
		request := newPushedAuthorizationRequest("client-a")
		request.CreationTime = fixedNow.Add(-2 * time.Minute)
		request.EntryExpiration = fixedNow.Add(-time.Minute)
		request.RetentionExpiration = fixedNow.Add(10 * time.Minute)
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, request); err != nil {
			t.Fatalf("store: %v", err)
		}
		count, err := store.RemoveExpired(context.Background(), fixedNow)
		if err != nil {
			t.Fatalf("RemoveExpired: %v", err)
		}
		if count != 0 {
			t.Fatalf("RemoveExpired count = %d, want 0", count)
		}
		if _, err := store.GetPushedAuthorizationRequest(context.Background(), key); err != nil {
			t.Fatalf("request within its retention removed: %v", err)
		}
	})
	mustCase(t, "RemoveExpiredReclaimsExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newPushedAuthorizationRequest("client-a")
		expired.CreationTime = fixedExpired
		expired.EntryExpiration = fixedExpired.Add(time.Minute)
		expired.RetentionExpiration = fixedExpired.Add(10 * time.Minute)
		inRoundTrip := newPushedAuthorizationRequest("client-b")
		inRoundTrip.CreationTime = fixedNow.Add(-2 * time.Minute)
		inRoundTrip.EntryExpiration = fixedNow.Add(-time.Minute)
		inRoundTrip.RetentionExpiration = fixedNow.Add(10 * time.Minute)
		boundary := newPushedAuthorizationRequest("client-c")
		boundary.CreationTime = fixedNow.Add(-10 * time.Minute)
		boundary.EntryExpiration = fixedNow.Add(-5 * time.Minute)
		boundary.RetentionExpiration = fixedNow
		for _, r := range []*models.PushedAuthorizationRequest{expired, inRoundTrip, boundary} {
			if err := store.StorePushedAuthorizationRequest(context.Background(), pushedAuthorizationKey(t, r.ClientId), r); err != nil {
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
		_, err = store.GetPushedAuthorizationRequest(context.Background(), pushedAuthorizationKey(t, "client-a"))
		expectNotFound(t, err)
		if _, err := store.GetPushedAuthorizationRequest(context.Background(), pushedAuthorizationKey(t, "client-b")); err != nil {
			t.Fatalf("request within its retention removed: %v", err)
		}
		if _, err := store.GetPushedAuthorizationRequest(context.Background(), pushedAuthorizationKey(t, "client-c")); err != nil {
			t.Fatalf("request retained exactly until the cutoff removed: %v", err)
		}
	})
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		key := pushedAuthorizationKey(t, "handle-1")
		other := pushedAuthorizationKey(t, "handle-2")
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.PushedAuthorizationRequestStore) {
			_ = store.StorePushedAuthorizationRequest(context.Background(), key, newPushedAuthorizationRequest("client-a"))
			_, _ = store.GetPushedAuthorizationRequest(context.Background(), key)
			_, _ = store.TakePushedAuthorizationRequest(context.Background(), key)
			_ = store.StorePushedAuthorizationRequest(context.Background(), other, newPushedAuthorizationRequest("client-a"))
			_, _ = store.RemoveExpired(context.Background(), fixedNow)
		})
	})
	cfg.mayCase(t, "ReturnedCopyIsolated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		key := pushedAuthorizationKey(t, "handle-1")
		want := newPushedAuthorizationRequest("client-a")
		written := newPushedAuthorizationRequest("client-a")
		if err := store.StorePushedAuthorizationRequest(context.Background(), key, written); err != nil {
			t.Fatalf("store: %v", err)
		}
		written.Payload[0] ^= 0xff
		written.ClientId = "changed"
		got, err := store.GetPushedAuthorizationRequest(context.Background(), key)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		expectPushedAuthorizationRequest(t, got, want)
		got.Payload[0] ^= 0xff
		got.ClientId = "changed"
		got, err = store.GetPushedAuthorizationRequest(context.Background(), key)
		if err != nil {
			t.Fatalf("get again: %v", err)
		}
		expectPushedAuthorizationRequest(t, got, want)
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

// pushedAuthorizationKey derives the store key of the request_uri with the
// given suffix through the one key function the core uses.
func pushedAuthorizationKey(t *testing.T, suffix string) string {
	t.Helper()
	key, err := storage.PushedAuthorizationRequestKey(storage.PushedAuthorizationRequestURIPrefix + suffix)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	return key
}

func newPushedAuthorizationRequest(clientId string) *models.PushedAuthorizationRequest {
	return &models.PushedAuthorizationRequest{
		ClientId:            clientId,
		CreationTime:        fixedNow,
		EntryExpiration:     fixedNow.Add(90 * time.Second),
		RetentionExpiration: fixedNow.Add(15 * time.Minute),
		Payload:             []byte("opaque-protected-payload\x00\xff"),
	}
}

func expectPushedAuthorizationRequest(t *testing.T, got, want *models.PushedAuthorizationRequest) {
	t.Helper()
	if got == nil {
		t.Fatal("request is nil")
	}
	if got.ClientId != want.ClientId {
		t.Fatalf("ClientId = %q, want %q", got.ClientId, want.ClientId)
	}
	if !got.CreationTime.Equal(want.CreationTime) {
		t.Fatalf("CreationTime = %v, want %v", got.CreationTime, want.CreationTime)
	}
	if !got.EntryExpiration.Equal(want.EntryExpiration) {
		t.Fatalf("EntryExpiration = %v, want %v", got.EntryExpiration, want.EntryExpiration)
	}
	if !got.RetentionExpiration.Equal(want.RetentionExpiration) {
		t.Fatalf("RetentionExpiration = %v, want %v", got.RetentionExpiration, want.RetentionExpiration)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("Payload = %q, want %q", got.Payload, want.Payload)
	}
}
