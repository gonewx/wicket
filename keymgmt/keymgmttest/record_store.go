// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmttest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/keymgmt"
)

// RunRecordStoreSuite runs the conformance suite for a keymgmt.RecordStore.
// newStore must return a fresh empty store on each call.
func RunRecordStoreSuite(t *testing.T, newStore func() keymgmt.RecordStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.Get(cancelledContext(), "missing")
		expectRecordNotFound(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		rec := newKeyRecord("h1", "kid-1")
		err := store.Create(cancelledContext(), rec)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.Get(context.Background(), "h1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.Get(context.Background(), "missing")
		if got != nil {
			t.Fatalf("Get(missing) = %v, want nil record with sentinel", got)
		}
		expectRecordNotFound(t, err)
	})
	mustCase(t, "MissingDeleteReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		err := store.Delete(context.Background(), "missing")
		expectRecordNotFound(t, err)
	})
	mustCase(t, "EmptyListIsEmpty", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.List(context.Background())
		if err != nil {
			t.Fatalf("List on empty store error = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("List on empty store = %v, want empty list", got)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	// The key id is the JWKS handle; two records may not share it.
	mustCase(t, "DuplicateHandleRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newKeyRecord("h1", "kid-1")
		if err := store.Create(context.Background(), first); err != nil {
			t.Fatalf("first create: %v", err)
		}
		second := newKeyRecord("h1", "kid-2")
		if err := store.Create(context.Background(), second); !errors.Is(err, keymgmt.ErrDuplicateKey) {
			t.Fatalf("second create error = %v, want ErrDuplicateKey", err)
		}
		got, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("Get after collision: %v", err)
		}
		if got.PublicID != "kid-1" {
			t.Fatalf("stored PublicID = %q, want original %q", got.PublicID, "kid-1")
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	// A public id that is still published (non-retired) must stay unique
	// across records so a token header always resolves to one key.
	mustCase(t, "PublicIDCollisionRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newKeyRecord("h1", "kid-1")
		if err := store.Create(context.Background(), first); err != nil {
			t.Fatalf("first create: %v", err)
		}
		second := newKeyRecord("h2", "kid-1")
		if err := store.Create(context.Background(), second); !errors.Is(err, keymgmt.ErrDuplicateKey) {
			t.Fatalf("public id collision error = %v, want ErrDuplicateKey", err)
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	// A retired key no longer appears in JWKS, so its public id does not
	// block a successor key from reusing the identifier.
	mustCase(t, "RetiredPublicIDReusable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		old := newKeyRecord("h1", "kid-1")
		old.Phase = keymgmt.PhaseRetired
		if err := store.Create(context.Background(), old); err != nil {
			t.Fatalf("create retired: %v", err)
		}
		replacement := newKeyRecord("h2", "kid-1")
		if err := store.Create(context.Background(), replacement); err != nil {
			t.Fatalf("create successor with retired public id: %v", err)
		}
	})
	mustCase(t, "CreateVersionInitializedToOne", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		rec := newKeyRecord("h1", "kid-1")
		if err := store.Create(context.Background(), rec); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Version != 1 {
			t.Fatalf("stored Version = %d, want 1", got.Version)
		}
	})
	mustCase(t, "UpdateMissingReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		err := store.Update(context.Background(), newKeyRecord("ghost", "kid-9"), 1)
		expectRecordNotFound(t, err)
	})
	// Derived from: https://doi.org/10.6028/NIST.SP.800-57pt1r5
	// An optimistic-concurrency loss must leave the stored key untouched:
	// a stale writer must not clobber a rotation that already landed.
	mustCase(t, "VersionConflictKeepsRecord", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		original := newKeyRecord("h1", "kid-1")
		if err := store.Create(context.Background(), original); err != nil {
			t.Fatalf("create: %v", err)
		}
		stale := newKeyRecord("h1", "kid-2")
		err := store.Update(context.Background(), stale, 99)
		if !errors.Is(err, keymgmt.ErrVersionConflict) {
			t.Fatalf("update with wrong version = %v, want ErrVersionConflict", err)
		}
		got, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("Get after conflict: %v", err)
		}
		if got.PublicID != "kid-1" {
			t.Fatalf("stored PublicID = %q, want original %q", got.PublicID, "kid-1")
		}
		if got.Version != 1 {
			t.Fatalf("stored Version after conflict = %d, want 1", got.Version)
		}
	})
	mustCase(t, "VersionIncrementsAndWritesBack", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		rec := newKeyRecord("h1", "kid-1")
		if err := store.Create(context.Background(), rec); err != nil {
			t.Fatalf("create: %v", err)
		}
		rec.Priority = 5
		if err := store.Update(context.Background(), rec, 1); err != nil {
			t.Fatalf("update: %v", err)
		}
		if rec.Version != 2 {
			t.Fatalf("caller Version after update = %d, want 2", rec.Version)
		}
		got, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if got.Version != 2 {
			t.Fatalf("stored Version after update = %d, want 2", got.Version)
		}
		if got.Priority != 5 {
			t.Fatalf("stored Priority = %d, want 5", got.Priority)
		}
	})
	// Derived from: https://doi.org/10.6028/NIST.SP.800-57pt1r5
	// Key retirement is driven by the manager's core-side reconciliation;
	// the store retains records until an explicit Delete, including records
	// already in the retired phase, so issued tokens stay verifiable.
	mustCase(t, "RetentionCompleteness", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for phase, wantID := range map[keymgmt.Phase]string{
			keymgmt.PhaseCandidate: "kid-candidate",
			keymgmt.PhaseActive:    "kid-active",
			keymgmt.PhaseRetained:  "kid-retained",
			keymgmt.PhaseRetired:   "kid-retired",
		} {
			rec := newKeyRecord("h-"+string(phase), wantID)
			rec.Phase = phase
			if err := store.Create(context.Background(), rec); err != nil {
				t.Fatalf("create %s: %v", phase, err)
			}
		}
		listed, err := store.List(context.Background())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(listed) != 4 {
			t.Fatalf("List returned %d records, want 4 (retention until explicit delete)", len(listed))
		}
		for _, rec := range listed {
			got, err := store.Get(context.Background(), rec.Handle)
			if err != nil {
				t.Fatalf("Get(%s) after List: %v", rec.Handle, err)
			}
			if got.PublicID != rec.PublicID {
				t.Fatalf("Get(%s).PublicID = %q, want %q", rec.Handle, got.PublicID, rec.PublicID)
			}
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7517#section-4.6
	// and https://doi.org/10.6028/NIST.SP.800-57pt1r5
	// Time-based lifecycle decisions live in the manager, not the store: a
	// record whose windows lie entirely in the past must still be readable.
	mustCase(t, "StoreIsTimeAgnostic", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		rec := newKeyRecord("h1", "kid-1")
		rec.NotBefore = past
		rec.NotAfter = past.Add(time.Hour)
		if err := store.Create(context.Background(), rec); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("Get on expired-window record: %v", err)
		}
		if got == nil || got.Handle != "h1" {
			t.Fatalf("Get = %v, want the record", got)
		}
		listed, err := store.List(context.Background())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(listed) != 1 {
			t.Fatalf("List returned %d records, want 1", len(listed))
		}
	})
	// Derived from: https://www.rfc-editor.org/rfc/rfc7518#section-3.2
	// Key material is immutable from a caller's perspective: a returned
	// record must be an independent copy, so mutating it (including the
	// material slices) cannot corrupt the stored key.
	mustCase(t, "DeepCopyReturned", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		rec := newKeyRecord("h1", "kid-1")
		rec.PublicMaterial = []byte("public-bytes")
		rec.ProtectedPrivateMaterial = []byte("protected-bytes")
		if err := store.Create(context.Background(), rec); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		got.PublicID = "mutated-id"
		got.PublicMaterial[0] = 'X'
		got.ProtectedPrivateMaterial[0] = 'Y'
		again, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("second Get: %v", err)
		}
		if again.PublicID != "kid-1" {
			t.Fatalf("stored PublicID mutated by caller: %q", again.PublicID)
		}
		if string(again.PublicMaterial) != "public-bytes" {
			t.Fatalf("stored PublicMaterial mutated by caller: %q", again.PublicMaterial)
		}
		if string(again.ProtectedPrivateMaterial) != "protected-bytes" {
			t.Fatalf("stored ProtectedPrivateMaterial mutated by caller: %q", again.ProtectedPrivateMaterial)
		}
		// List results must be independent copies as well.
		listed, err := store.List(context.Background())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		listed[0].PublicID = "listed-mutation"
		listed[0].PublicMaterial[0] = 'Z'
		final, err := store.Get(context.Background(), "h1")
		if err != nil {
			t.Fatalf("final Get: %v", err)
		}
		if final.PublicID != "kid-1" || string(final.PublicMaterial) != "public-bytes" {
			t.Fatalf("stored record mutated through List result: id=%q material=%q", final.PublicID, final.PublicMaterial)
		}
	})
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		assertNoBackgroundGoroutines(t, newStore, func(store keymgmt.RecordStore) {
			_ = store.Create(context.Background(), newKeyRecord("h1", "kid-1"))
			_, _ = store.Get(context.Background(), "h1")
			_ = store.Delete(context.Background(), "h1")
		})
	})
	// Derived from: https://doi.org/10.6028/NIST.SP.800-57pt1r5
	// Concurrent rotation: two writers on the same version must not both
	// succeed; exactly one wins the optimistic-concurrency race.
	cfg.mayCase(t, "ConcurrentUpdateSingleWinner", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.Create(context.Background(), newKeyRecord("h1", "kid-1")); err != nil {
			t.Fatalf("create: %v", err)
		}
		const workers = 2
		var wg sync.WaitGroup
		results := make(chan error, workers)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- store.Update(context.Background(), newKeyRecord("h1", "kid-2"), 1)
			}()
		}
		wg.Wait()
		close(results)
		winners := 0
		conflicts := 0
		for err := range results {
			switch {
			case err == nil:
				winners++
			case errors.Is(err, keymgmt.ErrVersionConflict):
				conflicts++
			default:
				t.Fatalf("unexpected update error: %v", err)
			}
		}
		if winners != 1 || conflicts != 1 {
			t.Fatalf("winners = %d, conflicts = %d, want exactly 1 each", winners, conflicts)
		}
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newKeyRecord(handle, publicID string) *keymgmt.Record {
	return &keymgmt.Record{
		Handle:         handle,
		PublicID:       publicID,
		Purpose:        keymgmt.PurposeTokenSigning,
		Algorithm:      "RS256",
		Phase:          keymgmt.PhaseActive,
		CreatedAt:      time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:      time.Time{},
		NotAfter:       time.Time{},
		PublicMaterial: []byte("public-bytes"),
	}
}
