// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRecordStoreMethodsTakeContextCancellation verifies cancellation reaches
// the store methods. The in-memory store has no blocking I/O, so the assertion
// is that a cancelled context does not change the outcome and every method
// accepts a context.
func TestRecordStoreMethodsTakeContextCancellation(t *testing.T) {
	t.Parallel()

	store := NewMemoryRecordStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.List(ctx); err != nil {
		t.Fatalf("List with cancelled ctx: %v", err)
	}
	if _, err := store.Get(ctx, "missing"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("Get miss = %v, want ErrRecordNotFound", err)
	}
	if err := store.Delete(ctx, "missing"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("Delete miss = %v, want ErrRecordNotFound", err)
	}
}

// TestRecordStoreSentinelSemantics pins the existing sentinel contract for the
// key store family: misses are ErrRecordNotFound, never a nil record with nil
// error.
func TestRecordStoreSentinelSemantics(t *testing.T) {
	t.Parallel()

	store := NewMemoryRecordStore()
	record := &Record{
		Handle:    "h1",
		PublicID:  "kid-1",
		Purpose:   PurposeTokenSigning,
		Phase:     PhaseActive,
		CreatedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := store.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := store.Get(context.Background(), "h1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.PublicID != "kid-1" {
		t.Fatalf("Get = %+v, want record with kid-1", got)
	}
	// The store returns independent copies: mutating the returned record must
	// not affect the stored one.
	got.PublicID = "mutated"
	again, err := store.Get(context.Background(), "h1")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if again.PublicID != "kid-1" {
		t.Fatalf("stored record mutated by caller: PublicID = %q", again.PublicID)
	}
}
