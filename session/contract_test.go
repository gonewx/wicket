// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fixedTestClock is a deterministic time source for session expiry semantics.
type fixedTestClock struct {
	now time.Time
}

func (c fixedTestClock) Now() time.Time { return c.now }

func TestMemoryStoreDeleteExpired(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(fixedTestClock{now: cutoff})
	expired := &Record{SessionID: "expired", SubjectID: "u1", Expires: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	future := &Record{SessionID: "future", SubjectID: "u1", Expires: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	noExpiry := &Record{SessionID: "no-expiry", SubjectID: "u1"}
	for _, rec := range []*Record{expired, future, noExpiry} {
		if err := store.CreateSession(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}

	count, err := store.DeleteExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if count != 1 {
		t.Fatalf("DeleteExpired count = %d, want 1", count)
	}
	if _, err := store.GetSession(context.Background(), "expired"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired session still present, err = %v", err)
	}
	if _, err := store.GetSession(context.Background(), "future"); err != nil {
		t.Fatalf("future session removed: %v", err)
	}
	if _, err := store.GetSession(context.Background(), "no-expiry"); err != nil {
		t.Fatalf("session without expiry removed: %v", err)
	}
}

// TestDeleteExpiredCutoffBoundary pins the strictly-before semantics: a session
// expiring exactly at the cutoff survives reclamation, because expiry judgement
// belongs to the core side.
func TestDeleteExpiredCutoffBoundary(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(fixedTestClock{now: cutoff})
	exact := &Record{SessionID: "exact", SubjectID: "u1", Expires: cutoff}
	if err := store.CreateSession(context.Background(), exact); err != nil {
		t.Fatal(err)
	}

	count, err := store.DeleteExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if count != 0 {
		t.Fatalf("DeleteExpired count = %d, want 0", count)
	}
}

// TestGetSessionMissReturnsSentinel pins the missing-record semantics: a miss is
// ErrSessionNotFound, never a nil record with a nil error.
func TestGetSessionMissReturnsSentinel(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(fixedTestClock{now: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)})
	if _, err := store.GetSession(context.Background(), "missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("GetSession miss error = %v, want ErrSessionNotFound", err)
	}
}

// TestLazyExpiryStillReturnsSentinel pins the retained lazy-expiry behavior: an
// expired session is deleted and reported as missing via the sentinel, using the
// store's own injected clock.
func TestLazyExpiryStillReturnsSentinel(t *testing.T) {
	t.Parallel()

	clock := &fixedTestClock{now: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	store := NewMemoryStore(clock)
	if err := store.CreateSession(context.Background(), &Record{SessionID: "s1", SubjectID: "u1", Expires: clock.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Hour)

	got, err := store.GetSession(context.Background(), "s1")
	if got != nil || !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired session = (%v, %v), want (nil, ErrSessionNotFound)", got, err)
	}
}
