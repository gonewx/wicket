// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package sessiontest

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/gonewx/wicket/session"
)

// RunSessionStoreSuite runs the conformance suite for a session.Store.
// newStore must return a fresh empty store on each call.
func RunSessionStoreSuite(t *testing.T, newStore func() session.Store, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.GetSession(cancelledContext(), "missing")
		expectSessionNotFound(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		rec := newSessionRecord("s1", "u1")
		err := store.CreateSession(cancelledContext(), rec)
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.GetSession(context.Background(), "s1")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetSession(context.Background(), "missing")
		if got != nil {
			t.Fatalf("GetSession(missing) = %v, want nil record with sentinel", got)
		}
		expectSessionNotFound(t, err)
	})
	mustCase(t, "SubjectQueryUnknownSubjectEmpty", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		got, err := store.GetSessionsBySubjectID(context.Background(), "nobody")
		if err != nil {
			t.Fatalf("GetSessionsBySubjectID(unknown) error = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("GetSessionsBySubjectID(unknown) = %v, want empty list", got)
		}
	})
	// Derived from: https://openid.net/specs/openid-connect-session-1_0.html
	// The session record tracks the relying parties it was established with;
	// appending a client id must be idempotent and never duplicate.
	mustCase(t, "AddClientIDAppendsDeduplicated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.CreateSession(context.Background(), newSessionRecord("s1", "u1")); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := store.AddClientID(context.Background(), "s1", "c1"); err != nil {
			t.Fatalf("add c1: %v", err)
		}
		if err := store.AddClientID(context.Background(), "s1", "c1"); err != nil {
			t.Fatalf("add c1 again: %v", err)
		}
		if err := store.AddClientID(context.Background(), "s1", "c2"); err != nil {
			t.Fatalf("add c2: %v", err)
		}
		got, err := store.GetSession(context.Background(), "s1")
		if err != nil {
			t.Fatalf("get after adds: %v", err)
		}
		if len(got.ClientIDs) != 2 || got.ClientIDs[0] != "c1" || got.ClientIDs[1] != "c2" {
			t.Fatalf("ClientIDs = %v, want [c1 c2]", got.ClientIDs)
		}
	})
	// Derived from: https://openid.net/specs/openid-connect-session-1_0.html
	// A session is bound to its establishing relying party list; the store
	// must not let an update of unrelated fields replace that list silently.
	mustCase(t, "UpdateSessionAppliesChanges", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		rec := newSessionRecord("s1", "u1")
		if err := store.CreateSession(context.Background(), rec); err != nil {
			t.Fatalf("create: %v", err)
		}
		updated := *rec
		updated.DisplayName = "renamed"
		updated.ClientIDs = []string{"c1"}
		if err := store.UpdateSession(context.Background(), &updated); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := store.GetSession(context.Background(), "s1")
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.DisplayName != "renamed" {
			t.Fatalf("DisplayName = %q, want %q", got.DisplayName, "renamed")
		}
		if len(got.ClientIDs) != 1 || got.ClientIDs[0] != "c1" {
			t.Fatalf("ClientIDs = %v, want [c1]", got.ClientIDs)
		}
	})
	mustCase(t, "CreateSessionInsertOnly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		first := newSessionRecord("s1", "u1")
		if err := store.CreateSession(context.Background(), first); err != nil {
			t.Fatalf("first create: %v", err)
		}
		second := newSessionRecord("s1", "u2")
		if err := store.CreateSession(context.Background(), second); err == nil {
			t.Fatal("second create with same id returned nil error")
		}
		got, err := store.GetSession(context.Background(), "s1")
		if err != nil {
			t.Fatalf("get after collision: %v", err)
		}
		if got.SubjectID != "u1" {
			t.Fatalf("stored SubjectID = %q, want original %q", got.SubjectID, "u1")
		}
		// The failed write must leave the subject index free of a duplicate
		// entry: the rejected subject resolves to no sessions.
		rejected, err := store.GetSessionsBySubjectID(context.Background(), "u2")
		if err != nil {
			t.Fatalf("subject query after collision: %v", err)
		}
		if len(rejected) != 0 {
			t.Fatalf("rejected subject resolves to %d sessions, want 0", len(rejected))
		}
	})
	mustCase(t, "UpdateSessionMissingIsNoOp", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.UpdateSession(context.Background(), newSessionRecord("ghost", "u1")); err != nil {
			t.Fatalf("update missing session error = %v, want nil no-op", err)
		}
		got, err := store.GetSession(context.Background(), "ghost")
		if got != nil || !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("update must not create the session: got=%v err=%v", got, err)
		}
	})
	mustCase(t, "DeleteSessionMissingIsNoOp", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.DeleteSession(context.Background(), "ghost"); err != nil {
			t.Fatalf("delete missing session error = %v, want nil no-op", err)
		}
	})
	mustCase(t, "AddClientIDMissingIsNoOp", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.AddClientID(context.Background(), "ghost", "c1"); err != nil {
			t.Fatalf("add client to missing session error = %v, want nil no-op", err)
		}
	})
	mustCase(t, "ReclaimBoundaryStrictlyBefore", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		expired := newSessionRecord("expired", "u1")
		expired.Expires = fixedPast
		boundary := newSessionRecord("boundary", "u1")
		boundary.Expires = fixedNow
		alive := newSessionRecord("alive", "u1")
		alive.Expires = fixedFuture
		noExpiry := newSessionRecord("no-expiry", "u1")
		for _, rec := range []*session.Record{expired, boundary, alive, noExpiry} {
			if err := store.CreateSession(context.Background(), rec); err != nil {
				t.Fatalf("create %s: %v", rec.SessionID, err)
			}
		}
		count, err := store.DeleteExpired(context.Background(), fixedNow)
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if count != 1 {
			t.Fatalf("DeleteExpired count = %d, want 1 (only the strictly-before record)", count)
		}
		if _, err := store.GetSession(context.Background(), "expired"); !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("expired session still present: %v", err)
		}
		for _, id := range []string{"boundary", "alive", "no-expiry"} {
			if _, err := store.GetSession(context.Background(), id); err != nil {
				t.Fatalf("session %s removed: %v", id, err)
			}
		}
	})
	// Derived from: https://openid.net/specs/openid-connect-backchannel-1_0.html
	// A back-channel logout event terminates the subject's sessions; the
	// storage face of that event removes every session of the subject.
	mustCase(t, "SubjectLogoutRemovesAllSessions", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		for i := range 3 {
			if err := store.CreateSession(context.Background(), newSessionRecord("s"+string(rune('1'+i)), "u1")); err != nil {
				t.Fatalf("create: %v", err)
			}
		}
		if err := store.CreateSession(context.Background(), newSessionRecord("other", "u2")); err != nil {
			t.Fatalf("create other: %v", err)
		}
		count, err := store.DeleteSessionsBySubjectID(context.Background(), "u1")
		if err != nil {
			t.Fatalf("delete by subject: %v", err)
		}
		if count != 3 {
			t.Fatalf("deleted count = %d, want 3", count)
		}
		left, err := store.GetSessionsBySubjectID(context.Background(), "u1")
		if err != nil {
			t.Fatalf("subject query after logout: %v", err)
		}
		if len(left) != 0 {
			t.Fatalf("subject u1 still resolves to %d sessions, want 0", len(left))
		}
		if _, err := store.GetSession(context.Background(), "other"); err != nil {
			t.Fatalf("unrelated subject session removed: %v", err)
		}
	})
	// Derived from: https://openid.net/specs/openid-connect-backchannel-1_0.html
	// A logout terminates the session; the storage face must make the record
	// unreadable afterwards, exactly like a revocation.
	mustCase(t, "SessionLogoutRemovesRecord", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.CreateSession(context.Background(), newSessionRecord("s1", "u1")); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := store.DeleteSession(context.Background(), "s1"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		got, err := store.GetSession(context.Background(), "s1")
		if got != nil {
			t.Fatalf("logged-out session = %v, want nil", got)
		}
		expectSessionNotFound(t, err)
	})
	// Expiry judgement lives in the core-side coordinator, not in the store:
	// an expired record is reported invalid and removed, a live record is
	// reported valid with its renewal stamped from the injected clock.
	mustCase(t, "ExpiryJudgementLivesInCoordinator", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		coord := session.NewCoordinator(store, suiteClockAt, true)

		expired := newSessionRecord("expired", "u1")
		expired.Expires = fixedPast
		if err := store.CreateSession(context.Background(), expired); err != nil {
			t.Fatalf("create expired: %v", err)
		}
		valid, err := coord.ValidateSession(context.Background(), "expired")
		if err != nil {
			t.Fatalf("validate expired: %v", err)
		}
		if valid {
			t.Fatal("expired session reported valid")
		}
		if _, err := store.GetSession(context.Background(), "expired"); !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("expired session not removed after validation: %v", err)
		}

		alive := newSessionRecord("alive", "u2")
		alive.Expires = fixedFuture
		if err := store.CreateSession(context.Background(), alive); err != nil {
			t.Fatalf("create alive: %v", err)
		}
		valid, err = coord.ValidateSession(context.Background(), "alive")
		if err != nil {
			t.Fatalf("validate alive: %v", err)
		}
		if !valid {
			t.Fatal("live session reported invalid")
		}
		got, err := store.GetSession(context.Background(), "alive")
		if err != nil {
			t.Fatalf("get after renewal: %v", err)
		}
		if !got.Renewed.Equal(fixedNow) {
			t.Fatalf("Renewed = %v, want injected clock value %v", got.Renewed, fixedNow)
		}
	})
	// Lazy reclamation is an optimization of the suite's own memory store:
	// a read of an expired record reports the sentinel and reclaims the
	// record. External adapters may opt in or skip this behavior.
	cfg.mayCase(t, "LazyExpiryReclaimsOnRead", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		rec := newSessionRecord("s1", "u1")
		rec.Expires = fixedPast
		if err := store.CreateSession(context.Background(), rec); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := store.GetSession(context.Background(), "s1")
		if got != nil || !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("expired session read = (%v, %v), want (nil, sentinel)", got, err)
		}
		left, err := store.GetSessionsBySubjectID(context.Background(), "u1")
		if err != nil {
			t.Fatalf("subject query: %v", err)
		}
		if len(left) != 0 {
			t.Fatalf("reclaimed session still listed: %v", left)
		}
	})
	cfg.mayCase(t, "ConcurrentAddClientIDAllCollected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		if err := store.CreateSession(context.Background(), newSessionRecord("s1", "u1")); err != nil {
			t.Fatalf("create: %v", err)
		}
		const workers = 8
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				_ = store.AddClientID(context.Background(), "s1", "c"+string(rune('a'+n)))
			}(i)
		}
		wg.Wait()
		got, err := store.GetSession(context.Background(), "s1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.ClientIDs) != workers {
			t.Fatalf("collected %d client ids, want %d (no loss under concurrency)", len(got.ClientIDs), workers)
		}
	})
	cfg.mayCase(t, "ConcurrentCreateSessionSingleWinner", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		const workers = 8
		var wg sync.WaitGroup
		successes := make(chan bool, workers)
		for i := range workers {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				err := store.CreateSession(context.Background(), newSessionRecord("s1", "u"+string(rune('a'+n))))
				successes <- err == nil
			}(i)
		}
		wg.Wait()
		close(successes)
		winners := 0
		for ok := range successes {
			if ok {
				winners++
			}
		}
		if winners != 1 {
			t.Fatalf("%d concurrent creates succeeded, want exactly 1", winners)
		}
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

func newSessionRecord(sessionID, subjectID string) *session.Record {
	return &session.Record{
		SessionID: sessionID,
		SubjectID: subjectID,
		Created:   fixedNow,
		Renewed:   fixedNow,
		Expires:   fixedFuture,
	}
}
