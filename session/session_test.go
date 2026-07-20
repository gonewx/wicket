// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
}

func TestRecordExpiry(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	for name, tt := range map[string]struct {
		expires time.Time
		advance time.Duration
		want    bool
	}{
		"not expired": {
			expires: clock.Now().Add(time.Hour),
			advance: 0,
			want:    false,
		},
		"expired": {
			expires: clock.Now().Add(time.Hour),
			advance: 2 * time.Hour,
			want:    true,
		},
		"exact boundary": {
			expires: clock.Now().Add(time.Hour),
			advance: time.Hour + time.Nanosecond,
			want:    true,
		},
		"zero expires never expired": {
			expires: time.Time{},
			advance: 999 * time.Hour,
			want:    false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := &Record{Expires: tt.expires}
			checkTime := clock.Now().Add(tt.advance)
			if got := rec.IsExpired(checkTime); got != tt.want {
				t.Fatalf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordAddClientID(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		initial  []string
		add      string
		wantNew  bool
		wantList []string
	}{
		"add to empty": {
			initial: nil, add: "c1", wantNew: true, wantList: []string{"c1"},
		},
		"add duplicate": {
			initial: []string{"c1"}, add: "c1", wantNew: false, wantList: []string{"c1"},
		},
		"add second": {
			initial: []string{"c1"}, add: "c2", wantNew: true, wantList: []string{"c1", "c2"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := &Record{ClientIDs: append([]string(nil), tt.initial...)}
			got := rec.AddClientID(tt.add)
			if got != tt.wantNew {
				t.Fatalf("AddClientID() = %v, want %v", got, tt.wantNew)
			}
			if len(rec.ClientIDs) != len(tt.wantList) {
				t.Fatalf("ClientIDs = %v, want %v", rec.ClientIDs, tt.wantList)
			}
		})
	}
}

func TestMemoryStoreLifecycle(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)

	rec := &Record{
		SessionID: "s1",
		SubjectID: "u1",
		Created:   clock.Now(),
		Renewed:   clock.Now(),
		Expires:   clock.Now().Add(24 * time.Hour),
		ClientIDs: []string{"c1"},
	}

	if err := store.CreateSession(rec); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := store.GetSession("s1")
	if err != nil || got == nil {
		t.Fatalf("GetSession: got=%v, err=%v", got, err)
	}
	if got.SubjectID != "u1" {
		t.Fatalf("SubjectID = %q, want u1", got.SubjectID)
	}
	if len(got.ClientIDs) != 1 || got.ClientIDs[0] != "c1" {
		t.Fatalf("ClientIDs = %v, want [c1]", got.ClientIDs)
	}

	got.ClientIDs = append(got.ClientIDs, "c2")
	got.Renewed = clock.Now().Add(time.Minute)
	if err := store.UpdateSession(got); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}

	got2, _ := store.GetSession("s1")
	if len(got2.ClientIDs) != 2 {
		t.Fatalf("after update ClientIDs = %v, want 2 entries", got2.ClientIDs)
	}

	if err := store.DeleteSession("s1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	got3, _ := store.GetSession("s1")
	if got3 != nil {
		t.Fatal("session should be nil after delete")
	}
}

func TestMemoryStoreCreateCollision(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)

	rec := &Record{SessionID: "s1", SubjectID: "u1", Expires: clock.Now().Add(time.Hour)}
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(rec); err == nil {
		t.Fatal("expected collision error")
	}
}

func TestMemoryStoreDeleteIdempotent(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(newTestClock())
	if err := store.DeleteSession("nonexistent"); err != nil {
		t.Fatalf("delete nonexistent: %v", err)
	}
}

func TestMemoryStoreGetSessionNotFound(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(newTestClock())
	got, err := store.GetSession("nope")
	if err != nil || got != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestMemoryStoreLazyExpiry(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)

	rec := &Record{
		SessionID: "s1",
		SubjectID: "u1",
		Expires:   clock.Now().Add(time.Hour),
	}
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}

	clock.Advance(2 * time.Hour)

	got, err := store.GetSession("s1")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expired session should return nil")
	}
}

func TestMemoryStoreSubjectQueries(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)

	for i := range 3 {
		rec := &Record{
			SessionID: fmt.Sprintf("s%d", i),
			SubjectID: "u1",
			Expires:   clock.Now().Add(24 * time.Hour),
		}
		if err := store.CreateSession(rec); err != nil {
			t.Fatal(err)
		}
	}

	sessions, err := store.GetSessionsBySubjectID("u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 3 {
		t.Fatalf("GetBySubjectID: got %d, want 3", len(sessions))
	}

	count, err := store.DeleteSessionsBySubjectID("u1")
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("DeleteBySubjectID: got %d, want 3", count)
	}

	sessions2, _ := store.GetSessionsBySubjectID("u1")
	if len(sessions2) != 0 {
		t.Fatalf("after delete, got %d sessions", len(sessions2))
	}
}

// TestMemoryStoreDeleteIfExpiredSkipsRenewed guards the TOCTOU fix: a session
// flagged expired during an unlocked subject scan must survive if it is renewed
// (its Expires pushed into the future) before the deferred cleanup runs. The
// re-check under the write lock is what prevents deleting a just-renewed session.
func TestMemoryStoreDeleteIfExpiredSkipsRenewed(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)

	rec := &Record{
		SessionID: "s1",
		SubjectID: "u1",
		Expires:   clock.Now().Add(time.Hour),
	}
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}

	// Move past expiry so the record is currently expired.
	clock.Advance(2 * time.Hour)

	// Simulate a concurrent renewal landing before the deferred cleanup:
	// the stored record's Expires is pushed back into the future.
	renewed := *rec
	renewed.Expires = clock.Now().Add(time.Hour)
	if err := store.UpdateSession(&renewed); err != nil {
		t.Fatal(err)
	}

	// deleteIfExpired must observe the renewed (non-expired) record and leave it.
	store.deleteIfExpired("s1")

	got, err := store.GetSession("s1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("renewed session was deleted; deleteIfExpired must re-check expiry under the lock")
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sid := fmt.Sprintf("s%d", id)
			rec := &Record{
				SessionID: sid,
				SubjectID: fmt.Sprintf("u%d", id%5),
				Expires:   clock.Now().Add(24 * time.Hour),
			}
			_ = store.CreateSession(rec)
			_, _ = store.GetSession(sid)
			rec.Renewed = clock.Now()
			_ = store.UpdateSession(rec)
			_ = store.DeleteSession(sid)
		}(i)
	}
	wg.Wait()
}

func TestCoordinatorDisabled(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		sessionID string
	}{
		"nil input":      {sessionID: ""},
		"any session id": {sessionID: "some-id"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			coord := NewCoordinator(nil, newTestClock(), false)
			valid, err := coord.ValidateSession(tt.sessionID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !valid {
				t.Fatal("disabled coordinator should return true")
			}
		})
	}
}

func TestCoordinatorEnabledValidSession(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)
	coord := NewCoordinator(store, clock, true)

	rec := &Record{
		SessionID: "s1",
		SubjectID: "u1",
		Created:   clock.Now(),
		Renewed:   clock.Now(),
		Expires:   clock.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}

	valid, err := coord.ValidateSession("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Fatal("valid session should return true")
	}
}

func TestCoordinatorEnabledExpiredSession(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)
	coord := NewCoordinator(store, clock, true)

	rec := &Record{
		SessionID: "s1",
		SubjectID: "u1",
		Expires:   clock.Now().Add(time.Hour),
	}
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}

	clock.Advance(2 * time.Hour)

	valid, err := coord.ValidateSession("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expired session should return false")
	}

	got, _ := store.GetSession("s1")
	if got != nil {
		t.Fatal("expired session should be deleted from store")
	}
}

func TestCoordinatorEnabledMissingSession(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)
	coord := NewCoordinator(store, clock, true)

	valid, err := coord.ValidateSession("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("missing session should return false")
	}
}

func TestCoordinatorEnabledStoreError(t *testing.T) {
	t.Parallel()

	coord := NewCoordinator(&failingStore{}, newTestClock(), true)

	valid, err := coord.ValidateSession("s1")
	if err == nil {
		t.Fatal("expected store error")
	}
	if valid {
		t.Fatal("store error should return false (fail-closed)")
	}
}

type failingStore struct{}

func (failingStore) GetSession(string) (*Record, error) { return nil, fmt.Errorf("store unavailable") }
func (failingStore) CreateSession(*Record) error        { return fmt.Errorf("store unavailable") }
func (failingStore) UpdateSession(*Record) error        { return fmt.Errorf("store unavailable") }
func (failingStore) DeleteSession(string) error         { return fmt.Errorf("store unavailable") }
func (failingStore) GetSessionsBySubjectID(string) ([]*Record, error) {
	return nil, fmt.Errorf("store unavailable")
}
func (failingStore) DeleteSessionsBySubjectID(string) (int, error) {
	return 0, fmt.Errorf("store unavailable")
}
func (failingStore) AddClientID(string, string) error { return fmt.Errorf("store unavailable") }

func TestCoordinatorRenewedUpdate(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)
	coord := NewCoordinator(store, clock, true)

	rec := &Record{
		SessionID: "s1",
		SubjectID: "u1",
		Created:   clock.Now(),
		Renewed:   clock.Now(),
		Expires:   clock.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}

	clock.Advance(5 * time.Minute)

	valid, _ := coord.ValidateSession("s1")
	if !valid {
		t.Fatal("session should be valid")
	}

	got, _ := store.GetSession("s1")
	if got == nil {
		t.Fatal("session should exist")
	}
	if got.Renewed.Equal(rec.Created) {
		t.Fatal("Renewed should be updated after validation")
	}
}

func TestMemoryStoreNilAndEmptyInput(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(newTestClock())

	if err := store.CreateSession(nil); err == nil {
		t.Fatal("nil session should error")
	}
	if err := store.CreateSession(&Record{}); err == nil {
		t.Fatal("empty session id should error")
	}
}

func TestMemoryStoreAddClientID(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	for name, tt := range map[string]struct {
		setup     func(*MemoryStore)
		sessionID string
		clientID  string
		wantList  []string
	}{
		"append to existing": {
			setup: func(s *MemoryStore) {
				_ = s.CreateSession(&Record{SessionID: "s1", SubjectID: "u1", Expires: clock.Now().Add(time.Hour)})
			},
			sessionID: "s1", clientID: "c1", wantList: []string{"c1"},
		},
		"dedup existing client": {
			setup: func(s *MemoryStore) {
				_ = s.CreateSession(&Record{SessionID: "s1", SubjectID: "u1", Expires: clock.Now().Add(time.Hour), ClientIDs: []string{"c1"}})
			},
			sessionID: "s1", clientID: "c1", wantList: []string{"c1"},
		},
		"missing session is no-op": {
			setup:     func(s *MemoryStore) {},
			sessionID: "ghost", clientID: "c1", wantList: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := NewMemoryStore(clock)
			tt.setup(store)
			if err := store.AddClientID(tt.sessionID, tt.clientID); err != nil {
				t.Fatalf("AddClientID: %v", err)
			}
			got, _ := store.GetSession(tt.sessionID)
			if tt.wantList == nil {
				if got != nil {
					t.Fatalf("expected no session, got %+v", got)
				}
				return
			}
			if got == nil || len(got.ClientIDs) != len(tt.wantList) {
				t.Fatalf("ClientIDs = %v, want %v", got, tt.wantList)
			}
		})
	}
}

func TestMemoryStoreAddClientIDExpiredIsNoOp(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)
	_ = store.CreateSession(&Record{SessionID: "s1", SubjectID: "u1", Expires: clock.Now().Add(time.Hour)})
	clock.Advance(2 * time.Hour)

	if err := store.AddClientID("s1", "c1"); err != nil {
		t.Fatalf("AddClientID on expired: %v", err)
	}
	// Session is lazily reaped on next read; the client add must not have resurrected it.
	if got, _ := store.GetSession("s1"); got != nil {
		t.Fatal("expired session should not be revived by AddClientID")
	}
}

func TestMemoryStoreNilClockNeverExpires(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(nil)
	rec := &Record{SessionID: "s1", SubjectID: "u1", Expires: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := store.CreateSession(rec); err != nil {
		t.Fatal(err)
	}

	// With no clock, expiry cannot be evaluated: GetSession and the subject
	// query must not panic and must return the record.
	got, err := store.GetSession("s1")
	if err != nil || got == nil {
		t.Fatalf("GetSession with nil clock: got=%v err=%v", got, err)
	}
	list, err := store.GetSessionsBySubjectID("u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("GetSessionsBySubjectID with nil clock: len=%d err=%v", len(list), err)
	}
}

func TestCoordinatorNilClockDoesNotPanic(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(nil)
	_ = store.CreateSession(&Record{SessionID: "s1", SubjectID: "u1", Expires: time.Time{}})
	coord := NewCoordinator(store, nil, true)

	// A nil clock cannot decide expiry, so an enabled coordinator fails closed
	// (returns false, nil) rather than panicking — same direction as store==nil.
	valid, err := coord.ValidateSession("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("enabled coordinator with nil clock should fail closed (false)")
	}
}

func TestMemoryStoreUpdateClearingSubjectReindexes(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	store := NewMemoryStore(clock)
	_ = store.CreateSession(&Record{SessionID: "s1", SubjectID: "u1", Expires: clock.Now().Add(time.Hour)})

	// Re-home the session under a new subject; the old subject must no longer
	// resolve it and the new subject must.
	updated := &Record{SessionID: "s1", SubjectID: "u2", Expires: clock.Now().Add(time.Hour)}
	if err := store.UpdateSession(updated); err != nil {
		t.Fatal(err)
	}

	if list, _ := store.GetSessionsBySubjectID("u1"); len(list) != 0 {
		t.Fatalf("old subject should have 0 sessions, got %d", len(list))
	}
	if list, _ := store.GetSessionsBySubjectID("u2"); len(list) != 1 {
		t.Fatalf("new subject should have 1 session, got %d", len(list))
	}
}
