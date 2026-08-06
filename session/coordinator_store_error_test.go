// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// coordinatorStubStore is a deterministic store stub: GetSession returns a
// fixed record (or a fixed error) so the coordinator's write branches are
// reachable regardless of the production store's lazy expiry behavior, and
// each write method fails on demand.
type coordinatorStubStore struct {
	rec              *Record
	getErr           error
	deleteSessionErr error
	updateSessionErr error
}

func (s *coordinatorStubStore) GetSession(context.Context, string) (*Record, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.rec, nil
}

func (s *coordinatorStubStore) CreateSession(context.Context, *Record) error { return nil }

func (s *coordinatorStubStore) UpdateSession(context.Context, *Record) error {
	return s.updateSessionErr
}

func (s *coordinatorStubStore) DeleteSession(context.Context, string) error {
	return s.deleteSessionErr
}

func (s *coordinatorStubStore) GetSessionsBySubjectID(context.Context, string) ([]*Record, error) {
	return nil, nil
}

func (s *coordinatorStubStore) DeleteSessionsBySubjectID(context.Context, string) (int, error) {
	return 0, nil
}

func (s *coordinatorStubStore) AddClientID(context.Context, string, string) error { return nil }

func (s *coordinatorStubStore) DeleteExpired(context.Context, time.Time) (int, error) {
	return 0, nil
}

// TestCoordinatorSurfacesStoreErrors pins the error-disposal contract of
// ValidateSession: a sentinel from the expiry reclamation write is ignored
// (the session is already gone, so "invalid" is still the right answer), a
// sentinel from the renewal write means the session was deleted concurrently
// (same conclusion), and any infrastructure error surfaces instead of being
// swallowed.
func TestCoordinatorSurfacesStoreErrors(t *testing.T) {
	t.Parallel()

	sentinel := ErrSessionNotFound
	infra := fmt.Errorf("store unavailable")

	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	clock := fixedTestClock{now: now}

	for name, tt := range map[string]struct {
		rec              *Record
		deleteSessionErr error
		updateSessionErr error
		wantValid        bool
		wantErr          error
	}{
		"delete sentinel": {
			rec:              &Record{SessionID: "s1", Expires: now.Add(-time.Hour)},
			deleteSessionErr: sentinel,
			wantValid:        false,
			wantErr:          nil,
		},
		"delete infra error": {
			rec:              &Record{SessionID: "s1", Expires: now.Add(-time.Hour)},
			deleteSessionErr: infra,
			wantValid:        false,
			wantErr:          infra,
		},
		"update sentinel": {
			rec:              &Record{SessionID: "s1", Expires: now.Add(time.Hour)},
			updateSessionErr: sentinel,
			wantValid:        false,
			wantErr:          nil,
		},
		"update infra error": {
			rec:              &Record{SessionID: "s1", Expires: now.Add(time.Hour)},
			updateSessionErr: infra,
			wantValid:        false,
			wantErr:          infra,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &coordinatorStubStore{
				rec:              tt.rec,
				deleteSessionErr: tt.deleteSessionErr,
				updateSessionErr: tt.updateSessionErr,
			}
			coord := NewCoordinator(store, clock, true)

			valid, err := coord.ValidateSession(context.Background(), "s1")
			if valid != tt.wantValid {
				t.Fatalf("valid = %v, want %v", valid, tt.wantValid)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
