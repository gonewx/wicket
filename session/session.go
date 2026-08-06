// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ErrSessionNotFound reports that a session lookup missed. It is this
// package's sentinel for "record absent", distinct from infrastructure errors.
var ErrSessionNotFound = errors.New("session: session not found")

type Record struct {
	SessionID   string
	SubjectID   string
	DisplayName string
	Created     time.Time
	Renewed     time.Time
	Expires     time.Time
	ClientIDs   []string
}

func (r *Record) IsExpired(now time.Time) bool {
	return !r.Expires.IsZero() && now.After(r.Expires)
}

func (r *Record) AddClientID(clientID string) bool {
	if slices.Contains(r.ClientIDs, clientID) {
		return false
	}
	r.ClientIDs = append(r.ClientIDs, clientID)
	return true
}

type Store interface {
	// GetSession returns the session record, or ErrSessionNotFound when it is
	// absent.
	GetSession(ctx context.Context, sessionID string) (*Record, error)
	CreateSession(ctx context.Context, session *Record) error
	UpdateSession(ctx context.Context, session *Record) error
	DeleteSession(ctx context.Context, sessionID string) error
	GetSessionsBySubjectID(ctx context.Context, subjectID string) ([]*Record, error)
	DeleteSessionsBySubjectID(ctx context.Context, subjectID string) (int, error)
	// AddClientID atomically appends a client id to the session record,
	// deduplicating within the store lock. A missing session is a no-op.
	AddClientID(ctx context.Context, sessionID, clientID string) error
	// DeleteExpired removes sessions whose Expires is set and precedes cutoff,
	// returning how many were removed. It reclaims space only; expiry judgement
	// remains on the core side.
	DeleteExpired(ctx context.Context, cutoff time.Time) (int, error)
}

type Clock interface {
	Now() time.Time
}

type Coordinator struct {
	store   Store
	clock   Clock
	enabled bool
}

func NewCoordinator(store Store, clock Clock, enabled bool) *Coordinator {
	return &Coordinator{store: store, clock: clock, enabled: enabled}
}

func (c *Coordinator) ValidateSession(ctx context.Context, sessionID string) (bool, error) {
	if !c.enabled {
		return true, nil
	}

	if c.store == nil || c.clock == nil {
		return false, nil
	}

	rec, err := c.store.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return false, nil
		}
		return false, err
	}

	now := c.clock.Now()
	if rec.IsExpired(now) {
		_ = c.store.DeleteSession(ctx, sessionID)
		return false, nil
	}

	rec.Renewed = now
	_ = c.store.UpdateSession(ctx, rec)

	return true, nil
}
