// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session

import (
	"slices"
	"time"
)

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
	GetSession(sessionID string) (*Record, error)
	CreateSession(session *Record) error
	UpdateSession(session *Record) error
	DeleteSession(sessionID string) error
	GetSessionsBySubjectID(subjectID string) ([]*Record, error)
	DeleteSessionsBySubjectID(subjectID string) (int, error)
	// AddClientID atomically appends a client id to the session record,
	// deduplicating within the store lock. A missing session is a no-op.
	AddClientID(sessionID, clientID string) error
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

func (c *Coordinator) ValidateSession(sessionID string) (bool, error) {
	if !c.enabled {
		return true, nil
	}

	if c.store == nil || c.clock == nil {
		return false, nil
	}

	rec, err := c.store.GetSession(sessionID)
	if err != nil {
		return false, err
	}

	if rec == nil {
		return false, nil
	}

	now := c.clock.Now()
	if rec.IsExpired(now) {
		_ = c.store.DeleteSession(sessionID)
		return false, nil
	}

	rec.Renewed = now
	_ = c.store.UpdateSession(rec)

	return true, nil
}
