// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Record
	subjects map[string]map[string]struct{}
	clock    Clock
}

func NewMemoryStore(clock Clock) *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*Record),
		subjects: make(map[string]map[string]struct{}),
		clock:    clock,
	}
}

// now returns the current time from the injected clock, or the zero time when
// no clock is configured. A zero time never triggers expiry (Record.IsExpired
// treats a zero Expires and a zero comparison time as non-expired), so a nil
// clock degrades to "never expire" instead of panicking.
func (s *MemoryStore) now() (t timeValue) {
	if s.clock != nil {
		t.set = true
		t.at = s.clock.Now()
	}
	return t
}

func (s *MemoryStore) GetSession(ctx context.Context, sessionID string) (*Record, error) {
	s.mu.RLock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		s.mu.RUnlock()
		return nil, ErrSessionNotFound
	}

	now := s.now()
	expired := now.set && rec.IsExpired(now.at)
	var cp *Record
	if !expired {
		c := *rec
		c.ClientIDs = append([]string(nil), rec.ClientIDs...)
		cp = &c
	}
	s.mu.RUnlock()

	if expired {
		s.deleteIfExpired(sessionID)
		return nil, ErrSessionNotFound
	}
	return cp, nil
}

func (s *MemoryStore) CreateSession(ctx context.Context, session *Record) error {
	if session == nil || session.SessionID == "" {
		return fmt.Errorf("session record and session id are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.SessionID]; exists {
		return fmt.Errorf("session %s already exists", session.SessionID)
	}

	cp := *session
	cp.ClientIDs = append([]string(nil), session.ClientIDs...)
	s.sessions[session.SessionID] = &cp
	s.indexSubject(session.SubjectID, session.SessionID)

	return nil
}

func (s *MemoryStore) UpdateSession(ctx context.Context, session *Record) error {
	if session == nil || session.SessionID == "" {
		return fmt.Errorf("session record and session id are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.sessions[session.SessionID]
	if !ok {
		return nil
	}

	if existing.SubjectID != session.SubjectID {
		s.unindexSubject(existing.SubjectID, session.SessionID)
	}

	cp := *session
	cp.ClientIDs = append([]string(nil), session.ClientIDs...)
	s.sessions[session.SessionID] = &cp
	s.indexSubject(session.SubjectID, session.SessionID)

	return nil
}

// AddClientID atomically appends a client id to the stored session's client
// list, deduplicating. It is a no-op (nil error) when the session is absent or
// expired, so a caller racing with logout/expiry does not resurrect the record.
func (s *MemoryStore) AddClientID(ctx context.Context, sessionID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	now := s.now()
	if now.set && rec.IsExpired(now.at) {
		return nil
	}
	rec.AddClientID(clientID)
	return nil
}

func (s *MemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}

	s.unindexSubject(rec.SubjectID, sessionID)
	delete(s.sessions, sessionID)
	return nil
}

func (s *MemoryStore) GetSessionsBySubjectID(ctx context.Context, subjectID string) ([]*Record, error) {
	s.mu.RLock()
	ids, ok := s.subjects[subjectID]
	if !ok {
		s.mu.RUnlock()
		return nil, nil
	}

	now := s.now()
	result := make([]*Record, 0, len(ids))
	var expired []string
	for id := range ids {
		rec := s.sessions[id]
		if rec == nil {
			continue
		}
		if now.set && rec.IsExpired(now.at) {
			expired = append(expired, id)
			continue
		}
		cp := *rec
		cp.ClientIDs = append([]string(nil), rec.ClientIDs...)
		result = append(result, &cp)
	}
	s.mu.RUnlock()

	for _, id := range expired {
		s.deleteIfExpired(id)
	}

	return result, nil
}

// deleteIfExpired removes a session only if it is still expired under the write
// lock. This closes the TOCTOU window between an unlocked expiry observation and
// the delete: a concurrent ValidateSession may have renewed the record after it
// was flagged expired, and that renewed session must survive.
func (s *MemoryStore) deleteIfExpired(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	now := s.now()
	if !now.set || !rec.IsExpired(now.at) {
		return
	}
	s.unindexSubject(rec.SubjectID, sessionID)
	delete(s.sessions, sessionID)
}

func (s *MemoryStore) DeleteSessionsBySubjectID(ctx context.Context, subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids, ok := s.subjects[subjectID]
	if !ok {
		return 0, nil
	}

	count := 0
	for id := range ids {
		if _, exists := s.sessions[id]; exists {
			delete(s.sessions, id)
			count++
		}
	}
	delete(s.subjects, subjectID)

	return count, nil
}

// DeleteExpired removes sessions whose Expires is set and precedes cutoff,
// returning how many were removed. It reclaims space only; expiry judgement
// remains on the core side.
func (s *MemoryStore) DeleteExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, rec := range s.sessions {
		if !rec.Expires.IsZero() && rec.Expires.Before(cutoff) {
			s.unindexSubject(rec.SubjectID, id)
			delete(s.sessions, id)
			count++
		}
	}
	return count, nil
}

// indexSubject records the session under its subject's reverse index. A session
// with an empty subject id is intentionally not indexed: it cannot be enumerated
// or invalidated by subject (there is no subject to key on). Callers that need
// subject-based management must supply a non-empty subject id.
//
// Caller must hold the write lock.
func (s *MemoryStore) indexSubject(subjectID, sessionID string) {
	if subjectID == "" {
		return
	}
	if s.subjects[subjectID] == nil {
		s.subjects[subjectID] = make(map[string]struct{})
	}
	s.subjects[subjectID][sessionID] = struct{}{}
}

// unindexSubject removes the session from its subject's reverse index, pruning
// the subject entry once its last session is gone. Caller must hold the write lock.
func (s *MemoryStore) unindexSubject(subjectID, sessionID string) {
	if subjectID == "" {
		return
	}
	set := s.subjects[subjectID]
	if set == nil {
		return
	}
	delete(set, sessionID)
	if len(set) == 0 {
		delete(s.subjects, subjectID)
	}
}

// timeValue carries a clock reading plus whether a clock was present, so expiry
// logic can distinguish "clock says now" from "no clock configured".
type timeValue struct {
	at  time.Time
	set bool
}
