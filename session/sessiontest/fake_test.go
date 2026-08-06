// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package sessiontest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/session"
)

// fakeSessionStore is a minimal in-memory adapter written alongside the suite
// as an independent reference. It implements the port contract without
// sharing code with the production store: misses return ErrSessionNotFound,
// CreateSession is insert-only, missing writes are no-ops, DeleteExpired
// reclaims strictly before the cutoff, and reads lazily reclaim expired
// records when a clock is injected.
type fakeSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session.Record
	subjects map[string]map[string]struct{}
	clock    session.Clock
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		sessions: make(map[string]*session.Record),
		subjects: make(map[string]map[string]struct{}),
	}
}

func (s *fakeSessionStore) GetSession(_ context.Context, sessionID string) (*session.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	if s.clock != nil && rec.IsExpired(s.clock.Now()) {
		s.unindex(rec.SubjectID, sessionID)
		delete(s.sessions, sessionID)
		return nil, session.ErrSessionNotFound
	}
	cp := *rec
	cp.ClientIDs = append([]string(nil), rec.ClientIDs...)
	return &cp, nil
}

func (s *fakeSessionStore) CreateSession(_ context.Context, rec *session.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec == nil || rec.SessionID == "" {
		return fmt.Errorf("session record and session id are required")
	}
	if _, ok := s.sessions[rec.SessionID]; ok {
		return fmt.Errorf("session %s already exists", rec.SessionID)
	}
	cp := *rec
	cp.ClientIDs = append([]string(nil), rec.ClientIDs...)
	s.sessions[rec.SessionID] = &cp
	s.index(rec.SubjectID, rec.SessionID)
	return nil
}

func (s *fakeSessionStore) UpdateSession(_ context.Context, rec *session.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.sessions[rec.SessionID]
	if !ok {
		return nil
	}
	if existing.SubjectID != rec.SubjectID {
		s.unindex(existing.SubjectID, rec.SessionID)
	}
	cp := *rec
	cp.ClientIDs = append([]string(nil), rec.ClientIDs...)
	s.sessions[rec.SessionID] = &cp
	s.index(rec.SubjectID, rec.SessionID)
	return nil
}

func (s *fakeSessionStore) DeleteSession(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	s.unindex(rec.SubjectID, sessionID)
	delete(s.sessions, sessionID)
	return nil
}

func (s *fakeSessionStore) GetSessionsBySubjectID(_ context.Context, subjectID string) ([]*session.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids, ok := s.subjects[subjectID]
	if !ok {
		return nil, nil
	}
	var out []*session.Record
	for id := range ids {
		rec, ok := s.sessions[id]
		if !ok {
			continue
		}
		if s.clock != nil && rec.IsExpired(s.clock.Now()) {
			continue
		}
		cp := *rec
		cp.ClientIDs = append([]string(nil), rec.ClientIDs...)
		out = append(out, &cp)
	}
	return out, nil
}

func (s *fakeSessionStore) DeleteSessionsBySubjectID(_ context.Context, subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids, ok := s.subjects[subjectID]
	if !ok {
		return 0, nil
	}
	count := 0
	for id := range ids {
		if _, ok := s.sessions[id]; ok {
			delete(s.sessions, id)
			count++
		}
	}
	delete(s.subjects, subjectID)
	return count, nil
}

func (s *fakeSessionStore) AddClientID(_ context.Context, sessionID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	if s.clock != nil && rec.IsExpired(s.clock.Now()) {
		return nil
	}
	rec.AddClientID(clientID)
	return nil
}

func (s *fakeSessionStore) DeleteExpired(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for id, rec := range s.sessions {
		if !rec.Expires.IsZero() && rec.Expires.Before(cutoff) {
			s.unindex(rec.SubjectID, id)
			delete(s.sessions, id)
			count++
		}
	}
	return count, nil
}

func (s *fakeSessionStore) index(subjectID, sessionID string) {
	if subjectID == "" {
		return
	}
	if s.subjects[subjectID] == nil {
		s.subjects[subjectID] = make(map[string]struct{})
	}
	s.subjects[subjectID][sessionID] = struct{}{}
}

func (s *fakeSessionStore) unindex(subjectID, sessionID string) {
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

type fakeSessionClock struct {
	at time.Time
}

func (c fakeSessionClock) Now() time.Time { return c.at }

// TestFakeSessionStoreConformanceE2E runs the full suite against an
// independent minimal adapter with a fixed clock, MUST and MAY alike. This
// is the reference run the discriminative rounds below must stay green on.
func TestFakeSessionStoreConformanceE2E(t *testing.T) {
	t.Parallel()
	RunSessionStoreSuite(t, func() session.Store {
		store := newFakeSessionStore()
		store.clock = fakeSessionClock{at: fixedNow}
		return store
	}, WithMay(true))
}
