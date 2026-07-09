// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session

import (
	"fmt"
	"sync"
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

func (s *MemoryStore) GetSession(sessionID string) (*Record, error) {
	s.mu.RLock()
	rec, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	if s.clock != nil && rec.IsExpired(s.clock.Now()) {
		_ = s.DeleteSession(sessionID)
		return nil, nil
	}

	cp := *rec
	cp.ClientIDs = append([]string(nil), rec.ClientIDs...)
	return &cp, nil
}

func (s *MemoryStore) CreateSession(session *Record) error {
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

	if session.SubjectID != "" {
		if s.subjects[session.SubjectID] == nil {
			s.subjects[session.SubjectID] = make(map[string]struct{})
		}
		s.subjects[session.SubjectID][session.SessionID] = struct{}{}
	}

	return nil
}

func (s *MemoryStore) UpdateSession(session *Record) error {
	if session == nil || session.SessionID == "" {
		return fmt.Errorf("session record and session id are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.sessions[session.SessionID]
	if !ok {
		return nil
	}

	if existing.SubjectID != session.SubjectID && existing.SubjectID != "" {
		if set := s.subjects[existing.SubjectID]; set != nil {
			delete(set, session.SessionID)
			if len(set) == 0 {
				delete(s.subjects, existing.SubjectID)
			}
		}
	}

	cp := *session
	cp.ClientIDs = append([]string(nil), session.ClientIDs...)
	s.sessions[session.SessionID] = &cp

	if session.SubjectID != "" {
		if s.subjects[session.SubjectID] == nil {
			s.subjects[session.SubjectID] = make(map[string]struct{})
		}
		s.subjects[session.SubjectID][session.SessionID] = struct{}{}
	}

	return nil
}

func (s *MemoryStore) DeleteSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}

	if rec.SubjectID != "" {
		if set := s.subjects[rec.SubjectID]; set != nil {
			delete(set, sessionID)
			if len(set) == 0 {
				delete(s.subjects, rec.SubjectID)
			}
		}
	}

	delete(s.sessions, sessionID)
	return nil
}

func (s *MemoryStore) GetSessionsBySubjectID(subjectID string) ([]*Record, error) {
	s.mu.RLock()
	ids, ok := s.subjects[subjectID]
	if !ok {
		s.mu.RUnlock()
		return nil, nil
	}

	result := make([]*Record, 0, len(ids))
	now := s.clock.Now()
	var expired []string
	for id := range ids {
		rec := s.sessions[id]
		if rec == nil {
			continue
		}
		if rec.IsExpired(now) {
			expired = append(expired, id)
			continue
		}
		cp := *rec
		cp.ClientIDs = append([]string(nil), rec.ClientIDs...)
		result = append(result, &cp)
	}
	s.mu.RUnlock()

	for _, id := range expired {
		_ = s.DeleteSession(id)
	}

	return result, nil
}

func (s *MemoryStore) DeleteSessionsBySubjectID(subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids, ok := s.subjects[subjectID]
	if !ok {
		return 0, nil
	}

	count := len(ids)
	for id := range ids {
		delete(s.sessions, id)
	}
	delete(s.subjects, subjectID)

	return count, nil
}
