// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"sync"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

type AuthorizationCodeStore struct {
	mu    sync.Mutex
	items map[string]*models.AuthorizationCode
}

func NewAuthorizationCodeStore() *AuthorizationCodeStore {
	return &AuthorizationCodeStore{items: map[string]*models.AuthorizationCode{}}
}

func (s *AuthorizationCodeStore) StoreAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newHandle()
	s.items[id] = code
	return id, nil
}

func (s *AuthorizationCodeStore) GetAuthorizationCode(ctx context.Context, handle string) (*models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return code, nil
}

func (s *AuthorizationCodeStore) RemoveAuthorizationCode(ctx context.Context, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, handle)
	return nil
}

func (s *AuthorizationCodeStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for handle, code := range s.items {
		if code.CreationTime.Add(time.Duration(code.Lifetime) * time.Second).Before(cutoff) {
			delete(s.items, handle)
			count++
		}
	}
	return count, nil
}

type RefreshTokenStore struct {
	mu    sync.Mutex
	items map[string]*models.RefreshToken
}

func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{items: map[string]*models.RefreshToken{}}
}

func (s *RefreshTokenStore) StoreRefreshToken(ctx context.Context, token *models.RefreshToken) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newHandle()
	s.items[id] = token
	return id, nil
}

func (s *RefreshTokenStore) GetRefreshToken(ctx context.Context, handle string) (*models.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return token, nil
}

func (s *RefreshTokenStore) UpdateRefreshToken(ctx context.Context, handle string, token *models.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[handle] = token
	return nil
}

func (s *RefreshTokenStore) RemoveRefreshToken(ctx context.Context, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, handle)
	return nil
}

func (s *RefreshTokenStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for handle, token := range s.items {
		if token.CreationTime.Add(time.Duration(token.Lifetime) * time.Second).Before(cutoff) {
			delete(s.items, handle)
			count++
		}
	}
	return count, nil
}

type ReferenceTokenStore struct {
	mu    sync.Mutex
	items map[string]*models.Token
}

func NewReferenceTokenStore() *ReferenceTokenStore {
	return &ReferenceTokenStore{items: map[string]*models.Token{}}
}

func (s *ReferenceTokenStore) StoreReferenceToken(ctx context.Context, token *models.Token) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newHandle()
	s.items[id] = token
	return id, nil
}

func (s *ReferenceTokenStore) GetReferenceToken(ctx context.Context, handle string) (*models.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return token, nil
}

func (s *ReferenceTokenStore) RemoveReferenceToken(ctx context.Context, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, handle)
	return nil
}

func (s *ReferenceTokenStore) RemoveReferenceTokens(ctx context.Context, subjectId, clientId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, token := range s.items {
		if token.SubjectId() == subjectId && token.ClientId == clientId {
			delete(s.items, key)
		}
	}
	return nil
}

func (s *ReferenceTokenStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for handle, token := range s.items {
		if token.CreationTime.Add(time.Duration(token.Lifetime) * time.Second).Before(cutoff) {
			delete(s.items, handle)
			count++
		}
	}
	return count, nil
}

type UserConsentStore struct {
	mu    sync.Mutex
	items map[string]*models.Consent
}

func NewUserConsentStore() *UserConsentStore {
	return &UserConsentStore{items: map[string]*models.Consent{}}
}

func (s *UserConsentStore) StoreUserConsent(ctx context.Context, consent *models.Consent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[consent.SubjectId+"\x00"+consent.ClientId] = consent
	return nil
}

func (s *UserConsentStore) GetUserConsent(ctx context.Context, subjectId, clientId string) (*models.Consent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	consent, ok := s.items[subjectId+"\x00"+clientId]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return consent, nil
}

func (s *UserConsentStore) GetAllUserConsents(ctx context.Context, subjectId string) ([]*models.Consent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.Consent, 0)
	for _, consent := range s.items {
		if consent.SubjectId == subjectId {
			out = append(out, consent)
		}
	}
	return out, nil
}

func (s *UserConsentStore) RemoveUserConsent(ctx context.Context, subjectId, clientId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, subjectId+"\x00"+clientId)
	return nil
}

func (s *UserConsentStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for key, consent := range s.items {
		if consent.Expiration != nil && consent.Expiration.Before(cutoff) {
			delete(s.items, key)
			count++
		}
	}
	return count, nil
}

func newHandle() string {
	id, err := utils.CreateUniqueId(32, utils.Hex)
	if err != nil {
		return ""
	}
	return id
}
