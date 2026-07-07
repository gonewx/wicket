// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"sync"

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

func (s *AuthorizationCodeStore) StoreAuthorizationCode(code *models.AuthorizationCode) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newHandle()
	s.items[id] = code
	return id, nil
}

func (s *AuthorizationCodeStore) GetAuthorizationCode(handle string) (*models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[handle], nil
}

func (s *AuthorizationCodeStore) RemoveAuthorizationCode(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, handle)
	return nil
}

type RefreshTokenStore struct {
	mu    sync.Mutex
	items map[string]*models.RefreshToken
}

func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{items: map[string]*models.RefreshToken{}}
}

func (s *RefreshTokenStore) StoreRefreshToken(token *models.RefreshToken) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newHandle()
	s.items[id] = token
	return id, nil
}

func (s *RefreshTokenStore) GetRefreshToken(handle string) (*models.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[handle], nil
}

func (s *RefreshTokenStore) UpdateRefreshToken(handle string, token *models.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[handle] = token
	return nil
}

func (s *RefreshTokenStore) RemoveRefreshToken(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, handle)
	return nil
}

type ReferenceTokenStore struct {
	mu    sync.Mutex
	items map[string]*models.Token
}

func NewReferenceTokenStore() *ReferenceTokenStore {
	return &ReferenceTokenStore{items: map[string]*models.Token{}}
}

func (s *ReferenceTokenStore) StoreReferenceToken(token *models.Token) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newHandle()
	s.items[id] = token
	return id, nil
}

func (s *ReferenceTokenStore) GetReferenceToken(handle string) (*models.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[handle], nil
}

func (s *ReferenceTokenStore) RemoveReferenceToken(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, handle)
	return nil
}

func (s *ReferenceTokenStore) RemoveReferenceTokens(subjectId, clientId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, token := range s.items {
		if token.SubjectId() == subjectId && token.ClientId == clientId {
			delete(s.items, key)
		}
	}
	return nil
}

type UserConsentStore struct {
	mu    sync.Mutex
	items map[string]*models.Consent
}

func NewUserConsentStore() *UserConsentStore {
	return &UserConsentStore{items: map[string]*models.Consent{}}
}

func (s *UserConsentStore) StoreUserConsent(consent *models.Consent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[consent.SubjectId+"\x00"+consent.ClientId] = consent
	return nil
}

func (s *UserConsentStore) GetUserConsent(subjectId, clientId string) (*models.Consent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[subjectId+"\x00"+clientId], nil
}

func (s *UserConsentStore) GetAllUserConsents(subjectId string) ([]*models.Consent, error) {
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

func (s *UserConsentStore) RemoveUserConsent(subjectId, clientId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, subjectId+"\x00"+clientId)
	return nil
}

func newHandle() string {
	id, err := utils.CreateUniqueId(32, utils.Hex)
	if err != nil {
		return ""
	}
	return id
}
