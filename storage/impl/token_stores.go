// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"sync"
	"time"

	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

type AuthorizationCodeStore struct {
	mu    sync.Mutex
	items map[string]*models.AuthorizationCode
}

func NewAuthorizationCodeStore() *AuthorizationCodeStore {
	return &AuthorizationCodeStore{items: map[string]*models.AuthorizationCode{}}
}

func (s *AuthorizationCodeStore) StoreAuthorizationCode(ctx context.Context, handle string, code *models.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[handle]; ok {
		return storage.ErrDuplicateHandle
	}
	s.items[handle] = copyAuthorizationCode(code)
	return nil
}

func (s *AuthorizationCodeStore) GetAuthorizationCode(ctx context.Context, handle string) (*models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return copyAuthorizationCode(code), nil
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

func (s *RefreshTokenStore) StoreRefreshToken(ctx context.Context, handle string, token *models.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[handle]; ok {
		return storage.ErrDuplicateHandle
	}
	stored := copyRefreshToken(token)
	stored.Version = 1
	s.items[handle] = stored
	token.Version = 1
	return nil
}

func (s *RefreshTokenStore) GetRefreshToken(ctx context.Context, handle string) (*models.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return copyRefreshToken(token), nil
}

func (s *RefreshTokenStore) UpdateRefreshToken(ctx context.Context, handle string, token *models.RefreshToken, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.items[handle]
	if !ok {
		return storage.ErrNotFound
	}
	if current.Version != expectedVersion {
		return storage.ErrVersionConflict
	}
	stored := copyRefreshToken(token)
	stored.Version = current.Version + 1
	s.items[handle] = stored
	token.Version = stored.Version
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

func (s *ReferenceTokenStore) StoreReferenceToken(ctx context.Context, handle string, token *models.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[handle]; ok {
		return storage.ErrDuplicateHandle
	}
	s.items[handle] = copyToken(token)
	return nil
}

func (s *ReferenceTokenStore) GetReferenceToken(ctx context.Context, handle string) (*models.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.items[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return copyToken(token), nil
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

// StoreUserConsent writes a consent under the subject+client natural key. The
// write is an upsert: a later decision for the same pair replaces the earlier
// record, matching the interface contract.
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

// copyStrings returns an independent copy of values that preserves nil-ness:
// a nil input yields nil, and an empty non-nil slice stays non-nil. Callers
// distinguish the two states, so the copy must not collapse them.
func copyStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

// copyAuthorizationCode returns an independent copy of the record: value
// fields are copied and slice fields get fresh backing arrays. The subject
// principal is shared by convention (it is treated as immutable).
func copyAuthorizationCode(code *models.AuthorizationCode) *models.AuthorizationCode {
	if code == nil {
		return nil
	}
	out := *code
	out.RequestedScopes = copyStrings(code.RequestedScopes)
	out.RequestedResourceGaps = copyStrings(code.RequestedResourceGaps)
	return &out
}

// copyRefreshToken returns an independent copy of the record: value fields
// are copied, the access-token map is copied entry by entry, and slice fields
// get fresh backing arrays. The subject principal is shared by convention (it
// is treated as immutable).
func copyRefreshToken(token *models.RefreshToken) *models.RefreshToken {
	if token == nil {
		return nil
	}
	out := *token
	out.AccessToken = *copyToken(&token.AccessToken)
	out.AccessTokens = make(map[string]*models.Token, len(token.AccessTokens))
	for gap, accessToken := range token.AccessTokens {
		out.AccessTokens[gap] = copyToken(accessToken)
	}
	out.AuthorizedScopes = copyStrings(token.AuthorizedScopes)
	out.AuthorizedResourceGaps = copyStrings(token.AuthorizedResourceGaps)
	return &out
}

// copyToken returns an independent copy of the token: value fields are copied
// and slice fields get fresh backing arrays.
func copyToken(token *models.Token) *models.Token {
	if token == nil {
		return nil
	}
	out := *token
	out.AllowedSigningAlgorithms = copyStrings(token.AllowedSigningAlgorithms)
	out.Audiences = copyStrings(token.Audiences)
	out.Claims = append([]*claims.Claim(nil), token.Claims...)
	return &out
}
