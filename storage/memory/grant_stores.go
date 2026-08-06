// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"context"
	"sync"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

type MemoryPersistedGrantStore struct {
	mu     sync.Mutex
	grants map[string]*models.PersistedGrant
}

func NewMemoryPersistedGrantStore() *MemoryPersistedGrantStore {
	return &MemoryPersistedGrantStore{grants: map[string]*models.PersistedGrant{}}
}

// Store writes a grant under its Key. The write is an upsert: storing a grant
// whose Key already exists replaces the stored record, matching the interface
// contract for the caller-chosen natural key.
func (s *MemoryPersistedGrantStore) Store(ctx context.Context, grant *models.PersistedGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[grant.Key] = grant
	return nil
}

func (s *MemoryPersistedGrantStore) Get(ctx context.Context, key string) (*models.PersistedGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return grant, nil
}

func (s *MemoryPersistedGrantStore) GetAll(ctx context.Context, filter *storage.PersistedGrantFilter) ([]*models.PersistedGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.PersistedGrant, 0)
	for _, grant := range s.grants {
		if grantMatches(filter, grant) {
			out = append(out, grant)
		}
	}
	return out, nil
}

func (s *MemoryPersistedGrantStore) Remove(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, key)
	return nil
}

func (s *MemoryPersistedGrantStore) RemoveAll(ctx context.Context, filter *storage.PersistedGrantFilter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, grant := range s.grants {
		if grantMatches(filter, grant) {
			delete(s.grants, key)
		}
	}
	return nil
}

func (s *MemoryPersistedGrantStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for key, grant := range s.grants {
		if grant.Expiration != nil && grant.Expiration.Before(cutoff) {
			delete(s.grants, key)
			count++
		}
	}
	return count, nil
}

func grantMatches(filter *storage.PersistedGrantFilter, grant *models.PersistedGrant) bool {
	if filter == nil || grant == nil {
		return false
	}
	if filter.SubjectId != "" && grant.SubjectId != filter.SubjectId {
		return false
	}
	if filter.SessionId != "" && grant.SessionId != filter.SessionId {
		return false
	}
	if filter.ClientId != "" && grant.ClientId != filter.ClientId {
		return false
	}
	if len(filter.ClientIds) > 0 && !utils.Contains(filter.ClientIds, grant.ClientId) {
		return false
	}
	if filter.Type != "" && grant.Type != filter.Type {
		return false
	}
	if len(filter.Types) > 0 && !utils.Contains(filter.Types, grant.Type) {
		return false
	}
	return true
}

type MemoryDeviceFlowStore struct {
	mu           sync.Mutex
	byUserCode   map[string]*models.DeviceCode
	byDeviceCode map[string]*models.DeviceCode
	userByDevice map[string]string
}

func NewMemoryDeviceFlowStore() *MemoryDeviceFlowStore {
	return &MemoryDeviceFlowStore{
		byUserCode:   map[string]*models.DeviceCode{},
		byDeviceCode: map[string]*models.DeviceCode{},
		userByDevice: map[string]string{},
	}
}

// StoreDeviceAuthorization writes a record under the caller-supplied device
// and user codes. The write is insert-only: either code already being present
// fails with ErrDuplicateHandle, matching the interface contract.
func (s *MemoryDeviceFlowStore) StoreDeviceAuthorization(ctx context.Context, deviceCode string, userCode string, data *models.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byDeviceCode[deviceCode]; ok {
		return storage.ErrDuplicateHandle
	}
	if _, ok := s.byUserCode[userCode]; ok {
		return storage.ErrDuplicateHandle
	}
	s.byUserCode[userCode] = data
	s.byDeviceCode[deviceCode] = data
	s.userByDevice[deviceCode] = userCode
	return nil
}

func (s *MemoryDeviceFlowStore) FindByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.byUserCode[userCode]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return data, nil
}

func (s *MemoryDeviceFlowStore) FindByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.byDeviceCode[deviceCode]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return data, nil
}

func (s *MemoryDeviceFlowStore) UpdateByUserCode(ctx context.Context, userCode string, data *models.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byUserCode[userCode] = data
	return nil
}

func (s *MemoryDeviceFlowStore) RemoveByDeviceCode(ctx context.Context, deviceCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userCode := s.userByDevice[deviceCode]
	delete(s.byDeviceCode, deviceCode)
	delete(s.userByDevice, deviceCode)
	delete(s.byUserCode, userCode)
	return nil
}

func (s *MemoryDeviceFlowStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for deviceCode, userCode := range s.userByDevice {
		data := s.byDeviceCode[deviceCode]
		if data == nil || data.CreationTime.Add(time.Duration(data.Lifetime)*time.Second).Before(cutoff) {
			delete(s.byDeviceCode, deviceCode)
			delete(s.userByDevice, deviceCode)
			delete(s.byUserCode, userCode)
			count++
		}
	}
	return count, nil
}

type MemoryBackchannelAuthenticationRequestStore struct {
	mu       sync.Mutex
	requests map[string]*models.BackchannelAuthenticationRequest
}

func NewMemoryBackchannelAuthenticationRequestStore() *MemoryBackchannelAuthenticationRequestStore {
	return &MemoryBackchannelAuthenticationRequestStore{requests: map[string]*models.BackchannelAuthenticationRequest{}}
}

// StoreBackchannelAuthenticationRequest writes a record under the
// caller-supplied request id. The write is insert-only: a request id that
// already exists fails with ErrDuplicateHandle, matching the interface
// contract.
func (s *MemoryBackchannelAuthenticationRequestStore) StoreBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *models.BackchannelAuthenticationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.requests[requestID]; ok {
		return storage.ErrDuplicateHandle
	}
	s.requests[requestID] = data
	return nil
}

func (s *MemoryBackchannelAuthenticationRequestStore) FindBackchannelAuthenticationRequest(ctx context.Context, requestID string) (*models.BackchannelAuthenticationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.requests[requestID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return data, nil
}

func (s *MemoryBackchannelAuthenticationRequestStore) UpdateBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *models.BackchannelAuthenticationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[requestID] = data
	return nil
}

func (s *MemoryBackchannelAuthenticationRequestStore) RemoveBackchannelAuthenticationRequest(ctx context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, requestID)
	return nil
}

func (s *MemoryBackchannelAuthenticationRequestStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for requestID, request := range s.requests {
		if !request.ExpirationTime.IsZero() && request.ExpirationTime.Before(cutoff) {
			delete(s.requests, requestID)
			count++
		}
	}
	return count, nil
}
