// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"sync"

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

func (s *MemoryPersistedGrantStore) Store(grant *models.PersistedGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[grant.Key] = grant
	return nil
}

func (s *MemoryPersistedGrantStore) Get(key string) (*models.PersistedGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grants[key], nil
}

func (s *MemoryPersistedGrantStore) GetAll(filter *storage.PersistedGrantFilter) ([]*models.PersistedGrant, error) {
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

func (s *MemoryPersistedGrantStore) Remove(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, key)
	return nil
}

func (s *MemoryPersistedGrantStore) RemoveAll(filter *storage.PersistedGrantFilter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, grant := range s.grants {
		if grantMatches(filter, grant) {
			delete(s.grants, key)
		}
	}
	return nil
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

func (s *MemoryDeviceFlowStore) StoreDeviceAuthorization(deviceCode string, userCode string, data *models.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byUserCode[userCode] = data
	s.byDeviceCode[deviceCode] = data
	s.userByDevice[deviceCode] = userCode
	return nil
}

func (s *MemoryDeviceFlowStore) FindByUserCode(userCode string) (*models.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byUserCode[userCode], nil
}

func (s *MemoryDeviceFlowStore) FindByDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byDeviceCode[deviceCode], nil
}

func (s *MemoryDeviceFlowStore) UpdateByUserCode(userCode string, data *models.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byUserCode[userCode] = data
	return nil
}

func (s *MemoryDeviceFlowStore) RemoveByDeviceCode(deviceCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userCode := s.userByDevice[deviceCode]
	delete(s.byDeviceCode, deviceCode)
	delete(s.userByDevice, deviceCode)
	delete(s.byUserCode, userCode)
	return nil
}
