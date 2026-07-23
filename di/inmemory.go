// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"sync"

	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

type lazyPersistedGrantStore struct {
	cfg  *ServerConfig
	once sync.Once
	impl storage.PersistedGrantStore
}

func (s *lazyPersistedGrantStore) store() storage.PersistedGrantStore {
	s.once.Do(func() {
		s.impl = s.cfg.PersistedGrantStore()
		if s.impl == nil {
			s.impl = storage_memory.NewMemoryPersistedGrantStore()
		}
	})
	return s.impl
}

func (s *lazyPersistedGrantStore) Store(grant *storage_models.PersistedGrant) error {
	return s.store().Store(grant)
}

func (s *lazyPersistedGrantStore) Get(key string) (*storage_models.PersistedGrant, error) {
	return s.store().Get(key)
}

func (s *lazyPersistedGrantStore) GetAll(filter *storage.PersistedGrantFilter) ([]*storage_models.PersistedGrant, error) {
	return s.store().GetAll(filter)
}

func (s *lazyPersistedGrantStore) Remove(key string) error {
	return s.store().Remove(key)
}

func (s *lazyPersistedGrantStore) RemoveAll(filter *storage.PersistedGrantFilter) error {
	return s.store().RemoveAll(filter)
}

type lazyDeviceFlowStore struct {
	cfg  *ServerConfig
	once sync.Once
	impl storage.DeviceFlowStore
}

func (s *lazyDeviceFlowStore) store() storage.DeviceFlowStore {
	s.once.Do(func() {
		s.impl = s.cfg.DeviceFlowStore()
		if s.impl == nil {
			s.impl = storage_memory.NewMemoryDeviceFlowStore()
		}
	})
	return s.impl
}

func (s *lazyDeviceFlowStore) StoreDeviceAuthorization(deviceCode string, userCode string, data *storage_models.DeviceCode) error {
	return s.store().StoreDeviceAuthorization(deviceCode, userCode, data)
}

func (s *lazyDeviceFlowStore) FindByUserCode(userCode string) (*storage_models.DeviceCode, error) {
	return s.store().FindByUserCode(userCode)
}

func (s *lazyDeviceFlowStore) FindByDeviceCode(deviceCode string) (*storage_models.DeviceCode, error) {
	return s.store().FindByDeviceCode(deviceCode)
}

func (s *lazyDeviceFlowStore) UpdateByUserCode(userCode string, data *storage_models.DeviceCode) error {
	return s.store().UpdateByUserCode(userCode, data)
}

func (s *lazyDeviceFlowStore) RemoveByDeviceCode(deviceCode string) error {
	return s.store().RemoveByDeviceCode(deviceCode)
}

type lazyBackchannelAuthenticationRequestStore struct {
	cfg  *ServerConfig
	once sync.Once
	impl storage.BackchannelAuthenticationRequestStore
}

func (s *lazyBackchannelAuthenticationRequestStore) store() storage.BackchannelAuthenticationRequestStore {
	s.once.Do(func() {
		s.impl = s.cfg.BackchannelAuthenticationRequestStore()
		if s.impl == nil {
			s.impl = storage_memory.NewMemoryBackchannelAuthenticationRequestStore()
		}
	})
	return s.impl
}

func (s *lazyBackchannelAuthenticationRequestStore) StoreBackchannelAuthenticationRequest(requestID string, data *storage_models.BackchannelAuthenticationRequest) error {
	return s.store().StoreBackchannelAuthenticationRequest(requestID, data)
}

func (s *lazyBackchannelAuthenticationRequestStore) FindBackchannelAuthenticationRequest(requestID string) (*storage_models.BackchannelAuthenticationRequest, error) {
	return s.store().FindBackchannelAuthenticationRequest(requestID)
}

func (s *lazyBackchannelAuthenticationRequestStore) UpdateBackchannelAuthenticationRequest(requestID string, data *storage_models.BackchannelAuthenticationRequest) error {
	return s.store().UpdateBackchannelAuthenticationRequest(requestID, data)
}

func (s *lazyBackchannelAuthenticationRequestStore) RemoveBackchannelAuthenticationRequest(requestID string) error {
	return s.store().RemoveBackchannelAuthenticationRequest(requestID)
}
