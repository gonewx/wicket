// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"context"
	"sync"
	"time"

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

func (s *lazyPersistedGrantStore) Store(ctx context.Context, grant *storage_models.PersistedGrant) error {
	return s.store().Store(ctx, grant)
}

func (s *lazyPersistedGrantStore) Get(ctx context.Context, key string) (*storage_models.PersistedGrant, error) {
	return s.store().Get(ctx, key)
}

func (s *lazyPersistedGrantStore) GetAll(ctx context.Context, filter *storage.PersistedGrantFilter) ([]*storage_models.PersistedGrant, error) {
	return s.store().GetAll(ctx, filter)
}

func (s *lazyPersistedGrantStore) Remove(ctx context.Context, key string) error {
	return s.store().Remove(ctx, key)
}

func (s *lazyPersistedGrantStore) RemoveAll(ctx context.Context, filter *storage.PersistedGrantFilter) error {
	return s.store().RemoveAll(ctx, filter)
}

func (s *lazyPersistedGrantStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
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

func (s *lazyDeviceFlowStore) StoreDeviceAuthorization(ctx context.Context, deviceCode string, userCode string, data *storage_models.DeviceCode) error {
	return s.store().StoreDeviceAuthorization(ctx, deviceCode, userCode, data)
}

func (s *lazyDeviceFlowStore) FindByUserCode(ctx context.Context, userCode string) (*storage_models.DeviceCode, error) {
	return s.store().FindByUserCode(ctx, userCode)
}

func (s *lazyDeviceFlowStore) FindByDeviceCode(ctx context.Context, deviceCode string) (*storage_models.DeviceCode, error) {
	return s.store().FindByDeviceCode(ctx, deviceCode)
}

func (s *lazyDeviceFlowStore) UpdateByUserCode(ctx context.Context, userCode string, data *storage_models.DeviceCode) error {
	return s.store().UpdateByUserCode(ctx, userCode, data)
}

func (s *lazyDeviceFlowStore) RemoveByDeviceCode(ctx context.Context, deviceCode string) error {
	return s.store().RemoveByDeviceCode(ctx, deviceCode)
}

func (s *lazyDeviceFlowStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
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

func (s *lazyBackchannelAuthenticationRequestStore) StoreBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *storage_models.BackchannelAuthenticationRequest) error {
	return s.store().StoreBackchannelAuthenticationRequest(ctx, requestID, data)
}

func (s *lazyBackchannelAuthenticationRequestStore) FindBackchannelAuthenticationRequest(ctx context.Context, requestID string) (*storage_models.BackchannelAuthenticationRequest, error) {
	return s.store().FindBackchannelAuthenticationRequest(ctx, requestID)
}

func (s *lazyBackchannelAuthenticationRequestStore) UpdateBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *storage_models.BackchannelAuthenticationRequest) error {
	return s.store().UpdateBackchannelAuthenticationRequest(ctx, requestID, data)
}

func (s *lazyBackchannelAuthenticationRequestStore) RemoveBackchannelAuthenticationRequest(ctx context.Context, requestID string) error {
	return s.store().RemoveBackchannelAuthenticationRequest(ctx, requestID)
}

func (s *lazyBackchannelAuthenticationRequestStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}
