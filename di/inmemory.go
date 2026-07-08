// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/services"
	services_memory "github.com/gonewx/wicket/services/memory"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/InMemory.cs
// Static marker only; godi-gen reads these registrations at build time.
//
// dotnet 的 AddSingleton(IEnumerable<T>) 数据实例注册以 ServerConfig 缝字段
// （Clients / IdentityScopes / ApiResources / ApiScopes）为 Go 等价物（AD-5），
// 各工厂 Form B 延迟读缝。AddClientStore/AddResourceStore 泛型 helper 属
// Additional.cs，语义并入本文件注册行注释，di/additional.go 无独立注册行。
// AddInMemoryCaching（IMemoryCache / ICache<> 开放泛型）为可选 API，gois 无
// DefaultCache/CachingClientStore 对应物，exception 见 REGISTRATION_MAP。
func registerInMemory() {
	var r godi.Registry

	// From: BuilderExtensions/InMemory.cs#L128 AddInMemoryClients ->
	// Additional.cs#L124-L131 AddClientStore<InMemoryClientStore>() (Add):
	// TryAddTransient<InMemoryClientStore>（inner）并入工厂体内联构造；
	// AddTransient<IClientStore, ValidatingClientStore<InMemoryClientStore>> 为
	// IClientStore 真身。Transient：每次解析重建（含 NewMemoryClientStore 的
	// 重复 id 校验与索引构建），缝数据只读，与 dotnet Transient 行为一致。
	godi.AddTransientFactory[storage.ClientStore](&r, func(p godi.Provider) storage.ClientStore {
		inner, err := storage_memory.NewMemoryClientStore(godi.GetRequired[*ServerConfig](p).Clients())
		if err != nil {
			panic(fmt.Errorf("construct MemoryClientStore: %w", err))
		}
		return storage_impl.NewValidatingClientStore(
			inner,
			godi.GetRequired[validators.ClientConfigurationValidator](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})

	// From: BuilderExtensions/InMemory.cs#L130-L138 AddInMemoryClients 条件替换
	// ICorsPolicyService -> InMemoryCorsPolicyService (Add，条件覆盖定案)：
	// dotnet 语义 = 当前注册为 DefaultCorsPolicyService(Transient) 则覆盖；gois
	// 产品组合恒用 in-memory clients，最终注册即 InMemory 版。godi 无覆盖语义，
	// Core.cs#L191 Default 版注册行已删除（REGISTRATION_MAP closed(3.5)）。
	godi.AddTransientFactory[services.CorsPolicyService](&r, func(p godi.Provider) services.CorsPolicyService {
		return services_memory.NewMemoryCorsPolicyService(
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*ServerConfig](p).Clients(),
		)
	})

	// From: BuilderExtensions/InMemory.cs#L43/L71/L99 AddInMemoryIdentityResources/
	// ApiResources/ApiScopes -> Additional.cs#L139-L145 AddResourceStore (Add)：
	// 朴素 Transient 链（无 Validating 包装 = dotnet 原文）。
	godi.AddTransientFactory[storage.ResourceStore](&r, func(p godi.Provider) storage.ResourceStore {
		cfg := godi.GetRequired[*ServerConfig](p)
		store, err := storage_memory.NewMemoryResourcesStore(
			cfg.IdentityScopes(),
			cfg.ApiResources(),
			cfg.ApiScopes(),
		)
		if err != nil {
			panic(fmt.Errorf("construct MemoryResourcesStore: %w", err))
		}
		return store
	})

	// From: BuilderExtensions/InMemory.cs#L166 AddInMemoryPersistedGrants
	// (TryAddSingleton -> ServerConfig 覆盖钩子)：lazy seam 包装避免 NewRoot
	// eager 装配提前冻结 ServerConfig；缝覆盖优先，默认 NewMemoryPersistedGrantStore()
	// = NewServer 现硬编码等价。注册行自 3.3 done-early（di/pluggable_services.go）
	// 移入本文件归位。
	godi.AddSingletonFactory[storage.PersistedGrantStore](&r, func(p godi.Provider) storage.PersistedGrantStore {
		return &lazyPersistedGrantStore{cfg: godi.GetRequired[*ServerConfig](p)}
	})

	// From: BuilderExtensions/InMemory.cs#L167 AddInMemoryPersistedGrants
	// (TryAddSingleton -> ServerConfig 覆盖钩子)：同上 lazy seam；默认
	// NewMemoryDeviceFlowStore()。DeviceFlowCodeService 消费同步切换为容器解析。
	godi.AddSingletonFactory[storage.DeviceFlowStore](&r, func(p godi.Provider) storage.DeviceFlowStore {
		return &lazyDeviceFlowStore{cfg: godi.GetRequired[*ServerConfig](p)}
	})
	godi.AddSingletonFactory[storage.BackchannelAuthenticationRequestStore](&r, func(p godi.Provider) storage.BackchannelAuthenticationRequestStore {
		return &lazyBackchannelAuthenticationRequestStore{cfg: godi.GetRequired[*ServerConfig](p)}
	})
}

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
