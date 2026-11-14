// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"fmt"
	"log/slog"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
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

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/InMemory.cs#L128 AddInMemoryClients ->
	// Additional.cs#L124-L131 AddClientStore<InMemoryClientStore>() (Add):
	// TryAddTransient<InMemoryClientStore>（inner）并入工厂体内联构造；
	// AddTransient<IClientStore, ValidatingClientStore<InMemoryClientStore>> 为
	// IClientStore 真身。Transient：每次解析重建（含 NewMemoryClientStore 的
	// 重复 id 校验与索引构建），缝数据只读，与 dotnet Transient 行为一致。
	// 宿主经 SetClientStore 注入时 inner 为注入值（与 SetClients 互斥，Freeze
	// 校验），两条路径都包 ValidatingClientStore，见 di/client_store.go。
	godi.AddTransientFactory[storage.ClientStore](&r, func(p godi.Provider) storage.ClientStore {
		return storage_impl.NewValidatingClientStore(
			clientStoreSource(godi.GetRequired[*ServerConfig](p)),
			godi.GetRequired[validators.ClientConfigurationValidator](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/InMemory.cs#L130-L138 AddInMemoryClients 条件替换
	// ICorsPolicyService -> InMemoryCorsPolicyService (Add，条件覆盖定案)：
	// dotnet 语义 = 当前注册为 DefaultCorsPolicyService(Transient) 则覆盖；gois
	// 产品组合恒用 in-memory clients，最终注册即 InMemory 版。godi 无覆盖语义，
	// Core.cs#L191 Default 版注册行已删除（REGISTRATION_MAP closed(3.5)）。
	// 与 ClientStore 同源：经 storage.ClientOriginLookup 按 origin 查询（注入
	// 值或静态列表的 MemoryClientStore），见 di/client_store.go。
	godi.AddTransientFactory[services.CorsPolicyService](&r, func(p godi.Provider) services.CorsPolicyService {
		return newCorsPolicyService(
			godi.GetRequired[*ServerConfig](p),
			godi.GetRequired[validators.ClientConfigurationValidator](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/InMemory.cs#L43/L71/L99 AddInMemoryIdentityResources/
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

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/InMemory.cs#L166 AddInMemoryPersistedGrants
	// (TryAddSingleton -> ServerConfig 覆盖钩子)：lazy seam 包装避免 NewRoot
	// eager 装配提前冻结 ServerConfig；缝覆盖优先，默认 NewMemoryPersistedGrantStore()
	// = NewServer 现硬编码等价。注册行自 3.3 done-early（di/pluggable_services.go）
	// 移入本文件归位。
	godi.AddSingleton[storage.PersistedGrantStore, lazyPersistedGrantStore](&r)

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/InMemory.cs#L167 AddInMemoryPersistedGrants
	// (TryAddSingleton -> ServerConfig 覆盖钩子)：同上 lazy seam；默认
	// NewMemoryDeviceFlowStore()。DeviceFlowCodeService 消费同步切换为容器解析。
	godi.AddSingleton[storage.DeviceFlowStore, lazyDeviceFlowStore](&r)
	godi.AddSingleton[storage.BackchannelAuthenticationRequestStore, lazyBackchannelAuthenticationRequestStore](&r)
}
