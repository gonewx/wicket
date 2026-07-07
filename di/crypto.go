// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/storage"
)

// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Crypto.cs
// Static marker only; godi-gen reads these registrations at build time.
//
// dotnet 的 AddSigningCredential（Crypto.cs#L29/L75/L101/L121/L134/L147 各重载）
// 与 AddValidationKey（#L200/L214/L235/L257/L285 各重载）本质均为
// AddSingleton(实例) 多次调用累积多实现（每次包一个 InMemorySigningCredentialsStore /
// InMemoryValidationKeysStore）。godi 为编译期 DI，注册条数静态固定，无法按
// 运行时内容展开 N 条注册 → ServerConfig 缝切片字段
// （SigningCredentialStores / ValidationKeysStores）即 Go 侧唯一等价通道（AD-5）。
//
// 签名凭据流转路径：宿主装配期（cmd/main.go、测试宿主）以
// NewMemorySigningCredentialStore / NewMemoryValidationKeysStore 包好实例后
// SetSigningCredentialStores / SetValidationKeysStores 填缝 → 本文件切片类型
// 服务从缝返回 → KeyMaterialService 等消费方经构造注入收切片（AC2 形态①）。
//
// 生命周期偏离：dotnet 实例注册为 Singleton；此处用 Transient Form B——godi
// Singleton 工厂在 NewRoot eager 装配时执行，读缝会提前冻结 ServerConfig
// （lazy seam 铁律），且切片值类型无法 lazy 包装。缝数据启动后恒定，每次解析
// 返回同一缝切片，内容语义等价。
//
// AddDeveloperSigningCredential（Crypto.cs#L161）exception：gois 无开发者临时
// 密钥对应物，CleanRoomKeyGap 自动密钥（3.3 已注册）是现行默认。见 REGISTRATION_MAP。
func registerCrypto() {
	var r godi.Registry

	// From: BuilderExtensions/Crypto.cs#L29-L157 AddSigningCredential 重载归并
	// -> AddSingleton<ISigningCredentialStore>(实例) 累积 (Add)
	godi.AddTransientFactory[[]storage.SigningCredentialStore](&r, func(p godi.Provider) []storage.SigningCredentialStore {
		return godi.GetRequired[*ServerConfig](p).SigningCredentialStores()
	})

	// From: BuilderExtensions/Crypto.cs#L200-L285 AddValidationKey 重载归并
	// -> AddSingleton<IValidationKeysStore>(实例) 累积 (Add)
	godi.AddTransientFactory[[]storage.ValidationKeysStore](&r, func(p godi.Provider) []storage.ValidationKeysStore {
		return godi.GetRequired[*ServerConfig](p).ValidationKeysStores()
	})
}
