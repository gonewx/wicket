// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	models_contexts "github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	services_memory "github.com/gonewx/wicket/services/memory"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/tools"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs
// Static marker only; godi-gen reads these registrations at build time.
func registerPluggableServicesAndValidators() {
	var r godi.Registry

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L194 (TryAddTransient)
	AddProtectedMessageStore[messages.LogoutMessage](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L196 (TryAddTransient)
	AddProtectedMessageStore[messages.ErrorMessage](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L195 (TryAddTransient)
	AddProtectedMessageStore[models_contexts.LogoutNotificationContext](&r)
	AddPersistentGrantSerializer(&r)

	// ClientStore / ResourceStore / PersistedGrantStore 注册已随 3.5 移至
	// di/inmemory.go（InMemory.cs 归属文件）：ClientStore/ResourceStore 修正为
	// Transient（含 ValidatingClientStore 链），PersistedGrantStore lazy Singleton 归位。
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L227 (AddDistributedMemoryCache)
	godi.AddSingleton[services.DistributedCache, services_memory.MemoryDistributedCache](&r)

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L220 (TryAdd -> unique Go registration; no IHttpClientFactory equivalent)
	godi.AddTransientFactory[services.JwtRequestUriHttpClient](&r, func(p godi.Provider) services.JwtRequestUriHttpClient {
		return services_impl.NewJwtRequestUriHttpClient(http.DefaultClient, godi.GetRequired[*config_options.WicketOptions](p))
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L221 (TryAdd -> ServerConfig client seam; no IHttpClientFactory equivalent)
	godi.AddTransientFactory[services.BackChannelLogoutHttpClient](&r, func(p godi.Provider) services.BackChannelLogoutHttpClient {
		return services_impl.NewBackChannelLogoutHttpClient(
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*ServerConfig](p).BackChannelLogoutHttpClient(),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L193 (TryAddTransient)
	godi.AddTransient[storage.ConsentMessageStore, storage_impl.ConsentMessageStore](&r)

	// TODO: pending Epic 2/3 implementation.

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L205 (TryAddTransient)
	godi.AddTransient[services.HandleGenerationService, services_impl.HandleGenerationService](&r)
	// Core.cs#L191 DefaultCorsPolicyService 注册已随 3.5 删除：InMemory.cs#L130-L138
	// 条件替换定案为 InMemoryCorsPolicyService，见 di/inmemory.go 与 REGISTRATION_MAP。
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L210 (TryAddTransient)
	godi.AddTransient[services.UserCodeGenerator, services_impl.NumericUserCodeGenerator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L209 (TryAddTransient)
	godi.AddTransient[services.UserCodeService, services_impl.UserCodeService](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L214 (TryAddTransient)
	godi.AddTransient[validators.ScopeParser, validators_impl.ScopeParser](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L200 (TryAddTransient)
	godi.AddTransient[storage.AuthorizationCodeStore, storage_impl.AuthorizationCodeStore](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L201 (TryAddTransient)
	godi.AddTransient[storage.RefreshTokenStore, storage_impl.RefreshTokenStore](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L202 (TryAddTransient)
	godi.AddTransient[storage.ReferenceTokenStore, storage_impl.ReferenceTokenStore](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L203 (TryAddTransient)
	godi.AddTransient[storage.UserConsentStore, storage_impl.UserConsentStore](&r)
	// TODO: pending Epic 2/3 implementation.
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L183 (TryAddTransient)
	godi.AddTransient[services.PersistedGrantService, services_impl.PersistedGrantService](&r)
	godi.AddTransient[services.KeyMaterialService, services_impl.KeyMaterialService](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L186 (TryAddTransient)
	godi.AddTransient[services.TokenCreationService, services_impl.TokenCreationService](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L192 (TryAddTransient)
	godi.AddTransientFactory[services.ProfileService](&r, func(p godi.Provider) services.ProfileService {
		if provider := godi.GetRequired[*ServerConfig](p).ProfileProvider(); provider != nil {
			if svc := provider(); svc != nil {
				return svc
			}
		}
		return services_impl.NewProfileService(godi.GetRequired[*slog.Logger](p))
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L187 (TryAddTransient)
	godi.AddTransient[services.ClaimsService, services_impl.ClaimsService](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L188 (TryAddTransient)
	godi.AddTransient[services.RefreshTokenService, services_impl.RefreshTokenService](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L189 (TryAddTransient)
	// DeviceFlowStore 经容器解析（3.5：storage.DeviceFlowStore Singleton lazy seam，
	// di/inmemory.go）——消除原工厂内联读缝每次新建默认实例与容器单例的双通道。
	godi.AddTransientFactory[services.DeviceFlowCodeService](&r, func(p godi.Provider) services.DeviceFlowCodeService {
		return services_impl.NewDeviceFlowCodeService(
			godi.GetRequired[storage.DeviceFlowStore](p),
			godi.GetRequired[services.HandleGenerationService](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L190 (TryAddTransient)
	godi.AddTransient[services.ConsentService, services_impl.ConsentService](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L211 (TryAddTransient)
	godi.AddTransient[services.LogoutNotificationService, services_impl.LogoutNotificationService](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L212 (TryAddTransient)
	godi.AddTransient[services.BackchannelLogoutService, services_impl.BackchannelLogoutService](&r)
	godi.AddTransient[validators.ResourceValidator, validators_impl.ResourceValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L226 (TryAddTransient)
	godi.AddTransient[services.DeviceFlowThrottlingService, services_impl.DistributedDeviceFlowThrottlingService](&r)
	godi.AddTransient[services.BackchannelAuthenticationThrottlingService, services_impl.BackchannelAuthenticationThrottlingService](&r)
	godi.AddTransientFactory[services.BackchannelAuthenticationNotificationService](&r, func(p godi.Provider) services.BackchannelAuthenticationNotificationService {
		return services_impl.NewBackchannelAuthenticationNotificationService(godi.GetRequired[*ServerConfig](p).BackchannelAuthenticationNotificationHttpClient())
	})
	godi.AddTransient[validators.BackchannelAuthenticationRequestIdValidator, validators_impl.BackchannelAuthenticationRequestIdValidator](&r)
	godi.AddTransientFactory[validators.BackchannelAuthenticationUserValidator](&r, func(p godi.Provider) validators.BackchannelAuthenticationUserValidator {
		if override := godi.GetRequired[*ServerConfig](p).BackchannelAuthenticationUserValidator(); override != nil {
			return override
		}
		return validators_impl.NewBackchannelAuthenticationUserValidator()
	})
	godi.AddTransient[validators.BackchannelAuthenticationRequestValidator, validators_impl.BackchannelAuthenticationRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L185 (TryAddTransient)
	godi.AddTransientFactory[services.TokenService](&r, func(p godi.Provider) services.TokenService {
		return services_impl.NewTokenService(
			godi.GetRequired[services.ClaimsService](p),
			godi.GetRequired[storage.ReferenceTokenStore](p),
			godi.GetRequired[services.TokenCreationService](p),
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[services.KeyMaterialService](p),
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[*slog.Logger](p),
			requestFromProvider(p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L197 (TryAddTransient)
	godi.AddTransientFactory[services.InteractionService](&r, func(p godi.Provider) services.InteractionService {
		return services_impl.NewInteractionService(
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[storage.MessageStore[messages.LogoutMessage]](p),
			godi.GetRequired[storage.MessageStore[messages.ErrorMessage]](p),
			godi.GetRequired[storage.ConsentMessageStore](p),
			godi.GetRequired[services.PersistedGrantService](p),
			userSessionFromProvider(p),
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*services_impl.ReturnUrlParser](p),
			godi.GetRequired[services.ServerUrls](p),
			godi.GetRequired[storage.MessageStore[models_contexts.LogoutNotificationContext]](p),
		)
	})
	godi.AddSingletonFactory[sessionpkg.Store](&r, func(p godi.Provider) sessionpkg.Store {
		return sessionpkg.NewMemoryStore(godi.GetRequired[services.SystemClock](p))
	})
	godi.AddTransientFactory[services.SessionCoordinationService](&r, func(p godi.Provider) services.SessionCoordinationService {
		opts := godi.GetRequired[*config_options.WicketOptions](p)
		enabled := false
		if opts != nil && opts.ServerSideSessions != nil {
			enabled = opts.ServerSideSessions.Enabled
		}
		coordinator := sessionpkg.NewCoordinator(
			godi.GetRequired[sessionpkg.Store](p),
			godi.GetRequired[services.SystemClock](p),
			enabled,
		)
		return services_impl.NewSessionCoordinationAdapter(coordinator)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L159 (AddTransient)
	godi.AddTransient[*tools.TokenTools, tools.TokenTools](&r)

	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L281 (TryAddTransient)
	godi.AddTransient[validators.TokenRevocationRequestValidator, validators_impl.TokenRevocationRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L282 (TryAddTransient)
	godi.AddTransientFactory[validators.AuthorizeRequestValidator](&r, func(p godi.Provider) validators.AuthorizeRequestValidator {
		return validators_impl.NewAuthorizeRequestValidator(
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[services.IssuerNameService](p),
			godi.GetRequired[storage.ClientStore](p),
			godi.GetRequired[services.JwtRequestUriHttpClient](p),
			godi.GetRequired[validators.JwtRequestValidator](p),
			godi.GetRequired[validators.RedirectUriValidator](p),
			godi.GetRequired[validators.ResourceValidator](p),
			userSessionFromProvider(p),
			godi.GetRequired[validators.CustomAuthorizeRequestValidator](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L280 (TryAddTransient)
	godi.AddTransientFactory[validators.EndSessionRequestValidator](&r, func(p godi.Provider) validators.EndSessionRequestValidator {
		return validators_impl.NewEndSessionRequestValidator(
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[validators.TokenValidator](p),
			godi.GetRequired[validators.RedirectUriValidator](p),
			userSessionFromProvider(p),
			godi.GetRequired[services.LogoutNotificationService](p),
			godi.GetRequired[storage.MessageStore[models_contexts.LogoutNotificationContext]](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L283 (TryAddTransient)
	godi.AddTransient[validators.TokenRequestValidator, validators_impl.TokenRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L284 (TryAddTransient)
	godi.AddTransient[validators.RedirectUriValidator, validators_impl.StrictRedirectUriValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L285 (TryAddTransient)
	godi.AddTransient[validators.TokenValidator, validators_impl.TokenValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L286 (TryAddTransient)
	godi.AddTransient[validators.IntrospectionRequestValidator, validators_impl.IntrospectionRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L287 (TryAddTransient)
	godi.AddTransientFactory[validators.ResourceOwnerPasswordValidator](&r, func(p godi.Provider) validators.ResourceOwnerPasswordValidator {
		if override := godi.GetRequired[*ServerConfig](p).ResourceOwnerValidator(); override != nil {
			return override
		}
		return validators_impl.NewNotSupportedResourceOwnerPasswordValidator(godi.GetRequired[*slog.Logger](p))
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L288 (TryAddTransient)
	godi.AddTransient[validators.CustomTokenRequestValidator, validators_impl.CustomTokenRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L289 (TryAddTransient)
	godi.AddTransient[validators.UserInfoRequestValidator, validators_impl.UserInfoRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L290 (TryAddTransient)
	godi.AddTransient[validators.ClientConfigurationValidator, validators_impl.ClientConfigurationValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L292 (TryAddTransient)
	godi.AddTransient[validators.DeviceAuthorizationRequestValidator, validators_impl.DeviceAuthorizationRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L293 (TryAddTransient)
	godi.AddTransient[validators.DeviceCodeValidator, validators_impl.DeviceCodeValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L299 (TryAddTransient)
	godi.AddTransient[validators.CustomTokenValidator, validators_impl.CustomTokenValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L300 (TryAddTransient)
	godi.AddTransient[validators.CustomAuthorizeRequestValidator, validators_impl.CustomAuthorizeRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L223 (AddTransient)
	godi.AddTransient[validators.ClientSecretValidator, validators_impl.ClientSecretValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L224 (AddTransient)
	godi.AddTransient[validators.ApiSecretValidator, validators_impl.ApiSecretValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L161 (AddTransient)
	godi.AddTransientFactory[services.ReturnUrlParser](&r, func(p godi.Provider) services.ReturnUrlParser {
		return services_impl.NewOidcReturnUrlParser(
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[validators.AuthorizeRequestValidator](p),
			userSessionFromProvider(p),
			godi.GetRequired[services.ServerUrls](p),
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*ServerConfig](p).AuthorizationParametersMessageStore(),
		)
	})
}

func userSessionFromProvider(p godi.Provider) services.UserSession {
	return godi.GetRequired[services.UserSession](p)
}

func returnUrlParsersFromProvider(p godi.Provider) []services.ReturnUrlParser {
	return godi.GetServices[services.ReturnUrlParser](p)
}
