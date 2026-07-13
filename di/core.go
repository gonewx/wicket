// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/auth"
	authcookies "github.com/gonewx/wicket/auth/cookies"
	authcore "github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/google"
	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
	"github.com/gonewx/wicket/config"
	config_options "github.com/gonewx/wicket/config/options"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/dynamicscheme"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
	dynamicschemes "github.com/gonewx/wicket/hosting/dynamic/schemes"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/responses"
	responses_impl "github.com/gonewx/wicket/responses/impl"
	"github.com/gonewx/wicket/server"
	"github.com/gonewx/wicket/services"
	impl "github.com/gonewx/wicket/services/impl"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs
// (TryAddSingleton<ISystemClock, SystemClock>). Go has no framework layer, so
// this seed lives at the composition root. Epic 3.1 must inventory it as a
// framework-side registration rather than a Core.cs file mapping.
func registerCore() {
	var r godi.Registry
	godi.AddSingleton[services.SystemClock, impl.SystemClock](&r)
	// ServerConfig is a Go-only migration seam with no dotnet counterpart
	// (AD-5). It must be registered before AddOptions because the generated
	// eager singleton graph constructs OptionsFactory during NewRoot().
	godi.AddSingleton[*ServerConfig, ServerConfig](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs
	// Go has no ILogger<T> framework registration; expose the shared slog logger
	// via ServerConfig with server.DefaultLogger() as the default. The returned
	// logger defers seam reads until log time so NewRoot() does not freeze the
	// fill window.
	godi.AddSingletonFactory[*slog.Logger](&r, func(p godi.Provider) *slog.Logger {
		return newServerConfigLogger(godi.GetRequired[*ServerConfig](p), server.DefaultLogger())
	})
	// via platform service registration. dotnet registers
	// a singleton accessor backed by AsyncLocal; Go has no AsyncLocal equivalent,
	// so this migration intentionally uses scoped request storage.
	godi.AddScoped[accessor.HttpContextAccessor, accessor.DefaultHttpContextAccessor](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs
	godi.AddTransientFactory[hosting.EndpointRouter](&r, func(p godi.Provider) hosting.EndpointRouter {
		return hosting.NewEndpointRouter(
			godi.GetServices[*hosting.Endpoint](p),
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L109 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesAuthorize, gois.ProtocolRoutePathsAuthorize, endpointHandler[*handlers.AuthorizeHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L110 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesAuthorize, gois.ProtocolRoutePathsAuthorizeCallback, endpointHandler[*handlers.AuthorizeCallbackHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L111 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesToken, gois.ProtocolRoutePathsToken, endpointHandler[*handlers.TokenHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L112 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesDiscovery, gois.ProtocolRoutePathsDiscoveryConfiguration, endpointHandler[*handlers.DiscoveryHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L113 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesDiscovery, gois.ProtocolRoutePathsDiscoveryWebKeys, endpointHandler[*handlers.DiscoveryKeyHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L114 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesCheckSession, gois.ProtocolRoutePathsCheckSession, endpointHandler[*handlers.CheckSessionHandler])
	})
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesBackchannelAuthentication, gois.ProtocolRoutePathsBackchannelAuthentication, endpointHandler[*handlers.BackchannelAuthenticationHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L116 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesIntrospection, gois.ProtocolRoutePathsIntrospection, endpointHandler[*handlers.IntrospectionHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L117 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesUserInfo, gois.ProtocolRoutePathsUserInfo, endpointHandler[*handlers.UserInfoHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L118 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesEndSession, gois.ProtocolRoutePathsEndSession, endpointHandler[*handlers.EndSessionHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L119 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesEndSession, gois.ProtocolRoutePathsEndSessionCallback, endpointHandler[*handlers.EndSessionCallbackHandler])
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.AuthorizeHandler](&r, newAuthorizeHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.AuthorizeCallbackHandler](&r, newAuthorizeCallbackHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.TokenHandler](&r, newTokenHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.DiscoveryHandler](&r, newDiscoveryHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.DiscoveryKeyHandler](&r, newDiscoveryKeyHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.CheckSessionHandler](&r, newCheckSessionHandlerFromProvider)
	godi.AddTransientFactory[*handlers.BackchannelAuthenticationHandler](&r, newBackchannelAuthenticationHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.IntrospectionHandler](&r, newIntrospectionHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.UserInfoHandler](&r, newUserInfoHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.EndSessionHandler](&r, newEndSessionHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.EndSessionCallbackHandler](&r, newEndSessionCallbackHandlerFromProvider)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L163 (Add)
	AddMessageCookie[*messages.ConsentResponse](&r)
	godi.AddSingleton[dp.DataProtectionProvider, impl.DataProtectionProvider](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L49 (AddRequiredPlatformServices -> services.AddOptions())
	AddOptions[*config_options.WicketOptions](&r)
	AddOptions[*auth.Options](&r)
	// The static scheme registry resolves its default-scheme configuration from
	// the container *auth.Options snapshot. The factory reads the resolved value
	// so default-scheme selection reflects configured options; it self-registers
	// the concrete type with a singleton lifetime.
	godi.AddSingletonFactory[*authcore.SchemeProvider](&r, func(p godi.Provider) *authcore.SchemeProvider {
		opts, err := godi.GetRequired[optspkg.Options[*auth.Options]](p).Value()
		if err != nil {
			panic(fmt.Errorf("resolve auth options for scheme provider: %w", err))
		}
		return authcore.NewSchemeProvider(opts)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L390 (Decorator descriptor is Transient).
	godi.AddTransientFactory[*gois.Decorator[auth.SchemeProvider]](&r, func(p godi.Provider) *gois.Decorator[auth.SchemeProvider] {
		return gois.NewDecorator[auth.SchemeProvider](godi.GetRequired[*authcore.SchemeProvider](p))
	})
	// The outer scheme provider merges the static registry with runtime dynamic
	// providers. Its constructor params (decorator, options, resolver, logger)
	// are auto-wired from their registrations below.
	godi.AddTransient[auth.SchemeProvider, dynamicschemes.AuthSchemeProvider](&r)
	// The dynamic provider store persists runtime scheme provider records. It is
	// a singleton so its state persists across the transient scheme provider
	// instances; the factory reads only singleton options, not the ServerConfig
	// store seam, so eager singleton assembly does not freeze that seam.
	godi.AddSingletonFactory[dynamicscheme.ProviderStore](&r, func(p godi.Provider) dynamicscheme.ProviderStore {
		opts := godi.GetRequired[*config_options.DynamicProviderOptions](p)
		if opts != nil && opts.StorageProvider != nil {
			return opts.StorageProvider
		}
		return dynamicscheme.NewMemoryStore()
	})
	// The resolver merges the dynamic store view behind a TTL cache. Singleton so
	// its cache persists; reads only singleton options, the store, and a clock.
	godi.AddSingletonFactory[*dynamicscheme.Resolver](&r, func(p godi.Provider) *dynamicscheme.Resolver {
		opts := godi.GetRequired[*config_options.DynamicProviderOptions](p)
		enabled := false
		var cacheTTL time.Duration
		var clock dynamicscheme.Clock
		if opts != nil {
			enabled = opts.Enabled
			cacheTTL = opts.CacheTTL
			clock = opts.Clock
		}
		if clock == nil {
			clock = godi.GetRequired[services.SystemClock](p)
		}
		return dynamicscheme.NewResolver(godi.GetRequired[dynamicscheme.ProviderStore](p), clock, enabled, cacheTTL)
	})
	// (TryAddScoped<IAuthenticationHandlerProvider, AuthenticationHandlerProvider>).
	godi.AddScopedFactory[auth.HandlerProvider](&r, func(p godi.Provider) auth.HandlerProvider {
		return authcore.NewHandlerProvider(godi.GetRequired[auth.SchemeProvider](p), p)
	})
	// Handlers resolve keyed by scheme name; each built-in cookie scheme keys a
	// transient handler so the handler provider can activate it per request. The
	// host may supply a handler through the ServerConfig seam; the concrete
	// cookie handler is not yet available, so without a seam value the keyed
	// registration serves the neutral unsupported handler until it lands.
	// TODO: pending Epic 5 implementation
	godi.AddKeyedTransientFactory[auth.Handler](&r, gois.DefaultCookieAuthenticationScheme, func(p godi.Provider) auth.Handler {
		if provider := godi.GetRequired[*ServerConfig](p).AuthenticationHandlerProvider(gois.DefaultCookieAuthenticationScheme); provider != nil {
			if h := provider(p); h != nil {
				return h
			}
		}
		return authcore.NewUnsupportedHandler()
	})
	godi.AddKeyedTransientFactory[auth.Handler](&r, gois.ExternalCookieAuthenticationScheme, func(p godi.Provider) auth.Handler {
		if provider := godi.GetRequired[*ServerConfig](p).AuthenticationHandlerProvider(gois.ExternalCookieAuthenticationScheme); provider != nil {
			if h := provider(p); h != nil {
				return h
			}
		}
		return authcore.NewUnsupportedHandler()
	})
	// OAuth options and handler registration. The options factory and monitor
	// follow the same pattern as *auth.Options above; the handler is keyed but
	// not yet bound to a concrete scheme — host startup calls AddScheme for
	// concrete OAuth providers (Google, Facebook, etc.).
	AddOptions[*oauthcore.Options](&r)
	godi.AddTransientFactory[optspkg.OptionsMonitor[*oauthcore.Options]](&r, func(p godi.Provider) optspkg.OptionsMonitor[*oauthcore.Options] {
		return optspkg.NewOptionsMonitor[*oauthcore.Options](godi.GetRequired[optspkg.OptionsFactory[*oauthcore.Options]](p))
	})
	// Google provider: options assembly + PostConfigure + handler factory.
	AddOptions[*google.Options](&r)
	godi.AddSingletonFactory[optspkg.PostConfigureOptions[*google.Options]](&r, func(p godi.Provider) optspkg.PostConfigureOptions[*google.Options] {
		return oauthcore.NewPostConfigureOptions[*google.Options](godi.GetRequired[dp.DataProtectionProvider](p))
	})
	godi.AddTransientFactory[optspkg.OptionsMonitor[*google.Options]](&r, func(p godi.Provider) optspkg.OptionsMonitor[*google.Options] {
		return optspkg.NewOptionsMonitor[*google.Options](godi.GetRequired[optspkg.OptionsFactory[*google.Options]](p))
	})
	godi.AddKeyedTransientFactory[auth.Handler](&r, gois.GoogleAuthenticationScheme, func(p godi.Provider) auth.Handler {
		if provider := godi.GetRequired[*ServerConfig](p).AuthenticationHandlerProvider(gois.GoogleAuthenticationScheme); provider != nil {
			if h := provider(p); h != nil {
				return h
			}
		}
		return google.NewHandler(
			godi.GetRequired[optspkg.OptionsMonitor[*google.Options]](p),
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[services.SystemClock](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L162 (AddScoped<IUserSession, DefaultUserSession>, Add).
	// Form B keeps ServerUrls reading the live HttpContextAccessor request.
	godi.AddScopedFactory[services.UserSession](&r, func(p godi.Provider) services.UserSession {
		return impl.NewUserSession(
			godi.GetRequired[accessor.HttpContextAccessor](p),
			godi.GetRequired[auth.HandlerProvider](p),
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[services.SystemClock](p),
			impl.NewServerUrlsFromAccessor(godi.GetRequired[accessor.HttpContextAccessor](p)),
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[auth.SchemeProvider](p),
			godi.GetRequired[sessionpkg.Store](p),
		)
	})
	// (TryAddSingleton<IClaimsTransformation, NoopClaimsTransformation>).
	godi.AddSingleton[auth.ClaimsTransformation, authcore.NoopClaimsTransformation](&r)
	// (TryAddScoped<IAuthenticationService, AuthenticationService>), rewritten by
	// Core.cs#L358 AddDecorator to concrete self-registration with Scoped lifetime.
	godi.AddScoped[*authcore.Service, authcore.Service](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L390 (Decorator descriptor is Transient).
	godi.AddTransientFactory[*gois.Decorator[auth.Service]](&r, func(p godi.Provider) *gois.Decorator[auth.Service] {
		return gois.NewDecorator[auth.Service](godi.GetRequired[*authcore.Service](p))
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L94 (AddTransientDecorator outer AddTransient).
	// Form B enforces request-scope-only resolution; Form A would let Root
	// construct a transient with scoped dependencies.
	godi.AddTransientFactory[auth.Service](&r, func(p godi.Provider) auth.Service {
		requestFromProvider(p)
		return server.NewWicketAuthenticationService(
			godi.GetRequired[*gois.Decorator[auth.Service]](p),
			godi.GetRequired[auth.SchemeProvider](p),
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[services.UserSession](p),
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*config_options.WicketOptions](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L78 (Add) - AddAuthentication(DefaultCookieAuthenticationScheme)
	godi.AddSingletonFactory[optspkg.ConfigureOptions[*auth.Options]](&r, func(p godi.Provider) optspkg.ConfigureOptions[*auth.Options] {
		return optspkg.NewConfigureNameOptions(optspkg.DefaultName, func(o *auth.Options) error {
			o.DefaultScheme = gois.DefaultCookieAuthenticationScheme
			return nil
		})
	})
	AddOptions[*authcookies.AuthenticationOptions](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L81 (Add)
	godi.AddSingletonFactory[optspkg.ConfigureOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.ConfigureOptions[*authcookies.AuthenticationOptions] {
		return config.NewConfigureInternalCookieOptions(godi.GetRequired[*config_options.WicketOptions](p))
	})
	godi.AddSingletonFactory[optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions] {
		return authcookies.NewPostConfigureAuthenticationOptions(impl.NewDataProtectionProvider())
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L93 (Add)
	godi.AddSingletonFactory[optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions] {
		return config.NewPostConfigureInternalCookieOptions(
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[optspkg.Options[*auth.Options]](p),
			godi.GetRequired[*slog.Logger](p), // logger is currently unused inside PostConfigureInternalCookieOptions.
		)
	})
	godi.AddSingletonFactory[optspkg.ValidateOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.ValidateOptions[*authcookies.AuthenticationOptions] {
		return optspkg.NewValidateOptions(gois.DefaultCookieAuthenticationScheme,
			func(o *authcookies.AuthenticationOptions) error { return o.Validate() },
			optspkg.DefaultValidationFailureMessage)
	})
	godi.AddSingletonFactory[optspkg.ValidateOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.ValidateOptions[*authcookies.AuthenticationOptions] {
		return optspkg.NewValidateOptions(gois.ExternalCookieAuthenticationScheme,
			func(o *authcookies.AuthenticationOptions) error { return o.Validate() },
			optspkg.DefaultValidationFailureMessage)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L50-51 (Add)
	godi.AddSingletonFactory[*config_options.WicketOptions](&r, func(p godi.Provider) *config_options.WicketOptions {
		v, err := godi.GetRequired[optspkg.Options[*config_options.WicketOptions]](p).Value()
		if err != nil {
			// Accepted design decision from code review dated 2026-07-03:
			// dotnet resolver exceptions fail startup synchronously, so this
			// factory panics at construction time instead of threading the
			// error through NewRoot()'s error return, matching that fail-fast
			// semantics. This path is unreachable today because no
			// ValidateOptions is registered for WicketOptions; if one
			// is added later, a resolution failure will panic during NewRoot()
			// rather than surface as a NewRoot() error.
			panic(fmt.Errorf("resolve WicketOptions: %w", err))
		}
		return v
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L52-53 (Add)
	godi.AddSingletonFactory[*config_options.PersistentGrantOptions](&r, func(p godi.Provider) *config_options.PersistentGrantOptions {
		return godi.GetRequired[*config_options.WicketOptions](p).PersistentGrants
	})
	godi.AddTransientFactory[*config_options.DynamicProviderOptions](&r, func(p godi.Provider) *config_options.DynamicProviderOptions {
		return godi.GetRequired[*config_options.WicketOptions](p).DynamicProviders
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L243 (TryAdd -> unique registration)
	godi.AddTransientFactory[*config_options.KeyManagementOptions](&r, func(p godi.Provider) *config_options.KeyManagementOptions {
		return godi.GetRequired[*config_options.WicketOptions](p).KeyManagement
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L150 (Add)
	godi.AddTransientFactory[services.ServerUrls](&r, func(p godi.Provider) services.ServerUrls {
		return impl.NewServerUrls(requestFromProvider(p))
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L151 (Add)
	godi.AddTransientFactory[services.IssuerNameService](&r, func(p godi.Provider) services.IssuerNameService {
		req := requestFromProvider(p)
		svc := impl.NewIssuerNameService(godi.GetRequired[*config_options.WicketOptions](p))
		svc.Init(req)
		return svc
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L152 (Add)
	godi.AddTransientFactory[validators.SecretsListParser](&r, func(p godi.Provider) validators.SecretsListParser {
		return validators_impl.NewSecretParser(
			godi.GetServices[validators.SecretParser](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L153 (Add)
	godi.AddTransientFactory[validators.SecretsListValidator](&r, func(p godi.Provider) validators.SecretsListValidator {
		return validators_impl.NewSecretValidator(
			godi.GetRequired[services.SystemClock](p),
			godi.GetServices[validators.SecretValidator](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L312 (TryAddTransient)
	godi.AddTransientFactory[responses.TokenResponseGenerator](&r, func(p godi.Provider) responses.TokenResponseGenerator {
		return responses_impl.NewTokenResponseGeneratorWithBackchannelRequests(
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[services.TokenService](p),
			godi.GetRequired[services.RefreshTokenService](p),
			godi.GetRequired[validators.ScopeParser](p),
			godi.GetRequired[storage.ResourceStore](p),
			godi.GetRequired[storage.ClientStore](p),
			godi.GetRequired[storage.BackchannelAuthenticationRequestStore](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L313 (TryAddTransient)
	godi.AddTransient[responses.UserInfoResponseGenerator, responses_impl.UserInfoResponseGenerator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L314 (TryAddTransient)
	godi.AddTransient[responses.IntrospectionResponseGenerator, responses_impl.IntrospectionResponseGenerator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L315 (TryAddTransient -> ServerConfig seam)
	godi.AddTransientFactory[responses.AuthorizeInteractionResponseGenerator](&r, func(p godi.Provider) responses.AuthorizeInteractionResponseGenerator {
		return responses_impl.NewAuthorizeInteractionResponseGenerator(
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[*config_options.WicketOptions](p),
			godi.GetRequired[services.ConsentService](p),
			godi.GetRequired[services.ProfileService](p),
			godi.GetRequired[services.ServerUrls](p),
			godi.GetRequired[*ServerConfig](p).AuthorizationParametersMessageStore(),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L316 (TryAddTransient)
	godi.AddTransient[responses.AuthorizeResponseGenerator, responses_impl.AuthorizeResponseGenerator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L317 (TryAddTransient)
	godi.AddTransient[responses.DiscoveryResponseGenerator, responses_impl.DiscoveryResponseGenerator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L318 (TryAddTransient)
	godi.AddTransient[responses.TokenRevocationResponseGenerator, responses_impl.TokenRevocationResponseGenerator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L319 (TryAddTransient)
	godi.AddTransient[responses.DeviceAuthorizationResponseGenerator, responses_impl.DeviceAuthorizationResponseGenerator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L332 (AddTransient)
	godi.AddTransient[validators.SecretParser, validators_impl.BasicAuthenticationSecretParser](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L333 (AddTransient)
	godi.AddTransient[validators.SecretParser, validators_impl.PostBodySecretParser](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L345 (AddTransient)
	godi.AddTransient[validators.SecretValidator, validators_impl.HashedSharedSecretValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L154 (Add)
	godi.AddTransientFactory[*validators_impl.ExtensionGrantValidator](&r, func(p godi.Provider) *validators_impl.ExtensionGrantValidator {
		return validators_impl.NewExtensionGrantValidator(
			godi.GetServices[validators.ExtensionGrantValidator](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L155 (Add)
	godi.AddTransient[*validators_impl.BearerTokenUsageValidator, validators_impl.BearerTokenUsageValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L156 (Add)
	godi.AddTransient[validators.JwtRequestValidator, validators_impl.JwtRequestValidator](&r)
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Core.cs#L158 (Add)
	godi.AddTransientFactory[*impl.ReturnUrlParser](&r, func(p godi.Provider) *impl.ReturnUrlParser {
		return impl.NewReturnUrlParser(godi.GetServices[services.ReturnUrlParser](p))
	})
}
