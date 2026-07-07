// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"fmt"
	"log/slog"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/auth"
	authcookies "github.com/gonewx/wicket/auth/cookies"
	authcore "github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/config"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
	dynamicschemes "github.com/gonewx/wicket/hosting/dynamic/schemes"
	"github.com/gonewx/wicket/models/messages"
	optspkg "github.com/gonewx/wicket/options"
	"github.com/gonewx/wicket/responses"
	responses_impl "github.com/gonewx/wicket/responses/impl"
	"github.com/gonewx/wicket/server"
	"github.com/gonewx/wicket/services"
	impl "github.com/gonewx/wicket/services/impl"
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
	// From: BuilderExtensions/Core.cs AddRequiredPlatformServices platform logging.
	// Go has no ILogger<T> framework registration; expose the shared slog logger
	// via ServerConfig with server.DefaultLogger() as the default. The returned
	// logger defers seam reads until log time so NewRoot() does not freeze the
	// fill window.
	godi.AddSingletonFactory[*slog.Logger](&r, func(p godi.Provider) *slog.Logger {
		return newServerConfigLogger(godi.GetRequired[*ServerConfig](p), server.DefaultLogger())
	})
	// From: Microsoft.Extensions.DependencyInjection HttpServiceCollectionExtensions.AddHttpContextAccessor
	// via IdentityServer AddRequiredPlatformServices (Core.cs). dotnet registers
	// a singleton accessor backed by AsyncLocal; Go has no AsyncLocal equivalent,
	// so this migration intentionally uses scoped request storage.
	godi.AddScoped[accessor.HttpContextAccessor, accessor.DefaultHttpContextAccessor](&r)
	// From: BuilderExtensions/Core.cs#L107 (Add)
	godi.AddTransientFactory[hosting.EndpointRouter](&r, func(p godi.Provider) hosting.EndpointRouter {
		return hosting.NewEndpointRouter(
			godi.GetServices[*hosting.Endpoint](p),
			godi.GetRequired[*config_options.IdentityServerOptions](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: BuilderExtensions/Core.cs#L109 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesAuthorize, gois.ProtocolRoutePathsAuthorize, endpointHandler[*handlers.AuthorizeHandler])
	})
	// From: BuilderExtensions/Core.cs#L110 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesAuthorize, gois.ProtocolRoutePathsAuthorizeCallback, endpointHandler[*handlers.AuthorizeCallbackHandler])
	})
	// From: BuilderExtensions/Core.cs#L111 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesToken, gois.ProtocolRoutePathsToken, endpointHandler[*handlers.TokenHandler])
	})
	// From: BuilderExtensions/Core.cs#L112 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesDiscovery, gois.ProtocolRoutePathsDiscoveryConfiguration, endpointHandler[*handlers.DiscoveryHandler])
	})
	// From: BuilderExtensions/Core.cs#L113 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesDiscovery, gois.ProtocolRoutePathsDiscoveryWebKeys, endpointHandler[*handlers.DiscoveryKeyHandler])
	})
	// From: BuilderExtensions/Core.cs#L114 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesCheckSession, gois.ProtocolRoutePathsCheckSession, endpointHandler[*handlers.CheckSessionHandler])
	})
	// TODO: clean-room reimplementation for clean-room gap endpoint.
	// From: BuilderExtensions/Core.cs#L116 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesIntrospection, gois.ProtocolRoutePathsIntrospection, endpointHandler[*handlers.IntrospectionHandler])
	})
	// From: BuilderExtensions/Core.cs#L117 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesUserInfo, gois.ProtocolRoutePathsUserInfo, endpointHandler[*handlers.UserInfoHandler])
	})
	// From: BuilderExtensions/Core.cs#L118 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesEndSession, gois.ProtocolRoutePathsEndSession, endpointHandler[*handlers.EndSessionHandler])
	})
	// From: BuilderExtensions/Core.cs#L119 (Add + Singleton route metadata)
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(gois.EndpointNamesEndSession, gois.ProtocolRoutePathsEndSessionCallback, endpointHandler[*handlers.EndSessionCallbackHandler])
	})
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.AuthorizeHandler](&r, newAuthorizeHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.AuthorizeCallbackHandler](&r, newAuthorizeCallbackHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.TokenHandler](&r, newTokenHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.DiscoveryHandler](&r, newDiscoveryHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.DiscoveryKeyHandler](&r, newDiscoveryKeyHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.CheckSessionHandler](&r, newCheckSessionHandlerFromProvider)
	// TODO: clean-room reimplementation for clean-room gap handler.
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.IntrospectionHandler](&r, newIntrospectionHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.UserInfoHandler](&r, newUserInfoHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.EndSessionHandler](&r, newEndSessionHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L137 (AddTransient<T>)
	godi.AddTransientFactory[*handlers.EndSessionCallbackHandler](&r, newEndSessionCallbackHandlerFromProvider)
	// From: BuilderExtensions/Core.cs#L163 (Add)
	AddMessageCookie[*messages.ConsentResponse](&r)
	// From: ASP.NET Core DataProtection AddDataProtection platform service used by Core.cs#L163.
	godi.AddSingleton[dp.DataProtectionProvider, impl.DataProtectionProvider](&r)
	// From: BuilderExtensions/Core.cs#L49 (AddRequiredPlatformServices -> services.AddOptions())
	AddOptions[*config_options.IdentityServerOptions](&r)
	// From: aspnetcore AuthenticationCoreServiceCollectionExtensions.cs AddAuthenticationCore (TryAdd)
	// Container *auth.Options currently only closes
	// PostConfigureInternalCookieOptions dependencies; SchemeProvider still
	// consumes the builder-side instance until Epic 4 containerizes schemes.
	AddOptions[*auth.Options](&r)
	// From: aspnetcore Authentication.Core/AuthenticationCoreServiceCollectionExtensions.cs#L20
	// (TryAddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>),
	// rewritten by Core.cs#L358 AddDecorator: remove the interface mapping and
	// self-register the original concrete type with its original Singleton lifetime.
	godi.AddSingleton[*authcore.SchemeProvider, authcore.SchemeProvider](&r)
	// From: BuilderExtensions/Core.cs#L390 (Decorator descriptor is Transient).
	godi.AddTransientFactory[*gois.Decorator[auth.SchemeProvider]](&r, func(p godi.Provider) *gois.Decorator[auth.SchemeProvider] {
		return gois.NewDecorator[auth.SchemeProvider](godi.GetRequired[*authcore.SchemeProvider](p))
	})
	// From: BuilderExtensions/Core.cs#L262 (AddTransientDecorator outer Add).
	godi.AddTransient[auth.SchemeProvider, dynamicschemes.AuthSchemeProvider](&r)
	// From: aspnetcore Authentication.Core/AuthenticationCoreServiceCollectionExtensions.cs#L20
	// (TryAddScoped<IAuthenticationHandlerProvider, AuthenticationHandlerProvider>).
	godi.AddScopedFactory[auth.HandlerProvider](&r, func(p godi.Provider) auth.HandlerProvider {
		return authcore.NewHandlerProvider(godi.GetRequired[auth.SchemeProvider](p), p)
	})
	// From: BuilderExtensions/Core.cs#L162 (AddScoped<IUserSession, DefaultUserSession>, Add).
	// Form B keeps ServerUrls reading the live HttpContextAccessor request.
	godi.AddScopedFactory[services.UserSession](&r, func(p godi.Provider) services.UserSession {
		return impl.NewUserSession(
			godi.GetRequired[accessor.HttpContextAccessor](p),
			godi.GetRequired[auth.HandlerProvider](p),
			godi.GetRequired[*config_options.IdentityServerOptions](p),
			godi.GetRequired[services.SystemClock](p),
			impl.NewServerUrlsFromAccessor(godi.GetRequired[accessor.HttpContextAccessor](p)),
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[auth.SchemeProvider](p),
		)
	})
	// From: aspnetcore Authentication.Core/AuthenticationCoreServiceCollectionExtensions.cs
	// (TryAddSingleton<IClaimsTransformation, NoopClaimsTransformation>).
	godi.AddSingleton[auth.ClaimsTransformation, authcore.NoopClaimsTransformation](&r)
	// From: aspnetcore Authentication.Core/AuthenticationCoreServiceCollectionExtensions.cs
	// (TryAddScoped<IAuthenticationService, AuthenticationService>), rewritten by
	// Core.cs#L358 AddDecorator to concrete self-registration with Scoped lifetime.
	godi.AddScoped[*authcore.Service, authcore.Service](&r)
	// From: BuilderExtensions/Core.cs#L390 (Decorator descriptor is Transient).
	godi.AddTransientFactory[*gois.Decorator[auth.Service]](&r, func(p godi.Provider) *gois.Decorator[auth.Service] {
		return gois.NewDecorator[auth.Service](godi.GetRequired[*authcore.Service](p))
	})
	// From: BuilderExtensions/Core.cs#L94 (AddTransientDecorator outer AddTransient).
	// Form B enforces request-scope-only resolution; Form A would let Root
	// construct a transient with scoped dependencies.
	godi.AddTransientFactory[auth.Service](&r, func(p godi.Provider) auth.Service {
		requestFromProvider(p)
		return server.NewIdentityServerAuthenticationService(
			godi.GetRequired[*gois.Decorator[auth.Service]](p),
			godi.GetRequired[auth.SchemeProvider](p),
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[services.UserSession](p),
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*config_options.IdentityServerOptions](p),
		)
	})
	// From: Core.cs#L78 (Add) - AddAuthentication(DefaultCookieAuthenticationScheme)
	godi.AddSingletonFactory[optspkg.ConfigureOptions[*auth.Options]](&r, func(p godi.Provider) optspkg.ConfigureOptions[*auth.Options] {
		return optspkg.NewConfigureNameOptions(optspkg.DefaultName, func(o *auth.Options) error {
			o.DefaultScheme = gois.DefaultCookieAuthenticationScheme
			return nil
		})
	})
	// From: aspnetcore CookieExtensions.cs AddCookie -> AddSchemeHelper AddOptions<TOptions> (TryAdd)
	AddOptions[*authcookies.AuthenticationOptions](&r)
	// From: Core.cs#L81 (Add)
	godi.AddSingletonFactory[optspkg.ConfigureOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.ConfigureOptions[*authcookies.AuthenticationOptions] {
		return config.NewConfigureInternalCookieOptions(godi.GetRequired[*config_options.IdentityServerOptions](p))
	})
	// From: aspnetcore CookieExtensions.cs AddCookie (TryAddEnumerable Singleton -> unique registration)
	godi.AddSingletonFactory[optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions] {
		return authcookies.NewPostConfigureAuthenticationOptions(impl.NewDataProtectionProvider())
	})
	// From: Core.cs#L93 (Add)
	godi.AddSingletonFactory[optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.PostConfigureOptions[*authcookies.AuthenticationOptions] {
		return config.NewPostConfigureInternalCookieOptions(
			godi.GetRequired[*config_options.IdentityServerOptions](p),
			godi.GetRequired[optspkg.Options[*auth.Options]](p),
			godi.GetRequired[*slog.Logger](p), // logger is currently unused inside PostConfigureInternalCookieOptions.
		)
	})
	// From: aspnetcore AuthenticationBuilder.cs#L29 AddSchemeHelper AddOptions<TOptions>(name).Validate(...)
	godi.AddSingletonFactory[optspkg.ValidateOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.ValidateOptions[*authcookies.AuthenticationOptions] {
		return optspkg.NewValidateOptions(gois.DefaultCookieAuthenticationScheme,
			func(o *authcookies.AuthenticationOptions) error { return o.Validate() },
			optspkg.DefaultValidationFailureMessage)
	})
	// From: aspnetcore AuthenticationBuilder.cs#L29 AddSchemeHelper AddOptions<TOptions>(name).Validate(...)
	godi.AddSingletonFactory[optspkg.ValidateOptions[*authcookies.AuthenticationOptions]](&r, func(p godi.Provider) optspkg.ValidateOptions[*authcookies.AuthenticationOptions] {
		return optspkg.NewValidateOptions(gois.ExternalCookieAuthenticationScheme,
			func(o *authcookies.AuthenticationOptions) error { return o.Validate() },
			optspkg.DefaultValidationFailureMessage)
	})
	// From: BuilderExtensions/Core.cs#L50-51 (Add)
	godi.AddSingletonFactory[*config_options.IdentityServerOptions](&r, func(p godi.Provider) *config_options.IdentityServerOptions {
		v, err := godi.GetRequired[optspkg.Options[*config_options.IdentityServerOptions]](p).Value()
		if err != nil {
			// Accepted design decision (code review of Story 2.3, 2026-07-03):
			// dotnet resolver exceptions fail startup synchronously, so this
			// factory panics at construction time instead of threading the
			// error through NewRoot()'s error return, matching that fail-fast
			// semantics. This path is unreachable today because no
			// ValidateOptions is registered for IdentityServerOptions; if one
			// is added later, a resolution failure will panic during NewRoot()
			// rather than surface as a NewRoot() error.
			panic(fmt.Errorf("resolve IdentityServerOptions: %w", err))
		}
		return v
	})
	// From: BuilderExtensions/Core.cs#L52-53 (Add)
	godi.AddSingletonFactory[*config_options.PersistentGrantOptions](&r, func(p godi.Provider) *config_options.PersistentGrantOptions {
		return godi.GetRequired[*config_options.IdentityServerOptions](p).PersistentGrants
	})
	// From: BuilderExtensions/Core.cs#L261 (AddTransient factory for IdentityServerOptions.CleanRoomProviderGap).
	godi.AddTransientFactory[*config_options.CleanRoomProviderGapOptions](&r, func(p godi.Provider) *config_options.CleanRoomProviderGapOptions {
		return godi.GetRequired[*config_options.IdentityServerOptions](p).CleanRoomProviderGap
	})
	// From: BuilderExtensions/Core.cs#L243 (TryAdd -> unique registration)
	godi.AddTransientFactory[*config_options.CleanRoomKeyGapOptions](&r, func(p godi.Provider) *config_options.CleanRoomKeyGapOptions {
		return godi.GetRequired[*config_options.IdentityServerOptions](p).CleanRoomKeyGap
	})
	// From: BuilderExtensions/Core.cs#L150 (Add)
	godi.AddTransientFactory[services.ServerUrls](&r, func(p godi.Provider) services.ServerUrls {
		return impl.NewServerUrls(requestFromProvider(p))
	})
	// From: BuilderExtensions/Core.cs#L151 (Add)
	godi.AddTransientFactory[services.IssuerNameService](&r, func(p godi.Provider) services.IssuerNameService {
		req := requestFromProvider(p)
		svc := impl.NewIssuerNameService(godi.GetRequired[*config_options.IdentityServerOptions](p))
		svc.Init(req)
		return svc
	})
	// From: BuilderExtensions/Core.cs#L152 (Add)
	godi.AddTransientFactory[validators.SecretsListParser](&r, func(p godi.Provider) validators.SecretsListParser {
		return validators_impl.NewSecretParser(
			godi.GetServices[validators.SecretParser](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: BuilderExtensions/Core.cs#L153 (Add)
	godi.AddTransientFactory[validators.SecretsListValidator](&r, func(p godi.Provider) validators.SecretsListValidator {
		return validators_impl.NewSecretValidator(
			godi.GetRequired[services.SystemClock](p),
			godi.GetServices[validators.SecretValidator](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: BuilderExtensions/Core.cs#L312 (TryAddTransient)
	godi.AddTransient[responses.TokenResponseGenerator, responses_impl.TokenResponseGenerator](&r)
	// From: BuilderExtensions/Core.cs#L313 (TryAddTransient)
	godi.AddTransient[responses.UserInfoResponseGenerator, responses_impl.UserInfoResponseGenerator](&r)
	// From: BuilderExtensions/Core.cs#L314 (TryAddTransient)
	godi.AddTransient[responses.IntrospectionResponseGenerator, responses_impl.IntrospectionResponseGenerator](&r)
	// From: BuilderExtensions/Core.cs#L315 (TryAddTransient -> ServerConfig seam)
	godi.AddTransientFactory[responses.AuthorizeInteractionResponseGenerator](&r, func(p godi.Provider) responses.AuthorizeInteractionResponseGenerator {
		return responses_impl.NewAuthorizeInteractionResponseGenerator(
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[*config_options.IdentityServerOptions](p),
			godi.GetRequired[services.ConsentService](p),
			godi.GetRequired[services.ProfileService](p),
			godi.GetRequired[services.ServerUrls](p),
			godi.GetRequired[*ServerConfig](p).AuthorizationParametersMessageStore(),
		)
	})
	// From: BuilderExtensions/Core.cs#L316 (TryAddTransient)
	godi.AddTransient[responses.AuthorizeResponseGenerator, responses_impl.AuthorizeResponseGenerator](&r)
	// From: BuilderExtensions/Core.cs#L317 (TryAddTransient)
	godi.AddTransient[responses.DiscoveryResponseGenerator, responses_impl.DiscoveryResponseGenerator](&r)
	// From: BuilderExtensions/Core.cs#L318 (TryAddTransient)
	godi.AddTransient[responses.TokenRevocationResponseGenerator, responses_impl.TokenRevocationResponseGenerator](&r)
	// From: BuilderExtensions/Core.cs#L319 (TryAddTransient)
	godi.AddTransient[responses.DeviceAuthorizationResponseGenerator, responses_impl.DeviceAuthorizationResponseGenerator](&r)
	// TODO: clean-room reimplementation for clean-room gap response generator.
	// From: BuilderExtensions/Core.cs#L332 (AddTransient)
	godi.AddTransient[validators.SecretParser, validators_impl.BasicAuthenticationSecretParser](&r)
	// From: BuilderExtensions/Core.cs#L333 (AddTransient)
	godi.AddTransient[validators.SecretParser, validators_impl.PostBodySecretParser](&r)
	// From: BuilderExtensions/Core.cs#L345 (AddTransient)
	godi.AddTransient[validators.SecretValidator, validators_impl.HashedSharedSecretValidator](&r)
	// From: BuilderExtensions/Core.cs#L154 (Add)
	godi.AddTransientFactory[*validators_impl.ExtensionGrantValidator](&r, func(p godi.Provider) *validators_impl.ExtensionGrantValidator {
		return validators_impl.NewExtensionGrantValidator(
			godi.GetServices[validators.ExtensionGrantValidator](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
	// From: BuilderExtensions/Core.cs#L155 (Add)
	godi.AddTransient[*validators_impl.BearerTokenUsageValidator, validators_impl.BearerTokenUsageValidator](&r)
	// From: BuilderExtensions/Core.cs#L156 (Add)
	godi.AddTransient[validators.JwtRequestValidator, validators_impl.JwtRequestValidator](&r)
	// From: BuilderExtensions/Core.cs#L158 (Add)
	godi.AddTransientFactory[*impl.ReturnUrlParser](&r, func(p godi.Provider) *impl.ReturnUrlParser {
		return impl.NewReturnUrlParser(godi.GetServices[services.ReturnUrlParser](p))
	})
	// TODO: clean-room reimplementation for clean-room gap user validator.
}
