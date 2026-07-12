// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package schemes

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dynamicscheme"
)

// AuthSchemeProvider is a two-state authentication scheme provider. When the
// dynamic subsystem is disabled it is a pure pass-through to the inner static
// registry. When enabled it merges the static registry view with runtime
// providers resolved from the dynamic resolver, static entries taking precedence
// on a name conflict. Default-scheme selection always delegates to the static
// registry: choosing the default is a host configuration decision and is not
// influenced by runtime rows.
type AuthSchemeProvider struct {
	inner    auth.SchemeProvider
	resolver *dynamicscheme.Resolver
	logger   *slog.Logger
}

// NewAuthSchemeProvider builds the scheme provider over the inner static
// registry decorator, the dynamic resolver, and options. A nil inner decorator
// or a disabled resolver yields pure static pass-through.
func NewAuthSchemeProvider(
	inner *gois.Decorator[auth.SchemeProvider],
	dynamicProviders *config_options.DynamicProviderOptions,
	resolver *dynamicscheme.Resolver,
	logger *slog.Logger,
) AuthSchemeProvider {
	provider := AuthSchemeProvider{resolver: resolver, logger: logger}
	if inner != nil {
		provider.inner = inner.Instance
	}
	return provider
}

// dynamicEnabled reports whether merged dynamic behavior is active.
func (p AuthSchemeProvider) dynamicEnabled() bool {
	return p.resolver != nil && p.resolver.Enabled()
}

func (p AuthSchemeProvider) GetAllSchemes() []*auth.Scheme {
	if p.inner == nil {
		return nil
	}
	static := p.inner.GetAllSchemes()
	if !p.dynamicEnabled() {
		return static
	}
	providers, err := p.resolver.All()
	if err != nil {
		p.logDynamicError("list dynamic schemes", err)
		return static
	}
	seen := make(map[string]struct{}, len(static))
	merged := make([]*auth.Scheme, 0, len(static)+len(providers))
	for _, scheme := range static {
		if scheme != nil {
			seen[scheme.Name] = struct{}{}
		}
		merged = append(merged, scheme)
	}
	for _, provider := range providers {
		if _, ok := seen[provider.Scheme]; ok {
			continue
		}
		merged = append(merged, schemeFromProvider(provider))
	}
	return merged
}

func (p AuthSchemeProvider) GetScheme(name string) *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	if scheme := p.inner.GetScheme(name); scheme != nil {
		return scheme
	}
	if !p.dynamicEnabled() {
		return nil
	}
	provider, ok, err := p.resolver.Get(name)
	if err != nil {
		p.logDynamicError("resolve dynamic scheme", err)
		return nil
	}
	if !ok {
		return nil
	}
	return schemeFromProvider(provider)
}

func (p AuthSchemeProvider) GetDefaultAuthenticateScheme() *auth.Scheme {
	return p.innerDefault(auth.SchemeProvider.GetDefaultAuthenticateScheme)
}

func (p AuthSchemeProvider) GetDefaultChallengeScheme() *auth.Scheme {
	return p.innerDefault(auth.SchemeProvider.GetDefaultChallengeScheme)
}

func (p AuthSchemeProvider) GetDefaultForbidScheme() *auth.Scheme {
	return p.innerDefault(auth.SchemeProvider.GetDefaultForbidScheme)
}

func (p AuthSchemeProvider) GetDefaultSignInScheme() *auth.Scheme {
	return p.innerDefault(auth.SchemeProvider.GetDefaultSignInScheme)
}

func (p AuthSchemeProvider) GetDefaultSignOutScheme() *auth.Scheme {
	return p.innerDefault(auth.SchemeProvider.GetDefaultSignOutScheme)
}

func (p AuthSchemeProvider) AddScheme(scheme *auth.Scheme) error {
	if p.inner == nil {
		return nil
	}
	return p.inner.AddScheme(scheme)
}

func (p AuthSchemeProvider) TryAddScheme(scheme *auth.Scheme) bool {
	return p.inner != nil && p.inner.TryAddScheme(scheme)
}

func (p AuthSchemeProvider) RemoveScheme(name string) bool {
	return p.inner != nil && p.inner.RemoveScheme(name)
}

func (p AuthSchemeProvider) GetRequestHandlerSchemes() ([]*auth.Scheme, error) {
	if p.inner == nil {
		return nil, nil
	}
	return p.inner.GetRequestHandlerSchemes()
}

// innerDefault delegates a default-scheme lookup to the static registry.
func (p AuthSchemeProvider) innerDefault(pick func(auth.SchemeProvider) *auth.Scheme) *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return pick(p.inner)
}

// logDynamicError records a resolver failure; the provider degrades to the
// static view because SchemeProvider methods have no error return and consumers
// must not fail on a dynamic-store hiccup.
func (p AuthSchemeProvider) logDynamicError(action string, err error) {
	if p.logger != nil {
		p.logger.Warn("dynamic scheme resolution degraded to static view",
			slog.String("action", action),
			slog.Any("error", err),
		)
	}
}

// schemeFromProvider adapts a dynamic provider record to an authentication
// scheme: the provider scheme becomes the scheme name and the protocol becomes
// the handler type.
func schemeFromProvider(provider *dynamicscheme.Provider) *auth.Scheme {
	return auth.NewScheme(provider.Scheme, provider.Protocol)
}

// UseSchemeAuthMiddleware returns request middleware for dynamic scheme
// providers. When disabled it is a no-op. When enabled the returned middleware
// currently passes the request through: per-request callback activation depends
// on the endpoint/handler pipeline and is out of scope here. The options
// argument is consumed to choose the branch.
func UseSchemeAuthMiddleware(logger *slog.Logger, dynamicProviders *config_options.DynamicProviderOptions) func(http.Handler) http.Handler {
	enabled := dynamicProviders != nil && dynamicProviders.Enabled
	if !enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	if logger != nil {
		logger.Debug("dynamic scheme authentication middleware active")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
}
