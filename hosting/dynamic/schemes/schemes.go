// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package schemes

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	config_options "github.com/gonewx/wicket/config/options"
)

type AuthSchemeProvider struct {
	inner auth.SchemeProvider
}

func NewAuthSchemeProvider(inner *gois.Decorator[auth.SchemeProvider], dynamicProviders *config_options.DynamicProviderOptions) AuthSchemeProvider {
	if inner == nil {
		return AuthSchemeProvider{}
	}
	return AuthSchemeProvider{inner: inner.Instance}
}

func (p AuthSchemeProvider) GetAllSchemes() []*auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return p.inner.GetAllSchemes()
}

func (p AuthSchemeProvider) GetScheme(name string) *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return p.inner.GetScheme(name)
}

func (p AuthSchemeProvider) GetDefaultAuthenticateScheme() *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return p.inner.GetDefaultAuthenticateScheme()
}

func (p AuthSchemeProvider) GetDefaultChallengeScheme() *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return p.inner.GetDefaultChallengeScheme()
}

func (p AuthSchemeProvider) GetDefaultForbidScheme() *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return p.inner.GetDefaultForbidScheme()
}

func (p AuthSchemeProvider) GetDefaultSignInScheme() *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return p.inner.GetDefaultSignInScheme()
}

func (p AuthSchemeProvider) GetDefaultSignOutScheme() *auth.Scheme {
	if p.inner == nil {
		return nil
	}
	return p.inner.GetDefaultSignOutScheme()
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

func (p AuthSchemeProvider) GetRequestHandlerSchemes() ([]*auth.Scheme, error) {
	if p.inner == nil {
		return nil, nil
	}
	return p.inner.GetRequestHandlerSchemes()
}

func UseSchemeAuthMiddleware(logger *slog.Logger, dynamicProviders *config_options.DynamicProviderOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}
