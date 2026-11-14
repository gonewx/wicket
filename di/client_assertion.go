// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"log/slog"
	"net/http"
	"slices"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/clientassertion"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
)

// privateKeyJwtFeatureName is the replay dependent feature name of
// private_key_jwt client authentication. The entry recorded under this name
// is the only enablement state of the feature.
const privateKeyJwtFeatureName = "private_key_jwt"

// EnablePrivateKeyJwt declares private_key_jwt client authentication enabled
// with the given options. It must be called before Freeze. A repeated call
// replaces the options.
func (c *ServerConfig) EnablePrivateKeyJwt(options clientassertion.Options) {
	if c.frozen {
		panic("EnablePrivateKeyJwt must not be called after Freeze")
	}
	options.SigningAlgorithms = slices.Clone(options.SigningAlgorithms)
	c.privateKeyJwtOptions = options
	c.enableReplayDependentFeature(privateKeyJwtFeatureName)
}

// PrivateKeyJwtEnabled reports whether private_key_jwt client authentication
// was declared enabled.
func (c *ServerConfig) PrivateKeyJwtEnabled() bool {
	return c.replayDependentFeatureEnabled(privateKeyJwtFeatureName)
}

// PrivateKeyJwtOptions returns a copy of the declared options with every
// unset field replaced by its default. It returns the zero value while the
// feature is not enabled.
func (c *ServerConfig) PrivateKeyJwtOptions() clientassertion.Options {
	if !c.PrivateKeyJwtEnabled() {
		return clientassertion.Options{}
	}
	options := c.privateKeyJwtOptions
	defaults := clientassertion.DefaultOptions()
	if options.ClockSkew == 0 {
		options.ClockSkew = defaults.ClockSkew
	}
	if options.MaxAssertionLifetime == 0 {
		options.MaxAssertionLifetime = defaults.MaxAssertionLifetime
	}
	if len(options.SigningAlgorithms) == 0 {
		options.SigningAlgorithms = defaults.SigningAlgorithms
	} else {
		options.SigningAlgorithms = slices.Clone(options.SigningAlgorithms)
	}
	if options.MaxAssertionBytes == 0 {
		options.MaxAssertionBytes = defaults.MaxAssertionBytes
	}
	if options.JwksFetchTimeout == 0 {
		options.JwksFetchTimeout = defaults.JwksFetchTimeout
	}
	if options.MaxJwksResponseBytes == 0 {
		options.MaxJwksResponseBytes = defaults.MaxJwksResponseBytes
	}
	if options.JwksCacheLifetime == 0 {
		options.JwksCacheLifetime = defaults.JwksCacheLifetime
	}
	if options.JwksMinRefreshInterval == 0 {
		options.JwksMinRefreshInterval = defaults.JwksMinRefreshInterval
	}
	return options
}

// requirePrivateKeyJwtOptions panics when the feature is enabled with
// options that do not validate.
func (c *ServerConfig) requirePrivateKeyJwtOptions() {
	if !c.PrivateKeyJwtEnabled() {
		return
	}
	if err := c.PrivateKeyJwtOptions().Validate(); err != nil {
		panic("private_key_jwt options invalid: " + err.Error())
	}
}

// inertSecretParser stands in the parser chain while private_key_jwt is not
// enabled. It never yields a secret and its blank method name is dropped
// from the list of available authentication methods.
type inertSecretParser struct{}

func (inertSecretParser) Parse(*http.Request) (*models.ParsedSecret, error) { return nil, nil }

func (inertSecretParser) AuthenticationMethod() string { return "" }

// clientAssertionSecretParserFromProvider yields the private_key_jwt parser
// of an enabled assembly and the inert parser otherwise. The inert branch
// resolves nothing besides the server configuration.
func clientAssertionSecretParserFromProvider(p godi.Provider) validators.SecretParser {
	cfg := godi.GetRequired[*ServerConfig](p)
	if !cfg.PrivateKeyJwtEnabled() {
		return inertSecretParser{}
	}
	return clientassertion.NewParser(
		cfg.PrivateKeyJwtOptions(),
		godi.GetRequired[*config_options.WicketOptions](p).InputLengthRestrictions.ClientId,
	)
}

// clientAuthenticatorFromProvider yields the client authenticator an endpoint
// handler uses: the registered validator itself while private_key_jwt is not
// enabled, and that validator wrapped by the assertion authenticator when it
// is. Every endpoint handler factory that requires client authentication has
// to obtain its validator here.
func clientAuthenticatorFromProvider(p godi.Provider) validators.ClientSecretValidator {
	inner := godi.GetRequired[validators.ClientSecretValidator](p)
	if !godi.GetRequired[*ServerConfig](p).PrivateKeyJwtEnabled() {
		return inner
	}
	return clientassertion.NewClientAuthenticator(
		inner,
		godi.GetRequired[validators.SecretsListParser](p),
		godi.GetRequired[storage.ClientStore](p),
		godi.GetRequired[*clientassertion.Verifier](p),
		godi.GetRequired[services.IssuerNameService](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

// apiAuthenticatorFromProvider is clientAuthenticatorFromProvider for the
// API resource authentication of the introspection endpoint.
func apiAuthenticatorFromProvider(p godi.Provider) validators.ApiSecretValidator {
	inner := godi.GetRequired[validators.ApiSecretValidator](p)
	if !godi.GetRequired[*ServerConfig](p).PrivateKeyJwtEnabled() {
		return inner
	}
	return clientassertion.NewApiAuthenticator(
		inner,
		godi.GetRequired[validators.SecretsListParser](p),
		godi.GetRequired[storage.ResourceStore](p),
		godi.GetRequired[*clientassertion.Verifier](p),
		godi.GetRequired[services.IssuerNameService](p),
		godi.GetRequired[services.SystemClock](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

// clientAssertionAlgorithmSource is a registered secret parser that names
// the signature algorithms it accepts.
type clientAssertionAlgorithmSource interface {
	AuthenticationMethod() string
	SigningAlgorithms() []string
}

// clientAssertionSigningAlgorithms returns the algorithms of the first
// registered private_key_jwt parser, and false when none is registered.
func clientAssertionSigningAlgorithms(p godi.Provider) ([]string, bool) {
	for _, parser := range godi.GetServices[validators.SecretParser](p) {
		source, ok := parser.(clientAssertionAlgorithmSource)
		if ok && source.AuthenticationMethod() == privateKeyJwtFeatureName {
			return source.SigningAlgorithms(), true
		}
	}
	return nil, false
}
