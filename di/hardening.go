// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"log/slog"
	"slices"

	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

// RequireAsymmetricRequestObjects declares that request objects (the
// request and request_uri authorize parameters) are accepted only when
// signed with an asymmetric algorithm (RS, PS or ES with SHA-256, -384 or
// -512); symmetric signatures and keys are refused, and discovery advertises
// only those algorithms. It must be called before Freeze. A repeated call
// has no further effect.
func (c *ServerConfig) RequireAsymmetricRequestObjects() {
	if c.frozen {
		panic("RequireAsymmetricRequestObjects must not be called after Freeze")
	}
	c.asymmetricRequestObjectsRequired = true
}

// AsymmetricRequestObjectsRequired reports whether request objects require
// an asymmetric signature: declared so, or the high security profile is
// enabled.
func (c *ServerConfig) AsymmetricRequestObjectsRequired() bool {
	return c != nil && (c.asymmetricRequestObjectsRequired || c.HighSecurityProfileEnabled())
}

// RequireClientCredentialsAuthentication declares that the
// client_credentials grant is issued only to a client that actually
// authenticated at the token endpoint: with a required secret, a
// private_key_jwt assertion or a TLS client certificate. A client without a
// required secret is refused with invalid_client. It must be called before
// Freeze. A repeated call has no further effect.
func (c *ServerConfig) RequireClientCredentialsAuthentication() {
	if c.frozen {
		panic("RequireClientCredentialsAuthentication must not be called after Freeze")
	}
	c.clientCredentialsAuthenticationRequired = true
}

// ClientCredentialsAuthenticationRequired reports whether the
// client_credentials grant requires client authentication: declared so, or
// the high security profile is enabled.
func (c *ServerConfig) ClientCredentialsAuthenticationRequired() bool {
	return c != nil && (c.clientCredentialsAuthenticationRequired || c.HighSecurityProfileEnabled())
}

// PrivateKeyJwtSigningAlgorithms returns a copy of the algorithms the server
// accepts for private_key_jwt client assertions, or nil while the feature is
// not enabled. Client configuration validation reads it.
func (c *ServerConfig) PrivateKeyJwtSigningAlgorithms() []string {
	if c == nil || !c.PrivateKeyJwtEnabled() {
		return nil
	}
	return slices.Clone(c.PrivateKeyJwtOptions().SigningAlgorithms)
}

// withClientCredentialsAuthentication wraps the token endpoint's client
// authenticator so a client_credentials request of a client that did not
// authenticate is refused. It returns inner while the option is not
// declared.
func withClientCredentialsAuthentication(p godi.Provider, inner validators.ClientSecretValidator) validators.ClientSecretValidator {
	if !godi.GetRequired[*ServerConfig](p).ClientCredentialsAuthenticationRequired() {
		return inner
	}
	return validators_impl.NewClientCredentialsAuthenticationValidator(inner, godi.GetRequired[*slog.Logger](p))
}

// jwtRequestValidatorFromProvider yields the request object validator,
// wrapped by the asymmetric request object decorator while that option is
// declared.
func jwtRequestValidatorFromProvider(p godi.Provider) validators.JwtRequestValidator {
	inner := validators_impl.NewJwtRequestValidator(
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[services.IssuerNameService](p),
		godi.GetRequired[*slog.Logger](p),
	)
	if cfg, ok := godi.Get[*ServerConfig](p); !ok || !cfg.AsymmetricRequestObjectsRequired() {
		return inner
	}
	return validators_impl.NewAsymmetricRequestObjectValidator(inner)
}
