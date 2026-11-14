// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"log/slog"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientcert"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
)

// EnableClientCertificateAuthentication declares mutual TLS client
// authentication (RFC 8705) enabled with the given options. It must be
// called before Freeze. A repeated call replaces the options. The
// declaration makes the implementation exist: the method parsers, the
// authenticator and the mtls alias routes. Whether mutual TLS is advertised
// in discovery still follows WicketOptions.MutualTls.Enabled.
func (c *ServerConfig) EnableClientCertificateAuthentication(options clientcert.Options) {
	if c.frozen {
		panic("EnableClientCertificateAuthentication must not be called after Freeze")
	}
	c.clientCertificateEnabled = true
	c.clientCertificateOptions = options
}

// ClientCertificateAuthenticationEnabled reports whether mutual TLS client
// authentication was declared enabled.
func (c *ServerConfig) ClientCertificateAuthenticationEnabled() bool {
	return c != nil && c.clientCertificateEnabled
}

// ClientCertificateMethodEnabled reports whether the given mutual TLS client
// authentication method is available: the feature is enabled and, for
// tls_client_auth, trusted authorities are configured.
func (c *ServerConfig) ClientCertificateMethodEnabled(method string) bool {
	if !c.ClientCertificateAuthenticationEnabled() {
		return false
	}
	switch method {
	case wicket.EndpointAuthenticationMethodsTlsClientAuth:
		return c.clientCertificateOptions.TrustedAuthorities != nil
	case wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth:
		return true
	default:
		return false
	}
}

// ClientCertificateOptions returns the declared options, or the zero value
// while the feature is not enabled.
func (c *ServerConfig) ClientCertificateOptions() clientcert.Options {
	if !c.ClientCertificateAuthenticationEnabled() {
		return clientcert.Options{}
	}
	return c.clientCertificateOptions
}

// SetClientCertificateSource injects where client certificates are read
// from. Nil restores the default, the peer certificates of the TLS
// connection. A host behind a TLS terminating proxy injects a source reading
// what the proxy forwards and is responsible for trusting that proxy. It
// must be called before Freeze.
func (c *ServerConfig) SetClientCertificateSource(source clientcert.CertificateSource) {
	if c.frozen {
		panic("SetClientCertificateSource must not be called after Freeze")
	}
	c.clientCertificateSource = source
}

// ClientCertificateSource returns the injected source, or the default one.
func (c *ServerConfig) ClientCertificateSource() clientcert.CertificateSource {
	if c == nil || c.clientCertificateSource == nil {
		return clientcert.ConnectionCertificateSource{}
	}
	return c.clientCertificateSource
}

// tlsClientAuthSecretParserFromProvider yields the tls_client_auth method
// parser while that method is available, and the inert parser otherwise.
func tlsClientAuthSecretParserFromProvider(p godi.Provider) validators.SecretParser {
	if !godi.GetRequired[*ServerConfig](p).ClientCertificateMethodEnabled(wicket.EndpointAuthenticationMethodsTlsClientAuth) {
		return inertSecretParser{}
	}
	return clientcert.NewTlsClientAuthParser()
}

// selfSignedTlsClientAuthSecretParserFromProvider yields the
// self_signed_tls_client_auth method parser while that method is available,
// and the inert parser otherwise.
func selfSignedTlsClientAuthSecretParserFromProvider(p godi.Provider) validators.SecretParser {
	if !godi.GetRequired[*ServerConfig](p).ClientCertificateMethodEnabled(wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth) {
		return inertSecretParser{}
	}
	return clientcert.NewSelfSignedTlsClientAuthParser()
}

// mtlsEndpointHandler serves an mtls alias route with the handler of its main
// route while mutual TLS client authentication is enabled. Otherwise it
// yields no handler, so the request falls through to the next handler as if
// the route were not registered.
func mtlsEndpointHandler[T hosting.EndpointHandler](p godi.Provider) (hosting.EndpointHandler, error) {
	if !godi.GetRequired[*ServerConfig](p).ClientCertificateAuthenticationEnabled() {
		return nil, nil
	}
	return godi.GetRequired[T](p), nil
}

// withClientCertificateAuthentication wraps inner with the mutual TLS client
// authenticator while the feature is enabled and returns inner otherwise.
func withClientCertificateAuthentication(p godi.Provider, inner validators.ClientSecretValidator) validators.ClientSecretValidator {
	cfg := godi.GetRequired[*ServerConfig](p)
	if !cfg.ClientCertificateAuthenticationEnabled() {
		return inner
	}
	return clientcert.NewClientAuthenticator(
		inner,
		godi.GetRequired[storage.ClientStore](p),
		cfg.ClientCertificateSource(),
		cfg.ClientCertificateOptions(),
		cfg.ClientCertificateMethodEnabled,
		godi.GetRequired[services.SystemClock](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

// accessTokenConfirmationFromProvider yields the access token binder while
// mutual TLS client authentication is enabled and nil otherwise, in which
// case the token service leaves every access token unbound as before.
func accessTokenConfirmationFromProvider(p godi.Provider) services.AccessTokenConfirmation {
	cfg := godi.GetRequired[*ServerConfig](p)
	if !cfg.ClientCertificateAuthenticationEnabled() {
		return nil
	}
	return clientcert.NewAccessTokenBinder(
		godi.GetRequired[storage.ClientStore](p),
		cfg.ClientCertificateSource(),
	)
}

// withCertificateBoundAccessTokens wraps the token endpoint's client
// authenticator so a client registered for certificate bound access tokens
// is refused without a client certificate before any grant is redeemed. It
// returns inner while mutual TLS client authentication is not enabled.
func withCertificateBoundAccessTokens(p godi.Provider, inner validators.ClientSecretValidator) validators.ClientSecretValidator {
	cfg := godi.GetRequired[*ServerConfig](p)
	if !cfg.ClientCertificateAuthenticationEnabled() {
		return inner
	}
	return clientcert.NewCertificateBindingValidator(inner, cfg.ClientCertificateSource(), godi.GetRequired[*slog.Logger](p))
}
