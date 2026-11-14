// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/validators"
)

// MethodParser declares one mutual TLS client authentication method in the
// secret parser chain. The certificate is not a secret the chain can parse
// from the request, so Parse never yields one; the parser exists so that the
// method is listed among the available authentication methods. The
// authentication itself happens in ClientAuthenticator.
type MethodParser struct {
	method string
}

var _ validators.SecretParser = MethodParser{}

// NewTlsClientAuthParser declares the tls_client_auth method.
func NewTlsClientAuthParser() MethodParser {
	return MethodParser{method: wicket.EndpointAuthenticationMethodsTlsClientAuth}
}

// NewSelfSignedTlsClientAuthParser declares the self_signed_tls_client_auth
// method.
func NewSelfSignedTlsClientAuthParser() MethodParser {
	return MethodParser{method: wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth}
}

// Parse always returns nil, nil.
func (MethodParser) Parse(*http.Request) (*models.ParsedSecret, error) { return nil, nil }

// AuthenticationMethod returns the declared method name.
func (p MethodParser) AuthenticationMethod() string { return p.method }

// IsCertificateMethod reports whether method is one of the two mutual TLS
// client authentication methods.
func IsCertificateMethod(method string) bool {
	return method == wicket.EndpointAuthenticationMethodsTlsClientAuth ||
		method == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
}
