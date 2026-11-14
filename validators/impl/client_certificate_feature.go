// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// ClientCertificateFeature is implemented by feature declarations that can
// report the mutual TLS client authentication methods the assembly serves.
type ClientCertificateFeature interface {
	// ClientCertificateMethodEnabled reports whether the given mutual TLS
	// client authentication method is available in this assembly.
	ClientCertificateMethodEnabled(method string) bool
}

func clientCertificateMethodEnabled(features validators.ClientFeatureDeclarations, method string) bool {
	if features == nil {
		return false
	}
	declared, ok := features.(ClientCertificateFeature)
	return ok && declared.ClientCertificateMethodEnabled(method)
}

// validateClientCertificateMethod returns the configuration error of a
// client registered for a mutual TLS method, or "" when it is valid.
func validateClientCertificateMethod(features validators.ClientFeatureDeclarations, client *storage_models.Client) string {
	method := client.TokenEndpointAuthMethod
	if !clientCertificateMethodEnabled(features, method) {
		return "client requires " + method + " client authentication but the method is not enabled"
	}
	if method == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth {
		if client.Jwks == "" {
			return "client requires self_signed_tls_client_auth but registers no inline JWK Set"
		}
		return ""
	}
	registered := 0
	for _, value := range []string{
		client.TlsClientAuthSubjectDn,
		client.TlsClientAuthSanDns,
		client.TlsClientAuthSanUri,
		client.TlsClientAuthSanIp,
		client.TlsClientAuthSanEmail,
	} {
		if value != "" {
			registered++
		}
	}
	if registered != 1 {
		return "client requires tls_client_auth but does not register exactly one certificate subject attribute"
	}
	return ""
}
