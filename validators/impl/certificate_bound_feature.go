// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// CertificateBoundAccessTokenFeature is implemented by feature declarations
// that can report whether certificate bound access tokens can be issued,
// which is the case exactly while mutual TLS client authentication is
// declared enabled.
type CertificateBoundAccessTokenFeature interface {
	// ClientCertificateAuthenticationEnabled reports whether mutual TLS
	// client authentication is declared enabled in this assembly.
	ClientCertificateAuthenticationEnabled() bool
}

func certificateBoundAccessTokensEnabled(features validators.ClientFeatureDeclarations) bool {
	if features == nil {
		return false
	}
	declared, ok := features.(CertificateBoundAccessTokenFeature)
	return ok && declared.ClientCertificateAuthenticationEnabled()
}

// validateCertificateBoundAccessTokens returns the configuration error of a
// client registered for certificate bound access tokens, or "" when it is
// valid or did not register for them.
func validateCertificateBoundAccessTokens(features validators.ClientFeatureDeclarations, client *storage_models.Client) string {
	if !client.TlsClientCertificateBoundAccessTokens {
		return ""
	}
	if !certificateBoundAccessTokensEnabled(features) {
		return "client requires certificate bound access tokens but mutual TLS client authentication is not enabled"
	}
	if client.AllowAccessTokensViaBrowser {
		// A token issued over the front channel cannot be bound to a client
		// certificate.
		return "client requires certificate bound access tokens but allows access tokens via the browser"
	}
	if !client.RequireClientSecret {
		// The refresh token of a public client is not bound; a stolen one
		// could be redeemed for a token bound to the thief's certificate.
		return "client requires certificate bound access tokens but is a public client"
	}
	return ""
}
