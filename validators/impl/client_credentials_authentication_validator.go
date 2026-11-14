// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ClientCredentialsAuthenticationValidator wraps the client authenticator of
// the token endpoint and refuses a client_credentials token request from a
// client that did not actually authenticate (RFC 6749 §4.4: the grant is for
// confidential clients only). Other grants pass through unchanged.
type ClientCredentialsAuthenticationValidator struct {
	inner  validators.ClientSecretValidator
	logger *slog.Logger
}

var _ validators.ClientSecretValidator = (*ClientCredentialsAuthenticationValidator)(nil)

// NewClientCredentialsAuthenticationValidator wraps inner.
func NewClientCredentialsAuthenticationValidator(inner validators.ClientSecretValidator, logger *slog.Logger) *ClientCredentialsAuthenticationValidator {
	return &ClientCredentialsAuthenticationValidator{inner: inner, logger: logger}
}

// Validate runs the wrapped validator. A failure is returned as it is; a
// success for a client_credentials request of a client that did not
// authenticate becomes invalid_client.
func (v *ClientCredentialsAuthenticationValidator) Validate(request *http.Request) *validators_models.ClientSecretValidationResult {
	result := v.inner.Validate(request)
	if result == nil || result.Error != nil || request == nil {
		return result
	}
	// The grant type is read from the same source the token handler
	// dispatches on: the parsed form, query string included.
	if request.Form == nil {
		_ = request.ParseForm()
	}
	if request.Form.Get(wicket.TokenRequestGrantType) != wicket.GrantTypeClientCredentials {
		return result
	}
	if clientAuthenticated(result.Client, result.Secret) {
		return result
	}
	if v.logger != nil {
		clientId := ""
		if result.Client != nil {
			clientId = result.Client.ClientId
		}
		v.logger.Info("client_credentials request from a client that did not authenticate", slog.String("client_id", clientId))
	}
	failed := validators_models.NewClientSecretValidationResult()
	failed.Error = wicket.TokenErrorsInvalidClient
	return failed
}

// clientAuthenticated reports whether the client proved its identity: with
// a private_key_jwt assertion, with a TLS client certificate under a tls
// method, or with a secret it is required to present.
func clientAuthenticated(client *storage_models.Client, secret *models.ParsedSecret) bool {
	if client == nil {
		return false
	}
	if secret != nil {
		switch secret.Type {
		case wicket.ParsedSecretTypesJwtBearer:
			if client.TokenEndpointAuthMethod == wicket.EndpointAuthenticationMethodsPrivateKeyJwt {
				return true
			}
		case wicket.ParsedSecretTypesX509Certificate:
			if client.TokenEndpointAuthMethod == wicket.EndpointAuthenticationMethodsTlsClientAuth ||
				client.TokenEndpointAuthMethod == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth {
				return true
			}
		}
	}
	return client.RequireClientSecret && !client.IsImplicitOnly()
}
