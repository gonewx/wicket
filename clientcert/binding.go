// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/certbind"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// errBindingClientUnavailable reports an access token whose client cannot be
// found enabled, so whether its token is to be bound is unknown.
var errBindingClientUnavailable = errors.New("clientcert: client of the access token is not available")

// AccessTokenBinder binds the access tokens of clients registered for
// certificate bound access tokens to the client certificate presented with
// the token request (RFC 8705 §3).
type AccessTokenBinder struct {
	clients storage.ClientStore
	source  CertificateSource
}

var _ services.AccessTokenConfirmation = (*AccessTokenBinder)(nil)

// NewAccessTokenBinder builds the binder; a nil source reads the TLS
// connection.
func NewAccessTokenBinder(clients storage.ClientStore, source CertificateSource) *AccessTokenBinder {
	if source == nil {
		source = ConnectionCertificateSource{}
	}
	return &AccessTokenBinder{clients: clients, source: source}
}

// Confirmation returns "" for a client not registered for certificate bound
// access tokens and the thumbprint confirmation of the presented certificate
// otherwise. It fails closed: a client that cannot be found enabled, or a
// registered client that presented no certificate, yields an error.
func (b *AccessTokenBinder) Confirmation(ctx context.Context, request *http.Request, clientId string) (string, error) {
	client, err := extensions.FindEnabledClientById(ctx, b.clients, clientId)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errBindingClientUnavailable, err)
	}
	if client == nil {
		return "", errBindingClientUnavailable
	}
	if !client.TlsClientCertificateBoundAccessTokens {
		return "", nil
	}
	certificates := b.source.ClientCertificates(request)
	if len(certificates) == 0 || certificates[0] == nil {
		return "", fmt.Errorf("clientcert: client registered for certificate bound access tokens presented no certificate: %w", wicket.TokenErrorsInvalidClient)
	}
	return certbind.Confirmation(certificates[0]), nil
}

// CertificateBindingValidator refuses the client authentication of a client
// registered for certificate bound access tokens that presented no client
// certificate, before any grant is redeemed.
type CertificateBindingValidator struct {
	inner  validators.ClientSecretValidator
	source CertificateSource
	logger *slog.Logger
}

var _ validators.ClientSecretValidator = (*CertificateBindingValidator)(nil)

// NewCertificateBindingValidator wraps inner; a nil source reads the TLS
// connection.
func NewCertificateBindingValidator(inner validators.ClientSecretValidator, source CertificateSource, logger *slog.Logger) *CertificateBindingValidator {
	if source == nil {
		source = ConnectionCertificateSource{}
	}
	return &CertificateBindingValidator{inner: inner, source: source, logger: logger}
}

// Validate runs the wrapped validator and turns its success into
// invalid_client when the client is registered for certificate bound access
// tokens and the request carries no client certificate.
func (v *CertificateBindingValidator) Validate(request *http.Request) *validators_models.ClientSecretValidationResult {
	result := v.inner.Validate(request)
	if result == nil || result.Error != nil || result.Client == nil || !result.Client.TlsClientCertificateBoundAccessTokens {
		return result
	}
	certificates := v.source.ClientCertificates(request)
	if len(certificates) == 0 || certificates[0] == nil {
		if v.logger != nil {
			v.logger.Info("client registered for certificate bound access tokens presented no certificate", slog.String("client_id", result.Client.ClientId))
		}
		return failed()
	}
	return result
}
