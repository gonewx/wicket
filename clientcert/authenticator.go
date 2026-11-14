// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ClientAuthenticator authenticates clients registered for a mutual TLS
// method and hands every other client to the wrapped validator. A client
// registered for a mutual TLS method can authenticate in no other way.
type ClientAuthenticator struct {
	inner         validators.ClientSecretValidator
	clients       storage.ClientStore
	source        CertificateSource
	options       Options
	methodEnabled func(string) bool
	clock         services.SystemClock
	logger        *slog.Logger
}

var _ validators.ClientSecretValidator = (*ClientAuthenticator)(nil)

// NewClientAuthenticator wraps inner. methodEnabled reports whether a mutual
// TLS method is available in the assembly; a nil source reads the TLS
// connection.
func NewClientAuthenticator(
	inner validators.ClientSecretValidator,
	clients storage.ClientStore,
	source CertificateSource,
	options Options,
	methodEnabled func(string) bool,
	clock services.SystemClock,
	logger *slog.Logger,
) *ClientAuthenticator {
	if source == nil {
		source = ConnectionCertificateSource{}
	}
	return &ClientAuthenticator{
		inner:         inner,
		clients:       clients,
		source:        source,
		options:       options,
		methodEnabled: methodEnabled,
		clock:         clock,
		logger:        logger,
	}
}

// Validate authenticates the client of the request. Every failure has the
// same shape: invalid_client without a description.
func (a *ClientAuthenticator) Validate(request *http.Request) *validators_models.ClientSecretValidationResult {
	form := formValues(request)
	clientId := form.Get("client_id")
	if clientId == "" {
		return a.delegate(request)
	}
	client, err := extensions.FindEnabledClientById(request.Context(), a.clients, clientId)
	if err != nil || client == nil || !IsCertificateMethod(client.TokenEndpointAuthMethod) {
		return a.delegate(request)
	}

	if form.Get("client_secret") != "" || form.Get("client_assertion") != "" ||
		form.Get("client_assertion_type") != "" || hasBasicAuthorization(request) {
		a.info("client registered for mutual TLS presented another credential", client.ClientId)
		return failed()
	}
	method := client.TokenEndpointAuthMethod
	if a.methodEnabled == nil || !a.methodEnabled(method) {
		a.info("client registered for a mutual TLS method that is not enabled", client.ClientId)
		return failed()
	}
	certificates := a.source.ClientCertificates(request)
	if len(certificates) == 0 || certificates[0] == nil {
		a.info("client registered for mutual TLS presented no certificate", client.ClientId)
		return failed()
	}
	leaf := certificates[0]

	switch method {
	case wicket.EndpointAuthenticationMethodsTlsClientAuth:
		if !chainTrusted(certificates, a.options.TrustedAuthorities, a.clock.Now()) {
			a.info("client certificate chain rejected", client.ClientId)
			return failed()
		}
		if !subjectMatches(client, leaf) {
			a.info("client certificate subject does not match the registration", client.ClientId)
			return failed()
		}
	default:
		if !registeredCertificateMatches(client.Jwks, leaf) {
			a.info("client certificate rejected", client.ClientId)
			return failed()
		}
	}

	result := validators_models.NewClientSecretValidationResult()
	result.Client = client
	result.Secret = &models.ParsedSecret{Id: clientId, Type: wicket.ParsedSecretTypesX509Certificate}
	return result
}

// delegate runs the wrapped validator and refuses its success for a client
// registered for a mutual TLS method.
func (a *ClientAuthenticator) delegate(request *http.Request) *validators_models.ClientSecretValidationResult {
	result := a.inner.Validate(request)
	if result != nil && result.Error == nil && result.Client != nil && IsCertificateMethod(result.Client.TokenEndpointAuthMethod) {
		a.info("client registered for mutual TLS authenticated in another way", result.Client.ClientId)
		return failed()
	}
	return result
}

func (a *ClientAuthenticator) info(message string, clientId string) {
	if a.logger != nil {
		a.logger.Info(message, slog.String("client_id", clientId))
	}
}

func failed() *validators_models.ClientSecretValidationResult {
	result := validators_models.NewClientSecretValidationResult()
	result.Error = wicket.TokenErrorsInvalidClient
	return result
}

// formValues returns the body parameters of a form encoded request, or nil
// for any other request.
func formValues(request *http.Request) url.Values {
	if request == nil {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil
	}
	if request.PostForm == nil {
		if err := request.ParseForm(); err != nil {
			return nil
		}
	}
	return request.PostForm
}

func hasBasicAuthorization(request *http.Request) bool {
	header := request.Header.Get("Authorization")
	return len(header) >= 6 && strings.EqualFold(header[:6], "Basic ")
}
