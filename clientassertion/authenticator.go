// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// presentedAssertion is what a request says about assertion based
// authentication.
type presentedAssertion struct {
	form      url.Values
	kind      string
	assertion string
}

func readPresentedAssertion(request *http.Request) presentedAssertion {
	form := assertionForm(request)
	return presentedAssertion{
		form:      form,
		kind:      form.Get("client_assertion_type"),
		assertion: form.Get("client_assertion"),
	}
}

func (p presentedAssertion) present() bool {
	return p.kind != "" || p.assertion != ""
}

// identify runs the checks shared by clients and API resources on a request
// that carries assertion parameters, and returns the parsed assertion.
func identify(request *http.Request, presented presentedAssertion, parser validators.SecretsListParser) (*models.ParsedSecret, bool) {
	// An assertion next to any other client credential is a use of more than
	// one authentication mechanism.
	if presented.form.Get("client_secret") != "" || hasBasicAuthorization(request) {
		return nil, false
	}
	if presented.kind != assertionType || presented.assertion == "" {
		return nil, false
	}
	parsed, err := parser.Parse(request)
	if err != nil || parsed == nil || parsed.Type != wicket.ParsedSecretTypesJwtBearer || parsed.Id == "" || parsed.Credential == "" {
		return nil, false
	}
	if clientId := presented.form.Get("client_id"); clientId != "" && clientId != parsed.Id {
		return nil, false
	}
	return parsed, true
}

// ClientAuthenticator authenticates clients. A request without assertion
// parameters goes to the wrapped validator; a request with them is decided
// here. A client registered for private_key_jwt can authenticate in no other
// way, and no other client can authenticate with an assertion.
type ClientAuthenticator struct {
	inner    validators.ClientSecretValidator
	parser   validators.SecretsListParser
	clients  storage.ClientStore
	verifier *Verifier
	issuer   services.IssuerNameService
	logger   *slog.Logger
}

var _ validators.ClientSecretValidator = (*ClientAuthenticator)(nil)

// NewClientAuthenticator wraps inner, the validator for every other client
// authentication method.
func NewClientAuthenticator(
	inner validators.ClientSecretValidator,
	parser validators.SecretsListParser,
	clients storage.ClientStore,
	verifier *Verifier,
	issuer services.IssuerNameService,
	logger *slog.Logger,
) *ClientAuthenticator {
	return &ClientAuthenticator{inner: inner, parser: parser, clients: clients, verifier: verifier, issuer: issuer, logger: logger}
}

// Validate authenticates the client of the request. Every validation failure
// has the same shape: invalid_client without a description.
func (a *ClientAuthenticator) Validate(request *http.Request) *validators_models.ClientSecretValidationResult {
	presented := readPresentedAssertion(request)
	if !presented.present() {
		result := a.inner.Validate(request)
		if result != nil && result.Error == nil && result.Client != nil &&
			result.Client.TokenEndpointAuthMethod == authenticationMethod {
			a.info("client registered for private_key_jwt presented no assertion", result.Client.ClientId)
			return failedClient(wicket.TokenErrorsInvalidClient)
		}
		return result
	}

	parsed, ok := identify(request, presented, a.parser)
	if !ok {
		return failedClient(wicket.TokenErrorsInvalidClient)
	}
	client, err := extensions.FindEnabledClientById(request.Context(), a.clients, parsed.Id)
	if err != nil || client == nil {
		return failedClient(wicket.TokenErrorsInvalidClient)
	}
	if client.TokenEndpointAuthMethod != authenticationMethod {
		a.info("client not registered for private_key_jwt presented an assertion", client.ClientId)
		return failedClient(wicket.TokenErrorsInvalidClient)
	}

	principal := Principal{
		ID:                client.ClientId,
		Jwks:              client.Jwks,
		JwksUri:           client.JwksUri,
		SigningAlgorithms: client.TokenEndpointAuthSigningAlgorithms,
	}
	if err := a.verifier.Verify(request.Context(), principal, a.issuer.GetCurrent(), parsed.Credential); err != nil {
		if errors.Is(err, ErrAuthenticationUnavailable) {
			return failedClient(ErrAuthenticationUnavailable)
		}
		return failedClient(wicket.TokenErrorsInvalidClient)
	}

	result := validators_models.NewClientSecretValidationResult()
	result.Client = client
	// The assertion itself does not travel on with the result.
	result.Secret = &models.ParsedSecret{Id: parsed.Id, Type: parsed.Type, Properties: parsed.Properties}
	return result
}

func (a *ClientAuthenticator) info(message string, clientId string) {
	if a.logger != nil {
		a.logger.Info(message, slog.String("client_id", clientId))
	}
}

func failedClient(err error) *validators_models.ClientSecretValidationResult {
	result := validators_models.NewClientSecretValidationResult()
	result.Error = err
	return result
}

// ApiAuthenticator authenticates API resources, the callers of the
// introspection endpoint. An API resource registers its public keys as
// secrets of the JSON Web Key type and names itself in iss and sub. Unlike a
// client it may hold shared secrets as well and present either.
type ApiAuthenticator struct {
	inner     validators.ApiSecretValidator
	parser    validators.SecretsListParser
	resources storage.ResourceStore
	verifier  *Verifier
	issuer    services.IssuerNameService
	clock     services.SystemClock
	logger    *slog.Logger
}

var _ validators.ApiSecretValidator = (*ApiAuthenticator)(nil)

// NewApiAuthenticator wraps inner, the validator for shared API secrets.
func NewApiAuthenticator(
	inner validators.ApiSecretValidator,
	parser validators.SecretsListParser,
	resources storage.ResourceStore,
	verifier *Verifier,
	issuer services.IssuerNameService,
	clock services.SystemClock,
	logger *slog.Logger,
) *ApiAuthenticator {
	return &ApiAuthenticator{inner: inner, parser: parser, resources: resources, verifier: verifier, issuer: issuer, clock: clock, logger: logger}
}

// Validate authenticates the API resource of the request.
func (a *ApiAuthenticator) Validate(request *http.Request) *validators_models.ApiSecretValidationResult {
	presented := readPresentedAssertion(request)
	if !presented.present() {
		return a.inner.Validate(request)
	}

	parsed, ok := identify(request, presented, a.parser)
	if !ok {
		return failedApi(wicket.TokenErrorsInvalidClient)
	}
	apis, err := a.resources.FindApiResourcesByName(request.Context(), []string{parsed.Id})
	if err != nil || len(apis) != 1 || apis[0] == nil || !apis[0].Enabled {
		return failedApi(wicket.TokenErrorsInvalidClient)
	}
	api := apis[0]
	keySet, registered := a.registeredKeySet(api)
	if !registered {
		return failedApi(wicket.TokenErrorsInvalidClient)
	}

	principal := Principal{ID: api.Name, Jwks: keySet}
	if err := a.verifier.Verify(request.Context(), principal, a.issuer.GetCurrent(), parsed.Credential); err != nil {
		if errors.Is(err, ErrAuthenticationUnavailable) {
			return failedApi(ErrAuthenticationUnavailable)
		}
		return failedApi(wicket.TokenErrorsInvalidClient)
	}

	result := validators_models.NewApiSecretValidationResult()
	result.Resource = api
	return result
}

// registeredKeySet gathers the unexpired JSON Web Key secrets of an API
// resource into one JWK Set document. Each secret value is a single JWK or a
// JWK Set. It reports false when the resource registered no such secret.
func (a *ApiAuthenticator) registeredKeySet(api *storage_models.ApiResource) (string, bool) {
	now := a.clock.Now()
	members := []json.RawMessage{}
	registered := false
	for _, secret := range api.ApiSecrets {
		if secret == nil || secret.Type != wicket.SecretTypesJsonWebKey {
			continue
		}
		if !secret.Expiration.IsZero() && !now.Before(secret.Expiration) {
			continue
		}
		registered = true
		var set struct {
			Keys *[]json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal([]byte(secret.Value), &set); err != nil {
			continue
		}
		if set.Keys != nil {
			members = append(members, *set.Keys...)
		} else {
			members = append(members, json.RawMessage(secret.Value))
		}
	}
	if !registered {
		return "", false
	}
	document, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: members})
	if err != nil {
		return "", false
	}
	return string(document), true
}

func failedApi(err error) *validators_models.ApiSecretValidationResult {
	result := validators_models.NewApiSecretValidationResult()
	result.Error = err
	return result
}
