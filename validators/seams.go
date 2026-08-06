// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package validators

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ClientConfigurationValidator validates a loaded client.
// input: client validation context -> behavior: mark invalid when needed -> output: mutated context.
type ClientConfigurationValidator interface {
	Validate(*validators_contexts.ClientConfigurationValidationContext)
}

// ResourceValidator validates requested scopes and resource gaps.
// input: resource validation request -> behavior: resolve allowed resources -> output: validation result or error.
type ResourceValidator interface {
	ValidateRequestedResources(ctx context.Context, request *validators_models.ResourceValidationRequest) (*validators_models.ResourceValidationResult, error)
}

// ResourceOwnerPasswordValidator validates resource-owner credentials.
// input: password validation context -> behavior: mutate result -> output: error.
type ResourceOwnerPasswordValidator interface {
	Validate(*validators_contexts.ResourceOwnerPasswordValidationContext) error
}

// CustomAuthorizeRequestValidator applies caller custom authorize validation.
// input: authorize validation context -> behavior: mutate result -> output: error.
type CustomAuthorizeRequestValidator interface {
	Validate(*validators_contexts.CustomAuthorizeRequestValidationContext) error
}

// CustomTokenRequestValidator applies caller custom token request validation.
// input: token request validation context -> behavior: mutate result -> output: error.
type CustomTokenRequestValidator interface {
	Validate(*validators_contexts.CustomTokenRequestValidationContext) error
}

// CustomTokenValidator applies caller custom token validation.
// input: token validation result -> behavior: mutate or replace result -> output: validation result.
type CustomTokenValidator interface {
	ValidateAccessToken(*validators_models.TokenValidationResult) *validators_models.TokenValidationResult
	ValidateIdentityToken(*validators_models.TokenValidationResult) *validators_models.TokenValidationResult
}

// BackchannelAuthenticationRequestIdValidator validates CIBA auth_req_id state for token polling.
// input: validation context -> behavior: mutate result/store state -> output: error.
type BackchannelAuthenticationRequestIdValidator interface {
	Validate(ctx context.Context, validation *validators_models.BackchannelAuthenticationRequestIdValidationContext) error
}

// BackchannelAuthenticationUserValidator resolves a CIBA user hint into a subject.
// input: validation context -> behavior: set subject or error -> output: error.
type BackchannelAuthenticationUserValidator interface {
	Validate(ctx context.Context, validation *validators_models.BackchannelAuthenticationUserValidationContext) error
}

// BackchannelAuthenticationRequestValidator validates a CIBA backchannel authentication request.
// input: raw form values/client -> behavior: save request state -> output: validation result.
type BackchannelAuthenticationRequestValidator interface {
	Validate(ctx context.Context, parameters url.Values, client *storage_models.Client) *validators_models.BackchannelAuthenticationRequestValidationResult
}

// SecretsListParser selects a parsed secret from an HTTP request.
// input: HTTP request -> behavior: parse supported secret forms -> output: parsed secret or error.
type SecretsListParser interface {
	Parse(*http.Request) (*models.ParsedSecret, error)
	GetAvailableAuthenticationMethods() []string
}

// SecretsListValidator validates a parsed secret against stored secrets.
// input: stored secrets and parsed secret -> behavior: validate -> output: result or error.
type SecretsListValidator interface {
	Validate([]*storage_models.Secret, *models.ParsedSecret) (*validators_models.SecretValidationResult, error)
}

// RedirectUriValidator validates redirect and post-logout redirect URIs.
// input: URI/client -> behavior: compare against client settings -> output: allowed flag.
type RedirectUriValidator interface {
	IsRedirectUriValid(string, *storage_models.Client) bool
	IsPostLogoutRedirectUriValid(string, *storage_models.Client) bool
}

// ScopeParser parses scope strings.
// input: requested scopes -> behavior: parse into scope values -> output: parsed scope result.
type ScopeParser interface {
	ParseScopeValues([]string) *validators_models.ParsedScopesResult
}
