// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ScopeParser parses raw scope values without side effects.
// input: raw scope values -> behavior: preserve each raw value as parsed name -> output: parsed scope result.
type ScopeParser struct{}

func NewScopeParser() ScopeParser {
	return ScopeParser{}
}

func (ScopeParser) ParseScopeValues(scopes []string) *validators_models.ParsedScopesResult {
	result := &validators_models.ParsedScopesResult{
		ParsedScopes: make([]*validators_models.ParsedScopeValue, 0, len(scopes)),
	}
	for _, scope := range scopes {
		result.ParsedScopes = append(result.ParsedScopes, &validators_models.ParsedScopeValue{
			RawValue:   scope,
			ParsedName: scope,
		})
	}
	return result
}

// ClientConfigurationValidator accepts current client configuration.
// input: client validation context -> behavior: leave context unchanged -> output: valid context.
type ClientConfigurationValidator struct{}

func NewClientConfigurationValidator() ClientConfigurationValidator {
	return ClientConfigurationValidator{}
}

func (ClientConfigurationValidator) Validate(*validators_contexts.ClientConfigurationValidationContext) {
}

// CustomTokenRequestValidator leaves token request validation unchanged.
// input: custom token request context -> behavior: no mutation -> output: nil error.
type CustomTokenRequestValidator struct{}

func NewCustomTokenRequestValidator() CustomTokenRequestValidator {
	return CustomTokenRequestValidator{}
}

func (CustomTokenRequestValidator) Validate(*validators_contexts.CustomTokenRequestValidationContext) error {
	return nil
}

// CustomAuthorizeRequestValidator leaves authorize request validation unchanged.
// input: custom authorize context -> behavior: no mutation -> output: nil error.
type CustomAuthorizeRequestValidator struct{}

func NewCustomAuthorizeRequestValidator() CustomAuthorizeRequestValidator {
	return CustomAuthorizeRequestValidator{}
}

func (CustomAuthorizeRequestValidator) Validate(*validators_contexts.CustomAuthorizeRequestValidationContext) error {
	return nil
}

// CustomTokenValidator leaves token validation unchanged.
// input: token validation result -> behavior: no mutation -> output: same result.
type CustomTokenValidator struct{}

func NewCustomTokenValidator() CustomTokenValidator {
	return CustomTokenValidator{}
}

func (CustomTokenValidator) ValidateAccessToken(result *validators_models.TokenValidationResult) *validators_models.TokenValidationResult {
	return result
}

func (CustomTokenValidator) ValidateIdentityToken(result *validators_models.TokenValidationResult) *validators_models.TokenValidationResult {
	return result
}

// ResourceValidator resolves requested resources for already parsed scopes.
// input: resource validation request -> behavior: parse scopes and query resource store -> output: resource validation result.
type ResourceValidator struct {
	store  storage.ResourceStore
	parser validators.ScopeParser
}

func NewResourceValidator(store storage.ResourceStore, parser validators.ScopeParser, logger *slog.Logger) *ResourceValidator {
	return &ResourceValidator{store: store, parser: parser}
}

func (v *ResourceValidator) ValidateRequestedResources(request *validators_models.ResourceValidationRequest) (*validators_models.ResourceValidationResult, error) {
	result := validators_models.NewResourceValidationResult()
	if request == nil {
		return result, nil
	}

	if v.parser != nil {
		parsed := v.parser.ParseScopeValues(request.Scopes)
		if parsed != nil {
			result.ParsedScopes = parsed.ParsedScopes
			for _, err := range parsed.Errors {
				result.InvalidScopes = append(result.InvalidScopes, err.RawValue)
			}
		}
	} else {
		for _, scope := range request.Scopes {
			result.ParsedScopes = append(result.ParsedScopes, &validators_models.ParsedScopeValue{
				RawValue:   scope,
				ParsedName: scope,
			})
		}
	}

	if v.store != nil {
		resources, err := v.store.FindResourcesByScope(result.RawScopeValues())
		if err != nil {
			return nil, err
		}
		if resources != nil {
			result.Resources = resources
		}
	}

	return result, nil
}

// CleanRoomGapRequestIdValidator is a neutral placeholder for unsupported request-id validation.
// input: none -> behavior: carry no validation state -> output: constructible service.
type CleanRoomGapRequestIdValidator struct{}

func NewCleanRoomGapRequestIdValidator() CleanRoomGapRequestIdValidator {
	return CleanRoomGapRequestIdValidator{}
}
