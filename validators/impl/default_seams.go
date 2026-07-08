// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"errors"
	"log/slog"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
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

// BackchannelAuthenticationRequestIdValidator validates CIBA auth_req_id state.
// input: context/store -> behavior: enforce client binding, expiry, status, and poll interval -> output: token validation result.
type BackchannelAuthenticationRequestIdValidator struct {
	store     storage.BackchannelAuthenticationRequestStore
	throttler services.BackchannelAuthenticationThrottlingService
	clock     services.SystemClock
}

func NewBackchannelAuthenticationRequestIdValidator(store storage.BackchannelAuthenticationRequestStore, throttler services.BackchannelAuthenticationThrottlingService, clock services.SystemClock) *BackchannelAuthenticationRequestIdValidator {
	return &BackchannelAuthenticationRequestIdValidator{store: store, throttler: throttler, clock: clock}
}

func (v *BackchannelAuthenticationRequestIdValidator) Validate(ctx *validators_models.BackchannelAuthenticationRequestIdValidationContext) error {
	if ctx == nil || ctx.Request == nil {
		return errors.New("validation context is required")
	}
	if ctx.RequestId == "" {
		ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(ctx.Request, gois.TokenErrorsInvalidRequest, "")
		return nil
	}
	request, err := v.store.FindBackchannelAuthenticationRequest(ctx.RequestId)
	if err != nil {
		return err
	}
	if request == nil || request.ClientId != ctx.Request.Client.ClientId {
		ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(ctx.Request, gois.TokenErrorsInvalidGrant, "")
		return nil
	}
	if !request.ExpirationTime.IsZero() && request.ExpirationTime.Before(v.clock.Now()) {
		ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(ctx.Request, gois.TokenErrorsExpiredToken, "")
		return nil
	}
	switch request.Status {
	case storage_models.BackchannelAuthenticationRequestStatusApproved:
		ctx.Request.BackchannelAuthenticationRequest = request
		ctx.Request.Subject = request.Subject
		ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationSuccess(ctx.Request)
	case storage_models.BackchannelAuthenticationRequestStatusDenied:
		ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(ctx.Request, gois.TokenErrorsAccessDenied, "")
	case storage_models.BackchannelAuthenticationRequestStatusConsumed:
		ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(ctx.Request, gois.TokenErrorsInvalidGrant, "")
	default:
		slowDown, err := v.throttler.ShouldSlowDown(ctx.RequestId, request)
		if err != nil {
			return err
		}
		if err := v.store.UpdateBackchannelAuthenticationRequest(ctx.RequestId, request); err != nil {
			return err
		}
		if slowDown {
			ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(ctx.Request, gois.TokenErrorsSlowDown, "")
		} else {
			ctx.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(ctx.Request, gois.TokenErrorsAuthorizationPending, "")
		}
	}
	return nil
}

type BackchannelAuthenticationUserValidator struct{}

func NewBackchannelAuthenticationUserValidator() BackchannelAuthenticationUserValidator {
	return BackchannelAuthenticationUserValidator{}
}

func (BackchannelAuthenticationUserValidator) Validate(ctx *validators_models.BackchannelAuthenticationUserValidationContext) error {
	if ctx == nil || (ctx.LoginHint == "" && ctx.IdTokenHint == "" && ctx.LoginHintToken == "") {
		return gois.TokenErrorsInvalidRequest
	}
	subjectID := ctx.LoginHint
	if subjectID == "" {
		subjectID = ctx.LoginHintToken
	}
	if subjectID == "" {
		subjectID = ctx.IdTokenHint
	}
	ctx.Subject = claims.NewClaimsPrincipal(
		claims.WithClaimsPrincipalIdentity(
			claims.NewClaimsIdentity(
				claims.WithAuthenticationType(gois.WicketAuthenticationType),
				claims.WithClaims([]*claims.Claim{
					claims.NewClaim(claims.WithClaimType(gois.JwtClaimTypesSubject), claims.WithClaimValue(subjectID)),
				}),
			),
		),
	)
	return nil
}
