// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"

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
type ClientConfigurationValidator struct {
	// features reports the features the assembly declared enabled; nil
	// means none is enabled.
	features validators.ClientFeatureDeclarations
}

func NewClientConfigurationValidator(features validators.ClientFeatureDeclarations) ClientConfigurationValidator {
	return ClientConfigurationValidator{features: features}
}

func (v ClientConfigurationValidator) Validate(context *validators_contexts.ClientConfigurationValidationContext) {
	if context == nil || context.Client == nil {
		return
	}
	switch context.Client.TokenEndpointAuthMethod {
	case "":
	case wicket.EndpointAuthenticationMethodsPrivateKeyJwt:
		if v.features == nil || !v.features.PrivateKeyJwtEnabled() {
			context.SetError("client requires private_key_jwt client authentication but the feature is not enabled")
		}
	case wicket.EndpointAuthenticationMethodsTlsClientAuth, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth:
		if message := validateClientCertificateMethod(v.features, context.Client); message != "" {
			context.SetError(message)
		}
	default:
		context.SetError("client declares an unsupported token endpoint authentication method")
	}
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

func (v *BackchannelAuthenticationRequestIdValidator) Validate(ctx context.Context, validation *validators_models.BackchannelAuthenticationRequestIdValidationContext) error {
	if validation == nil || validation.Request == nil {
		return errors.New("validation context is required")
	}
	if validation.RequestId == "" {
		validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsInvalidRequest, "")
		return nil
	}
	request, err := v.store.FindBackchannelAuthenticationRequest(ctx, validation.RequestId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsInvalidGrant, "")
			return nil
		}
		return err
	}
	if request == nil || request.ClientId != validation.Request.Client.ClientId {
		validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsInvalidGrant, "")
		return nil
	}
	if !request.ExpirationTime.IsZero() && request.ExpirationTime.Before(v.clock.Now()) {
		validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsExpiredToken, "")
		return nil
	}
	switch request.Status {
	case storage_models.BackchannelAuthenticationRequestStatusApproved:
		validation.Request.BackchannelAuthenticationRequest = request
		validation.Request.Subject = request.Subject
		validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationSuccess(validation.Request)
	case storage_models.BackchannelAuthenticationRequestStatusDenied:
		validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsAccessDenied, "")
	case storage_models.BackchannelAuthenticationRequestStatusConsumed:
		validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsInvalidGrant, "")
	default:
		slowDown, err := v.throttler.ShouldSlowDown(validation.RequestId, request)
		if err != nil {
			return err
		}
		if err := v.store.UpdateBackchannelAuthenticationRequest(ctx, validation.RequestId, request); err != nil {
			return err
		}
		if slowDown {
			validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsSlowDown, "")
		} else {
			validation.Result = validators_models.NewBackchannelAuthenticationRequestIdValidationError(validation.Request, wicket.TokenErrorsAuthorizationPending, "")
		}
	}
	return nil
}

type BackchannelAuthenticationUserValidator struct{}

func NewBackchannelAuthenticationUserValidator() BackchannelAuthenticationUserValidator {
	return BackchannelAuthenticationUserValidator{}
}

func (BackchannelAuthenticationUserValidator) Validate(ctx context.Context, validation *validators_models.BackchannelAuthenticationUserValidationContext) error {
	if validation == nil || (validation.LoginHint == "" && validation.IdTokenHint == "" && validation.LoginHintToken == "") {
		return wicket.TokenErrorsInvalidRequest
	}
	subjectID := validation.LoginHint
	if subjectID == "" {
		subjectID = validation.LoginHintToken
	}
	if subjectID == "" {
		subjectID = validation.IdTokenHint
	}
	validation.Subject = claims.NewClaimsPrincipal(
		claims.WithClaimsPrincipalIdentity(
			claims.NewClaimsIdentity(
				claims.WithAuthenticationType(wicket.WicketAuthenticationType),
				claims.WithClaims([]*claims.Claim{
					claims.NewClaim(claims.WithClaimType(wicket.JwtClaimTypesSubject), claims.WithClaimValue(subjectID)),
				}),
			),
		),
	)
	return nil
}
