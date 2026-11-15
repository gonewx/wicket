// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	models_contexts "github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	storage "github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	"github.com/gonewx/wicket/validators/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type TokenRequestValidator struct {
	Options                                     *config_options.WicketOptions
	IssuerNameService                           services.IssuerNameService
	ResourceStore                               storage.ResourceStore
	AuthorizationCodeStore                      storage.AuthorizationCodeStore
	RefreshTokenStore                           storage.RefreshTokenStore
	ExtensionGrantValidator                     *ExtensionGrantValidator
	CustomRequestValidator                      validators.CustomTokenRequestValidator
	ResourceValidator                           validators.ResourceValidator
	RefreshTokenService                         services.RefreshTokenService
	ResourceOwnerValidator                      validators.ResourceOwnerPasswordValidator
	Profile                                     services.ProfileService
	DeviceCodeValidator                         validators.DeviceCodeValidator
	BackchannelAuthenticationRequestIdValidator validators.BackchannelAuthenticationRequestIdValidator
	Clock                                       services.SystemClock
	Logger                                      *slog.Logger

	validatedRequest *models.ValidatedTokenRequest
}

func NewTokenRequestValidator(
	options *config_options.WicketOptions,
	issuerNameService services.IssuerNameService,
	authorizationCodeStore storage.AuthorizationCodeStore,
	extensionGrantValidator *ExtensionGrantValidator,
	customRequestValidator validators.CustomTokenRequestValidator,
	resourceValidator validators.ResourceValidator,
	resourceStore storage.ResourceStore,
	refreshTokenService services.RefreshTokenService,
	resourceOwnerValidator validators.ResourceOwnerPasswordValidator,
	profile services.ProfileService,
	deviceCodeValidator validators.DeviceCodeValidator,
	backChannelAuthenticationRequestIdValidator validators.BackchannelAuthenticationRequestIdValidator,
	clock services.SystemClock,
	logger *slog.Logger,
) *TokenRequestValidator {
	return &TokenRequestValidator{
		Options:                 options,
		IssuerNameService:       issuerNameService,
		AuthorizationCodeStore:  authorizationCodeStore,
		ExtensionGrantValidator: extensionGrantValidator,
		CustomRequestValidator:  customRequestValidator,
		ResourceValidator:       resourceValidator,
		ResourceStore:           resourceStore,
		RefreshTokenService:     refreshTokenService,
		ResourceOwnerValidator:  resourceOwnerValidator,
		Profile:                 profile,
		DeviceCodeValidator:     deviceCodeValidator,
		BackchannelAuthenticationRequestIdValidator: backChannelAuthenticationRequestIdValidator,
		Clock:  clock,
		Logger: logger,
	}
}

// Validates the request. A non-nil error reports an infrastructure failure so
// the caller can distinguish it from a protocol-level invalid result.
func (s *TokenRequestValidator) ValidateRequest(ctx context.Context, parameters url.Values, clientValidationResult *models.ClientSecretValidationResult) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start token request validation")

	s.validatedRequest = validators_models.NewValidatedTokenRequest()
	s.validatedRequest.IssuerName = s.IssuerNameService.GetCurrent()
	s.validatedRequest.Raw = parameters
	s.validatedRequest.Options = s.Options

	if clientValidationResult == nil {
		s.Logger.Error("Client validation result is nil")
		return s.invalid(errors.New("argument nil"), "ClientSecretValidationResult"), nil
	}

	s.validatedRequest.SetClient(clientValidationResult.Client, clientValidationResult.Secret, clientValidationResult.Confirmation)

	// check client protocol type
	if s.validatedRequest.Client.ProtocolType != wicket.ProtocolTypesOpenIdConnect {
		s.Logger.Error("Invalid protocol type for client")
		return s.invalid(wicket.TokenErrorsInvalidClient, ""), nil
	}

	// check grant type
	grantType := parameters.Get(wicket.TokenRequestGrantType)
	if grantType == "" {
		s.Logger.Error("Grant type is missing")
		return s.invalid(wicket.TokenErrorsUnsupportedGrantType, ""), nil
	}

	if len(grantType) > s.Options.InputLengthRestrictions.GrantType {
		s.Logger.Error("Grant type is too long")
		return s.invalid(wicket.TokenErrorsUnsupportedGrantType, ""), nil
	}

	s.validatedRequest.GrantType = grantType

	// check for resource gap and basic formatting
	resourceIndicators := parameters[wicket.TokenRequestResource]

	if utils.AnyPred(resourceIndicators, func(x string) bool {
		return len(x) > s.Options.InputLengthRestrictions.ResourceGapMaxLength
	}) {
		return s.invalid(wicket.TokenErrorsInvalidTarget, "Resource indicator maximum length exceeded"), nil
	}

	if !utils.AreValidResourceGapFormat(resourceIndicators) {
		return s.invalid(wicket.TokenErrorsInvalidTarget, "Invalid resource gap format"), nil
	}

	if len(resourceIndicators) > 1 {
		return s.invalid(wicket.TokenErrorsInvalidTarget, "Multiple resource gaps not supported on token endpoint."), nil
	}

	s.validatedRequest.RequestedResourceGap = utils.SingleOrDefault(resourceIndicators)

	// run specific logic for grants
	switch grantType {
	case wicket.GrantTypeAuthorizationCode:
		return s.runValidation(ctx, s.validateAuthorizationCodeRequest, parameters)
	case wicket.GrantTypeClientCredentials:
		return s.runValidation(ctx, s.validateClientCredentialsRequest, parameters)
	case wicket.GrantTypePassword:
		return s.runValidation(ctx, s.validateResourceOwnerCredentialRequest, parameters)
	case wicket.GrantTypeRefreshToken:
		return s.runValidation(ctx, s.validateRefreshTokenRequest, parameters)
	case wicket.GrantTypeDeviceCode:
		return s.runValidation(ctx, s.validateDeviceCodeRequest, parameters)
	case wicket.GrantTypeBackchannelAuthentication:
		return s.runValidation(ctx, s.validateBackchannelAuthenticationRequest, parameters)
	default:
		return s.runValidation(ctx, s.validateExtensionGrantRequest, parameters)
	}

}

func (s *TokenRequestValidator) runValidation(ctx context.Context, validationFunc func(context.Context, url.Values) (*models.TokenRequestValidationResult, error), parameters url.Values) (*models.TokenRequestValidationResult, error) {
	// run standard validation
	result, err := validationFunc(ctx, parameters)
	if err != nil {
		return result, err
	}
	if result.Error != nil {
		return result, nil
	}

	// run custom validation
	s.Logger.Debug("Calling into custom request validator", slog.String("type", fmt.Sprintf("%T", s.CustomRequestValidator)))

	customValidationContext := &validators_contexts.CustomTokenRequestValidationContext{Result: result}
	err = s.CustomRequestValidator.Validate(customValidationContext)
	if err != nil || customValidationContext.Result.Error != nil {
		if customValidationContext.Result.Error != nil {
			s.Logger.Error("Custom token request validator", slog.String("error", customValidationContext.Result.Error.Error()))
		} else {
			s.Logger.Error("Custom token request validator error")
		}

		return customValidationContext.Result, nil
	}

	return customValidationContext.Result, nil
}

func (s *TokenRequestValidator) validateAuthorizationCodeRequest(ctx context.Context, parameters url.Values) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start validation of authorization code token request")

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), wicket.GrantTypeAuthorizationCode) &&
		!utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), wicket.GrantTypeHybrid) {
		s.Logger.Error("Client not authorized for code flow")
		return s.invalid(wicket.TokenErrorsUnauthorizedClient, ""), nil
	}

	// validate authorization code
	code := parameters.Get(wicket.TokenRequestCode)
	if code == "" {
		s.Logger.Error("Authorization code is missing")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	if len(code) > s.Options.InputLengthRestrictions.AuthorizationCode {
		s.Logger.Error("Authorization code is too long")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	s.validatedRequest.AuthorizationCodeHandle = code

	authZcode, err := s.AuthorizationCodeStore.TakeAuthorizationCode(ctx, code)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.Logger.Error("Invalid authorization code", slog.String("code", code))
			return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
		}
		s.Logger.Error("Error loading authorization code", slog.String("code", code), slog.String("err", err.Error()))
		return nil, err
	}

	// validate client binding
	if authZcode.ClientId != s.validatedRequest.Client.ClientId {
		s.Logger.Error("Client is trying to use a code from a different client")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}
	if !authorizationCodeProofBindingHolds(ctx, authZcode) {
		s.Logger.Error("Authorization code is bound to a DPoP key the request did not prove")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	if authZcode.CreationTime.Add(time.Duration(authZcode.Lifetime) * time.Second).Before(s.Clock.Now()) {
		s.Logger.Error("Authorization code expired", slog.String("code", code))
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	// populate session id
	if authZcode.SessionId != "" {
		s.validatedRequest.SessionId = authZcode.SessionId
	}

	// validate code expiration
	if authZcode.CreationTime.Add(time.Duration(s.validatedRequest.Client.AuthorizationCodeLifetime) * time.Second).Before(s.Clock.Now()) {
		s.Logger.Error("Authorization code is expired", slog.String("code", code))
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	s.validatedRequest.AuthorizationCode = authZcode
	s.validatedRequest.Subject = authZcode.Subject

	// validate redirect_uri
	redirectUri := parameters.Get(wicket.TokenRequestRedirectUri)
	if redirectUri == "" {
		s.Logger.Error("Redirect URI is missing")
		return s.invalid(wicket.TokenErrorsUnauthorizedClient, ""), nil
	}

	if redirectUri != s.validatedRequest.AuthorizationCode.RedirectUri {
		s.Logger.Error("Invalid redirect_uri")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	// validate scopes are present
	if len(s.validatedRequest.AuthorizationCode.RequestedScopes) == 0 {
		s.Logger.Error("Authorization code has no associated scopes")
		return s.invalid(wicket.TokenErrorsInvalidRequest, ""), nil
	}

	// resource gap
	if s.validatedRequest.RequestedResourceGap != "" &&
		!utils.Contains(s.validatedRequest.AuthorizationCode.RequestedResourceGaps, s.validatedRequest.RequestedResourceGap) {
		return s.invalid(wicket.TokenErrorsInvalidTarget, "Resource indicator does not match any resource gap in the original authorize request."), nil
	}

	// resource and scope validation
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
		ctx,
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       s.validatedRequest.AuthorizationCode.RequestedScopes,
			ResourceGaps: s.validatedRequest.AuthorizationCode.RequestedResourceGaps,
			// if we are issuing a refresh token, then we need to allow the non-isolated resource
			IncludeNonIsolatedApiResources: utils.Contains(s.validatedRequest.AuthorizationCode.RequestedScopes, wicket.StandardScopesOfflineAccess),
		},
	)

	if err != nil {
		return s.invalid(err, ""), nil
	}

	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(wicket.TokenErrorsInvalidTarget, "Invalid resource gap."), nil
		}
		if len(validatedResources.InvalidScopes) > 0 {
			return s.invalid(wicket.TokenErrorsInvalidScope, "Invalid scope."), nil
		}
	}

	s.validatedRequest.ValidatedResources = validatedResources.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)

	// validate PKCE parameters
	codeVerifier := parameters.Get(wicket.TokenRequestCodeVerifier)
	if s.validatedRequest.Client.RequirePkce || s.validatedRequest.AuthorizationCode.CodeChallenge != "" {
		s.Logger.Debug("Client required a proof key for code exchange. Starting PKCE validation")

		proofKeyResult := s.validateAuthorizationCodeWithProofKeyParameters(codeVerifier, s.validatedRequest.AuthorizationCode)
		if proofKeyResult.Error != nil {
			return proofKeyResult, nil
		}

		s.validatedRequest.CodeVerifier = codeVerifier
	} else {
		if codeVerifier != "" {
			s.Logger.Error("Unexpected code_verifier: This happens when the client is trying to use PKCE, but it is not enabled. Set RequirePkce to true.", slog.String("codeVerifier", codeVerifier))
			return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
		}
	}

	// make sure user is enabled
	isActiveCtx := models_contexts.NewIsActiveContext(s.validatedRequest.AuthorizationCode.Subject, s.validatedRequest.Client, wicket.ProfileIsActiveCallersAccessTokenValidation)

	s.Profile.IsActive(isActiveCtx)
	if !isActiveCtx.IsActive {
		s.Logger.Error("User has been disabled", slog.String("subjectId", extensions.GetSubjectIdFromPrincipal(s.validatedRequest.AuthorizationCode.Subject)))
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	s.Logger.Debug("Validation of authorization code token request success")

	return s.valid(), nil
}

func (s *TokenRequestValidator) validateClientCredentialsRequest(ctx context.Context, parameters url.Values) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start client credentials token request validation")

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), wicket.GrantTypeClientCredentials) {
		s.Logger.Error("Client not authorized for client credentials flow, check the AllowedGrantTypes setting")
		return s.invalid(wicket.TokenErrorsUnauthorizedClient, ""), nil
	}

	// check if client is allowed to request scopes
	scopeError := s.validateRequestedScopesAndResources(ctx, parameters, true, true)
	if scopeError != nil {
		return s.invalid(scopeError, ""), nil
	}

	if len(s.validatedRequest.ValidatedResources.Resources.IdentityResources()) > 0 {
		s.Logger.Error("Client cannot request OpenID scopes in client credentials flow", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(wicket.TokenErrorsInvalidScope, ""), nil
	}

	if s.validatedRequest.ValidatedResources.Resources.OfflineAccess {
		s.Logger.Error("Client cannot request a refresh token in client credentials flow", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(wicket.TokenErrorsInvalidScope, ""), nil
	}

	s.Logger.Debug("credentials token request validation success", slog.String("clientId", s.validatedRequest.Client.ClientId))

	return s.valid(), nil
}

func (s *TokenRequestValidator) validateResourceOwnerCredentialRequest(ctx context.Context, parameters url.Values) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start resource owner password token request validation")

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), wicket.GrantTypePassword) {
		s.Logger.Error("Client not authorized for resource owner password flow, check the AllowedGrantTypes setting", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(wicket.TokenErrorsUnauthorizedClient, ""), nil
	}

	// check if client is allowed to request scopes
	scopeError := s.validateRequestedScopesAndResources(ctx, parameters, false, false)
	if scopeError != nil {
		return s.invalid(scopeError, ""), nil
	}

	// check resource owner credentials
	userName := parameters.Get(wicket.TokenRequestUserName)
	password := parameters.Get(wicket.TokenRequestPassword)

	if userName == "" {
		s.Logger.Error("Username is missing")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	if len(userName) > s.Options.InputLengthRestrictions.UserName ||
		len(password) > s.Options.InputLengthRestrictions.Password {
		s.Logger.Error("Username or password is too long")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	s.validatedRequest.UserName = userName

	// authenticate user
	resourceOwnerContext := validators_contexts.NewResourceOwnerPasswordValidationContext()
	resourceOwnerContext.UserName = userName
	resourceOwnerContext.Password = password
	resourceOwnerContext.Request = s.validatedRequest

	err := s.ResourceOwnerValidator.Validate(resourceOwnerContext)

	if err != nil {
		s.Logger.Error("User authentication failed", slog.String("error", err.Error()))
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	if resourceOwnerContext.Result.Error != nil {
		// protect against bad validator implementations
		if errors.Is(resourceOwnerContext.Result.Error, wicket.TokenErrorsUnsupportedGrantType) {
			s.Logger.Error("Resource owner password credential grant type not supported")
			return s.invalid(wicket.TokenErrorsUnsupportedGrantType, ""), nil
		}

		desc := "invalid_username_or_password"

		if resourceOwnerContext.Result.Description != "" {
			desc = resourceOwnerContext.Result.Description
		}

		s.Logger.Info("User authentication failed", slog.String("error", resourceOwnerContext.Result.Error.Error()), slog.String("errorDescription", desc))

		return s.invalid(resourceOwnerContext.Result.Error, desc), nil
	}

	if resourceOwnerContext.Result.Subject == nil {
		s.Logger.Error("User authentication failed: No principal returned")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	// make sure user is enabled
	isActiveCtx := models_contexts.NewIsActiveContext(resourceOwnerContext.Result.Subject, s.validatedRequest.Client, wicket.ProfileIsActiveCallersResourceOwnerValidation)
	s.Profile.IsActive(isActiveCtx)

	if !isActiveCtx.IsActive {
		s.Logger.Error("User has been disabled", slog.String("subjectId", extensions.GetSubjectIdFromPrincipal(resourceOwnerContext.Result.Subject)))
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	s.validatedRequest.UserName = userName
	s.validatedRequest.Subject = resourceOwnerContext.Result.Subject

	s.Logger.Debug("Resource owner password token request validation success")

	return s.valid(), nil
}

func (s *TokenRequestValidator) validateRefreshTokenRequest(ctx context.Context, parameters url.Values) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start validation of refresh token validation")

	refreshTokenHandle := parameters.Get(wicket.TokenRequestRefreshToken)
	if refreshTokenHandle == "" {
		s.Logger.Error("Refresh token is missing")
		return s.invalid(wicket.TokenErrorsInvalidRequest, ""), nil
	}

	if len(refreshTokenHandle) > s.Options.InputLengthRestrictions.RefreshToken {
		s.Logger.Error("Refresh token is too long")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	result := s.RefreshTokenService.ValidateRefreshToken(ctx, refreshTokenHandle, s.validatedRequest.Client)

	if result.Error != nil {
		if errors.Is(result.Error, storage.ErrNotFound) {
			s.Logger.Error("Refresh token validation failed. aborting")
			return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
		}
		s.Logger.Error("Refresh token validation failed. infrastructure error")
		return nil, result.Error
	}

	s.validatedRequest.RefreshToken = result.RefreshToken
	if !refreshTokenProofBindingHolds(ctx, s.validatedRequest.RefreshToken) {
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}
	s.validatedRequest.RefreshTokenHandle = refreshTokenHandle
	s.validatedRequest.Subject = result.RefreshToken.Subject
	s.validatedRequest.SessionId = result.RefreshToken.SessionId

	// resource gap
	resourceIndicators := s.validatedRequest.RefreshToken.AuthorizedResourceGaps
	if s.validatedRequest.RefreshToken.AuthorizedResourceGaps != nil {
		// we had an original resource collection, so check current requested resource against it
		if s.validatedRequest.RequestedResourceGap != "" &&
			!utils.Contains(s.validatedRequest.RefreshToken.AuthorizedResourceGaps, s.validatedRequest.RequestedResourceGap) {
			s.Logger.Error("Refresh token validation failed. requested resource gap not authorized")
			return s.invalid(wicket.TokenErrorsInvalidTarget, "Resource indicator does not match any resource gap in the original authorize request."), nil
		}
	} else {
		if strings.TrimSpace(s.validatedRequest.RequestedResourceGap) != "" {
			resourceIndicators = []string{s.validatedRequest.RequestedResourceGap}
		}
	}

	// resource and scope validation
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
		ctx,
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       s.validatedRequest.RefreshToken.AuthorizedScopes,
			ResourceGaps: resourceIndicators,
			// we're issuing refresh token, so we need to allow for non-isolated resource
			IncludeNonIsolatedApiResources: true,
		},
	)

	if err != nil {
		s.Logger.Error("Resource validation failed. aborting", slog.String("error", err.Error()))
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(wicket.TokenErrorsInvalidTarget, "Invalid resource gap."), nil
		}
		if len(validatedResources.InvalidScopes) > 0 {
			return s.invalid(wicket.TokenErrorsInvalidScope, "Invalid scope."), nil
		}
	}

	s.validatedRequest.ValidatedResources = validatedResources.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)

	s.Logger.Debug("Validation of refresh token request success")
	// todo: more logging - similar to TokenValidator before

	return s.valid(), nil
}

func (s *TokenRequestValidator) validateDeviceCodeRequest(ctx context.Context, parameters url.Values) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start validation of device code request")

	// resource gap not supported for device flow
	if s.validatedRequest.RequestedResourceGap != "" {
		s.Logger.Error("Resource indicator not supported for device flow")
		return s.invalid(wicket.TokenErrorsInvalidTarget, ""), nil
	}

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), wicket.GrantTypeDeviceCode) {
		s.Logger.Error("Client not authorized for device flow")
		return s.invalid(wicket.TokenErrorsUnauthorizedClient, ""), nil
	}

	// validate device code parameter
	deviceCode := parameters.Get(wicket.TokenRequestDeviceCode)
	if deviceCode == "" {
		s.Logger.Error("Device code is missing")
		return s.invalid(wicket.TokenErrorsInvalidRequest, ""), nil
	}

	if len(deviceCode) > s.Options.InputLengthRestrictions.DeviceCode {
		s.Logger.Error("Device code is too long")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	// validate device code
	deviceCodeContext := &validators_models.DeviceCodeValidationContext{
		DeviceCode: deviceCode,
		Request:    s.validatedRequest,
	}

	err := s.DeviceCodeValidator.Validate(ctx, deviceCodeContext)
	if err != nil {
		s.Logger.Error("Device code validation failed", slog.String("error", err.Error()))
		return nil, err
	}

	if deviceCodeContext.Result.Error != nil {
		return deviceCodeContext.Result, nil
	}

	// scope validation
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
		ctx,
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       s.validatedRequest.DeviceCode.AuthorizedScopes,
			ResourceGaps: nil, // not supported for device grant
		},
	)

	if err != nil {
		s.Logger.Error("Resource validation failed. aborting", slog.String("error", err.Error()))
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(wicket.TokenErrorsInvalidTarget, "Invalid resource gap."), nil
		}
		if len(validatedResources.InvalidScopes) > 0 {
			return s.invalid(wicket.TokenErrorsInvalidScope, "Invalid scope."), nil
		}
	}

	s.validatedRequest.ValidatedResources = validatedResources.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)

	s.Logger.Debug("Validation of device code token request success")

	return s.valid(), nil
}

func (s *TokenRequestValidator) validateBackchannelAuthenticationRequest(ctx context.Context, parameters url.Values) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start validation of CIBA token request")
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), wicket.GrantTypeBackchannelAuthentication) {
		return s.invalid(wicket.TokenErrorsUnauthorizedClient, ""), nil
	}
	requestID := parameters.Get(wicket.TokenRequestAuthenticationRequestId)
	if requestID == "" {
		return s.invalid(wicket.TokenErrorsInvalidRequest, ""), nil
	}
	if len(requestID) > s.Options.InputLengthRestrictions.AuthenticationRequestId {
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}
	validationCtx := &validators_models.BackchannelAuthenticationRequestIdValidationContext{
		RequestId: requestID,
		Request:   s.validatedRequest,
	}
	if err := s.BackchannelAuthenticationRequestIdValidator.Validate(ctx, validationCtx); err != nil {
		return nil, err
	}
	if validationCtx.Result == nil {
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}
	if validationCtx.Result.Error != nil {
		return validationCtx.Result, nil
	}
	if s.validatedRequest.RequestedResourceGap != "" &&
		!utils.Contains(s.validatedRequest.BackchannelAuthenticationRequest.RequestedResourceGaps, s.validatedRequest.RequestedResourceGap) {
		return s.invalid(wicket.TokenErrorsInvalidTarget, ""), nil
	}
	if s.validatedRequest.RequestedResourceGap == "" && len(s.validatedRequest.BackchannelAuthenticationRequest.RequestedResourceGaps) == 1 {
		s.validatedRequest.RequestedResourceGap = s.validatedRequest.BackchannelAuthenticationRequest.RequestedResourceGaps[0]
	}
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
		ctx,
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       s.validatedRequest.BackchannelAuthenticationRequest.RequestedScopes,
			ResourceGaps: s.validatedRequest.BackchannelAuthenticationRequest.RequestedResourceGaps,
		},
	)
	if err != nil {
		return nil, err
	}
	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(wicket.TokenErrorsInvalidTarget, ""), nil
		}
		return s.invalid(wicket.TokenErrorsInvalidScope, ""), nil
	}
	s.validatedRequest.ValidatedResources = validatedResources.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)
	return s.valid(), nil
}

func (s *TokenRequestValidator) validateExtensionGrantRequest(ctx context.Context, parameters url.Values) (*models.TokenRequestValidationResult, error) {
	s.Logger.Debug("Start validation of custom grant token request")

	// check if client is allowed to use grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), s.validatedRequest.GrantType) {
		s.Logger.Error("Client does not have the custom grant type in the allowed list, therefore requested grant is not allowed", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(wicket.TokenErrorsUnsupportedGrantType, ""), nil
	}

	// check if a validator is registered for the grant type
	if !utils.Contains(s.ExtensionGrantValidator.GetAvailableGrantTypes(), s.validatedRequest.GrantType) {
		s.Logger.Error("No validator is registered for the grant type", slog.String("grantType", s.validatedRequest.GrantType))
		return s.invalid(wicket.TokenErrorsUnsupportedGrantType, ""), nil
	}

	// check if client is allowed to request scopes
	scopesError := s.validateRequestedScopesAndResources(ctx, parameters, false, false)
	if scopesError != nil {
		return s.invalid(scopesError, ""), nil
	}

	// validate custom grant type
	result := s.ExtensionGrantValidator.Validate(s.validatedRequest)

	if result == nil {
		s.Logger.Error("Invalid extension grant")
		return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
	}

	if result.Error != nil {
		s.Logger.Error("Invalid extension grant", slog.String("error", result.Error.Error()))
		return s.invalid(result.Error, result.Description), nil
	}

	if result.Subject != nil {
		// make sure user is enabled
		isActiveCtx := models_contexts.NewIsActiveContext(s.validatedRequest.Subject, s.validatedRequest.Client, wicket.ProfileIsActiveCallersExtensionGrantValidation)

		s.Profile.IsActive(isActiveCtx)

		if !isActiveCtx.IsActive {
			s.Logger.Error("User has been disabled", slog.String("subjectId", extensions.GetSubjectIdFromPrincipal(result.Subject)))
			return s.invalid(wicket.TokenErrorsInvalidGrant, ""), nil
		}

		s.validatedRequest.Subject = result.Subject
	}

	s.Logger.Debug("Validation of extension grant token request success")

	return s.valid(), nil
}

// todo: do we want to rework the semantics of these ignore params?
// also seems like other workflows other than CC clients can omit scopes?
func (s *TokenRequestValidator) validateRequestedScopesAndResources(ctx context.Context, parameters url.Values, ignoreImplicitIdentityScopes bool, ignoreImplicitOfflineAccess bool) error {
	scopes := parameters.Get(wicket.TokenRequestScope)
	if scopes == "" {
		s.Logger.Debug("Client provided no scopes - checking allowed scopes list")

		if len(s.validatedRequest.Client.AllowedScopes) > 0 {
			// this finds all the scopes the client is allowed to access
			clientAllowedScopes := make([]string, 0)
			if !ignoreImplicitIdentityScopes {
				resources, err := s.ResourceStore.FindResourcesByScope(ctx, s.validatedRequest.Client.AllowedScopes)
				if err != nil {
					return err
				}

				clientAllowedScopes = append(clientAllowedScopes, utils.Where(resources.ToScopeNames(), func(x string) bool {
					return utils.Contains(s.validatedRequest.Client.AllowedScopes, x)
				})...)
			} else {
				apiScopes, err := s.ResourceStore.FindApiScopesByName(ctx, s.validatedRequest.Client.AllowedScopes)
				if err != nil {
					return err
				}

				clientAllowedScopes = append(clientAllowedScopes, utils.Select(apiScopes, func(x *storage_models.ApiScope) string { return x.Name })...)
			}

			if !ignoreImplicitOfflineAccess {
				if s.validatedRequest.Client.AllowOfflineAccess {
					clientAllowedScopes = append(clientAllowedScopes, wicket.StandardScopesOfflineAccess)
				}
			}

			scopes = strings.Join(utils.Distinct(clientAllowedScopes), " ")
			s.Logger.Debug("Defaulting to", slog.String("scopes", scopes))
		} else {
			s.Logger.Error("No allowed scopes configured for client", slog.String("clientId", s.validatedRequest.Client.ClientId))
			return wicket.TokenErrorsInvalidScope
		}
	}

	if len(scopes) > s.Options.InputLengthRestrictions.ClientSecret {
		s.Logger.Error("Scope parameter exceeds max allowed length")
		return wicket.TokenErrorsInvalidScope
	}

	requestedScopes := utils.ParseScopesString(scopes)
	if len(requestedScopes) == 0 {
		s.Logger.Error("No scopes found in request")
		return wicket.TokenErrorsInvalidScope
	}

	var resourceIndicators []string
	if s.validatedRequest.RequestedResourceGap != "" {
		resourceIndicators = append(resourceIndicators, s.validatedRequest.RequestedResourceGap)
	}

	resourceValidationResult, err := s.ResourceValidator.ValidateRequestedResources(
		ctx,
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       requestedScopes,
			ResourceGaps: resourceIndicators,
			// if the client is passing explicit scopes, we want to exclude the non-isolated resource scenaio from validation
			IncludeNonIsolatedApiResources: strings.TrimSpace(parameters.Get(wicket.TokenRequestScope)) == "",
		},
	)

	if err != nil {
		return err
	}
	if !resourceValidationResult.Succeeded() {

		if len(resourceValidationResult.InvalidResourceGaps) > 0 {
			s.Logger.Error("Invalid resource gap")
			return wicket.TokenErrorsInvalidTarget
		}
		if len(resourceValidationResult.InvalidScopes) > 0 {
			s.Logger.Error("Invalid scopes requested")
		} else {
			s.Logger.Error("Invalid scopes for client requested")
		}

		return wicket.TokenErrorsInvalidScope
	}

	s.validatedRequest.RequestedScopes = requestedScopes

	s.validatedRequest.ValidatedResources = resourceValidationResult.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)

	return nil
}

func (s *TokenRequestValidator) validateAuthorizationCodeWithProofKeyParameters(codeVerifier string, authZcode *storage_models.AuthorizationCode) *models.TokenRequestValidationResult {
	if authZcode.CodeChallenge == "" || authZcode.CodeChallengeMethod == "" {
		s.Logger.Error("Client is missing code challenge or code challenge method")
		return s.invalid(wicket.TokenErrorsInvalidGrant, "")
	}

	if codeVerifier == "" {
		s.Logger.Error("Missing code_verifier")
		return s.invalid(wicket.TokenErrorsInvalidGrant, "")
	}

	if len(codeVerifier) < s.Options.InputLengthRestrictions.CodeVerifierMinLength ||
		len(codeVerifier) > s.Options.InputLengthRestrictions.CodeVerifierMaxLength {
		s.Logger.Error("code_verifier is too short or too long")
		return s.invalid(wicket.TokenErrorsInvalidGrant, "")
	}

	if !utils.Contains(wicket.SupportedCodeChallengeMethods, authZcode.CodeChallengeMethod) {
		s.Logger.Error("Unsupported code challenge method")
		return s.invalid(wicket.TokenErrorsInvalidGrant, "")
	}

	if !s.validateCodeVerifierAgainstCodeChallenge(codeVerifier, authZcode.CodeChallenge, authZcode.CodeChallengeMethod) {
		s.Logger.Error("Transformed code verifier does not match code challenge", slog.String("codeVerifier", codeVerifier), slog.String("codeChallenge", authZcode.CodeChallenge), slog.String("codeChallengeMethod", authZcode.CodeChallengeMethod))

		return s.invalid(wicket.TokenErrorsInvalidGrant, "")
	}

	return s.valid()
}

func (s *TokenRequestValidator) validateCodeVerifierAgainstCodeChallenge(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	if codeChallengeMethod == wicket.CodeChallengeMethodsPlain {
		return utils.TimeConstantCompare(utils.Sha256(codeVerifier), codeChallenge)
	}

	h := sha256.New()
	h.Write([]byte(codeVerifier))

	transformedCodeVerifier := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return utils.TimeConstantCompare(utils.Sha256(transformedCodeVerifier), codeChallenge)
}

// TODO: support custom response
func (s *TokenRequestValidator) valid() *models.TokenRequestValidationResult {
	return models.NewTokenRequestValidationResult(s.validatedRequest)
}

// TODO: support custom response
func (s *TokenRequestValidator) invalid(err error, desc string) *models.TokenRequestValidationResult {
	return models.NewTokenRequestValidationResult(s.validatedRequest,
		models.WithTokenRequestValidationResultError(err),
		models.WithTokenRequestValidationResultDescription(desc),
	)
}
