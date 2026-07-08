// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
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

// Validates the request.
func (s *TokenRequestValidator) ValidateRequest(parameters url.Values, clientValidationResult *models.ClientSecretValidationResult) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start token request validation")

	s.validatedRequest = validators_models.NewValidatedTokenRequest()
	s.validatedRequest.IssuerName = s.IssuerNameService.GetCurrent()
	s.validatedRequest.Raw = parameters
	s.validatedRequest.Options = s.Options

	if clientValidationResult == nil {
		s.Logger.Error("Client validation result is nil")
		return s.invalid(errors.New("argument nil"), "ClientSecretValidationResult")
	}

	s.validatedRequest.SetClient(clientValidationResult.Client, clientValidationResult.Secret, clientValidationResult.Confirmation)

	// check client protocol type
	if s.validatedRequest.Client.ProtocolType != gois.ProtocolTypesOpenIdConnect {
		s.Logger.Error("Invalid protocol type for client")
		return s.invalid(gois.TokenErrorsInvalidClient, "")
	}

	// check grant type
	grantType := parameters.Get(gois.TokenRequestGrantType)
	if grantType == "" {
		s.Logger.Error("Grant type is missing")
		return s.invalid(gois.TokenErrorsUnsupportedGrantType, "")
	}

	if len(grantType) > s.Options.InputLengthRestrictions.GrantType {
		s.Logger.Error("Grant type is too long")
		return s.invalid(gois.TokenErrorsUnsupportedGrantType, "")
	}

	s.validatedRequest.GrantType = grantType

	// check for resource gap and basic formatting
	resourceIndicators := parameters[gois.TokenRequestResource]

	if utils.AnyPred(resourceIndicators, func(x string) bool {
		return len(x) > s.Options.InputLengthRestrictions.ResourceGapMaxLength
	}) {
		return s.invalid(gois.TokenErrorsInvalidTarget, "Resource indicator maximum length exceeded")
	}

	if !utils.AreValidResourceGapFormat(resourceIndicators) {
		return s.invalid(gois.TokenErrorsInvalidTarget, "Invalid resource gap format")
	}

	if len(resourceIndicators) > 1 {
		return s.invalid(gois.TokenErrorsInvalidTarget, "Multiple resource gaps not supported on token endpoint.")
	}

	s.validatedRequest.RequestedResourceGap = utils.SingleOrDefault(resourceIndicators)

	// run specific logic for grants
	switch grantType {
	case gois.GrantTypeAuthorizationCode:
		return s.runValidation(s.validateAuthorizationCodeRequest, parameters)
	case gois.GrantTypeClientCredentials:
		return s.runValidation(s.validateClientCredentialsRequest, parameters)
	case gois.GrantTypePassword:
		return s.runValidation(s.validateResourceOwnerCredentialRequest, parameters)
	case gois.GrantTypeRefreshToken:
		return s.runValidation(s.validateRefreshTokenRequest, parameters)
	case gois.GrantTypeDeviceCode:
		return s.runValidation(s.validateDeviceCodeRequest, parameters)
	case gois.GrantTypeBackchannelAuthentication:
		return s.runValidation(s.validateBackchannelAuthenticationRequest, parameters)
	default:
		return s.runValidation(s.validateExtensionGrantRequest, parameters)
	}

}

func (s *TokenRequestValidator) runValidation(validationFunc func(url.Values) *models.TokenRequestValidationResult, parameters url.Values) *models.TokenRequestValidationResult {
	// run standard validation
	result := validationFunc(parameters)
	if result.Error != nil {
		return result
	}

	// run custom validation
	s.Logger.Debug("Calling into custom request validator", slog.String("type", fmt.Sprintf("%T", s.CustomRequestValidator)))

	customValidationContext := &validators_contexts.CustomTokenRequestValidationContext{Result: result}
	err := s.CustomRequestValidator.Validate(customValidationContext)
	if err != nil || customValidationContext.Result.Error != nil {
		if customValidationContext.Result.Error != nil {
			s.Logger.Error("Custom token request validator", slog.String("error", customValidationContext.Result.Error.Error()))
		} else {
			s.Logger.Error("Custom token request validator error")
		}

		return customValidationContext.Result
	}

	return customValidationContext.Result
}

func (s *TokenRequestValidator) validateAuthorizationCodeRequest(parameters url.Values) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start validation of authorization code token request")

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), gois.GrantTypeAuthorizationCode) &&
		!utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), gois.GrantTypeHybrid) {
		s.Logger.Error("Client not authorized for code flow")
		return s.invalid(gois.TokenErrorsUnauthorizedClient, "")
	}

	// validate authorization code
	code := parameters.Get(gois.TokenRequestCode)
	if code == "" {
		s.Logger.Error("Authorization code is missing")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if len(code) > s.Options.InputLengthRestrictions.AuthorizationCode {
		s.Logger.Error("Authorization code is too long")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	s.validatedRequest.AuthorizationCodeHandle = code

	authZcode, err := s.AuthorizationCodeStore.GetAuthorizationCode(code)
	if err != nil || authZcode == nil {
		s.Logger.Error("Invalid authorization code", slog.String("code", code))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	// validate client binding
	if authZcode.ClientId != s.validatedRequest.Client.ClientId {
		s.Logger.Error("Client is trying to use a code from a different client")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	// remove code from store
	// todo: set to consumed in the future?
	if err := s.AuthorizationCodeStore.RemoveAuthorizationCode(code); err != nil {
		s.Logger.Error("Error removing authorization code", slog.String("code", code))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if authZcode.CreationTime.Add(time.Duration(authZcode.Lifetime) * time.Second).Before(s.Clock.Now()) {
		s.Logger.Error("Authorization code expired", slog.String("code", code))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	// populate session id
	if authZcode.SessionId != "" {
		s.validatedRequest.SessionId = authZcode.SessionId
	}

	// validate code expiration
	if authZcode.CreationTime.Add(time.Duration(s.validatedRequest.Client.AuthorizationCodeLifetime) * time.Second).Before(s.Clock.Now()) {
		s.Logger.Error("Authorization code is expired", slog.String("code", code))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	s.validatedRequest.AuthorizationCode = authZcode
	s.validatedRequest.Subject = authZcode.Subject

	// validate redirect_uri
	redirectUri := parameters.Get(gois.TokenRequestRedirectUri)
	if redirectUri == "" {
		s.Logger.Error("Redirect URI is missing")
		return s.invalid(gois.TokenErrorsUnauthorizedClient, "")
	}

	if redirectUri != s.validatedRequest.AuthorizationCode.RedirectUri {
		s.Logger.Error("Invalid redirect_uri")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	// validate scopes are present
	if len(s.validatedRequest.AuthorizationCode.RequestedScopes) == 0 {
		s.Logger.Error("Authorization code has no associated scopes")
		return s.invalid(gois.TokenErrorsInvalidRequest, "")
	}

	// resource gap
	if s.validatedRequest.RequestedResourceGap != "" &&
		len(s.validatedRequest.AuthorizationCode.RequestedResourceGaps) > 0 &&
		!utils.Contains(s.validatedRequest.AuthorizationCode.RequestedResourceGaps, s.validatedRequest.RequestedResourceGap) {
		return s.invalid(gois.TokenErrorsInvalidTarget, "Resource indicator does not match any resource gap in the original authorize request.")
	}

	// resource and scope validation
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       s.validatedRequest.AuthorizationCode.RequestedScopes,
			ResourceGaps: s.validatedRequest.AuthorizationCode.RequestedResourceGaps,
			// if we are issuing a refresh token, then we need to allow the non-isolated resource
			IncludeNonIsolatedApiResources: utils.Contains(s.validatedRequest.AuthorizationCode.RequestedScopes, gois.StandardScopesOfflineAccess),
		},
	)

	if err != nil {
		return s.invalid(err, "")
	}

	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(gois.TokenErrorsInvalidTarget, "Invalid resource gap.")
		}
		if len(validatedResources.InvalidScopes) > 0 {
			return s.invalid(gois.TokenErrorsInvalidScope, "Invalid scope.")
		}
	}

	s.validatedRequest.ValidatedResources = validatedResources.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)

	// validate PKCE parameters
	codeVerifier := parameters.Get(gois.TokenRequestCodeVerifier)
	if s.validatedRequest.Client.RequirePkce || s.validatedRequest.AuthorizationCode.CodeChallenge != "" {
		s.Logger.Debug("Client required a proof key for code exchange. Starting PKCE validation")

		proofKeyResult := s.validateAuthorizationCodeWithProofKeyParameters(codeVerifier, s.validatedRequest.AuthorizationCode)
		if proofKeyResult.Error != nil {
			return proofKeyResult
		}

		s.validatedRequest.CodeVerifier = codeVerifier
	} else {
		if codeVerifier != "" {
			s.Logger.Error("Unexpected code_verifier: This happens when the client is trying to use PKCE, but it is not enabled. Set RequirePkce to true.", slog.String("codeVerifier", codeVerifier))
			return s.invalid(gois.TokenErrorsInvalidGrant, "")
		}
	}

	// make sure user is enabled
	isActiveCtx := models_contexts.NewIsActiveContext(s.validatedRequest.AuthorizationCode.Subject, s.validatedRequest.Client, gois.ProfileIsActiveCallersAccessTokenValidation)

	s.Profile.IsActive(isActiveCtx)
	if !isActiveCtx.IsActive {
		s.Logger.Error("User has been disabled", slog.String("subjectId", extensions.GetSubjectIdFromPrincipal(s.validatedRequest.AuthorizationCode.Subject)))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	s.Logger.Debug("Validation of authorization code token request success")

	return s.valid()
}

func (s *TokenRequestValidator) validateClientCredentialsRequest(parameters url.Values) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start client credentials token request validation")

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), gois.GrantTypeClientCredentials) {
		s.Logger.Error("Client not authorized for client credentials flow, check the AllowedGrantTypes setting")
		return s.invalid(gois.TokenErrorsUnauthorizedClient, "")
	}

	// check if client is allowed to request scopes
	scopeError := s.validateRequestedScopesAndResources(parameters, true, true)
	if scopeError != nil {
		return s.invalid(scopeError, "")
	}

	if len(s.validatedRequest.ValidatedResources.Resources.IdentityResources()) > 0 {
		s.Logger.Error("Client cannot request OpenID scopes in client credentials flow", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(gois.TokenErrorsInvalidScope, "")
	}

	if s.validatedRequest.ValidatedResources.Resources.OfflineAccess {
		s.Logger.Error("Client cannot request a refresh token in client credentials flow", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(gois.TokenErrorsInvalidScope, "")
	}

	s.Logger.Debug("credentials token request validation success", slog.String("clientId", s.validatedRequest.Client.ClientId))

	return s.valid()
}

func (s *TokenRequestValidator) validateResourceOwnerCredentialRequest(parameters url.Values) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start resource owner password token request validation")

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), gois.GrantTypePassword) {
		s.Logger.Error("Client not authorized for resource owner password flow, check the AllowedGrantTypes setting", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(gois.TokenErrorsUnauthorizedClient, "")
	}

	// check if client is allowed to request scopes
	scopeError := s.validateRequestedScopesAndResources(parameters, false, false)
	if scopeError != nil {
		return s.invalid(scopeError, "")
	}

	// check resource owner credentials
	userName := parameters.Get(gois.TokenRequestUserName)
	password := parameters.Get(gois.TokenRequestPassword)

	if userName == "" {
		s.Logger.Error("Username is missing")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if len(userName) > s.Options.InputLengthRestrictions.UserName ||
		len(password) > s.Options.InputLengthRestrictions.Password {
		s.Logger.Error("Username or password is too long")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
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
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if resourceOwnerContext.Result.Error != nil {
		// protect against bad validator implementations
		if errors.Is(resourceOwnerContext.Result.Error, gois.TokenErrorsUnsupportedGrantType) {
			s.Logger.Error("Resource owner password credential grant type not supported")
			return s.invalid(gois.TokenErrorsUnsupportedGrantType, "")
		}

		desc := "invalid_username_or_password"

		if resourceOwnerContext.Result.Description != "" {
			desc = resourceOwnerContext.Result.Description
		}

		s.Logger.Info("User authentication failed", slog.String("error", resourceOwnerContext.Result.Error.Error()), slog.String("errorDescription", desc))

		return s.invalid(resourceOwnerContext.Result.Error, desc)
	}

	if resourceOwnerContext.Result.Subject == nil {
		s.Logger.Error("User authentication failed: No principal returned")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	// make sure user is enabled
	isActiveCtx := models_contexts.NewIsActiveContext(resourceOwnerContext.Result.Subject, s.validatedRequest.Client, gois.ProfileIsActiveCallersResourceOwnerValidation)
	s.Profile.IsActive(isActiveCtx)

	if !isActiveCtx.IsActive {
		s.Logger.Error("User has been disabled", slog.String("subjectId", extensions.GetSubjectIdFromPrincipal(resourceOwnerContext.Result.Subject)))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	s.validatedRequest.UserName = userName
	s.validatedRequest.Subject = resourceOwnerContext.Result.Subject

	s.Logger.Debug("Resource owner password token request validation success")

	return s.valid()
}

func (s *TokenRequestValidator) validateRefreshTokenRequest(parameters url.Values) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start validation of refresh token validation")

	refreshTokenHandle := parameters.Get(gois.TokenRequestRefreshToken)
	if refreshTokenHandle == "" {
		s.Logger.Error("Refresh token is missing")
		return s.invalid(gois.TokenErrorsInvalidRequest, "")
	}

	if len(refreshTokenHandle) > s.Options.InputLengthRestrictions.RefreshToken {
		s.Logger.Error("Refresh token is too long")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	result := s.RefreshTokenService.ValidateRefreshToken(refreshTokenHandle, s.validatedRequest.Client)

	if result.Error != nil {
		s.Logger.Error("Refresh token validation failed. aborting")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	s.validatedRequest.RefreshToken = result.RefreshToken
	s.validatedRequest.RefreshTokenHandle = refreshTokenHandle
	s.validatedRequest.Subject = result.RefreshToken.Subject
	s.validatedRequest.SessionId = result.RefreshToken.SessionId

	// resource gap
	resourceIndicators := s.validatedRequest.RefreshToken.AuthorizedResourceGaps
	if len(s.validatedRequest.RefreshToken.AuthorizedResourceGaps) > 0 {
		// we had an authorization request so check current requested resource against original list
		if s.validatedRequest.RequestedResourceGap != "" &&
			!utils.Contains(s.validatedRequest.RefreshToken.AuthorizedResourceGaps, s.validatedRequest.RequestedResourceGap) {
			s.Logger.Error("Refresh token validation failed. requested resource gap not authorized")
			return s.invalid(gois.TokenErrorsInvalidTarget, "Resource indicator does not match any resource gap in the original authorize request.")
		}
	} else {
		if strings.TrimSpace(s.validatedRequest.RequestedResourceGap) != "" {
			resourceIndicators = []string{s.validatedRequest.RequestedResourceGap}
		}
	}

	// resource and scope validation
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
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
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(gois.TokenErrorsInvalidTarget, "Invalid resource gap.")
		}
		if len(validatedResources.InvalidScopes) > 0 {
			return s.invalid(gois.TokenErrorsInvalidScope, "Invalid scope.")
		}
	}

	//TODO License validation

	s.validatedRequest.ValidatedResources = validatedResources.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)

	s.Logger.Debug("Validation of refresh token request success")
	// todo: more logging - similar to TokenValidator before

	return s.valid()
}

func (s *TokenRequestValidator) validateDeviceCodeRequest(parameters url.Values) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start validation of device code request")

	// resource gap not supported for device flow
	if s.validatedRequest.RequestedResourceGap != "" {
		s.Logger.Error("Resource indicator not supported for device flow")
		return s.invalid(gois.TokenErrorsInvalidTarget, "")
	}

	// check if client is authorized for grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), gois.GrantTypeDeviceCode) {
		s.Logger.Error("Client not authorized for device flow")
		return s.invalid(gois.TokenErrorsUnauthorizedClient, "")
	}

	// validate device code parameter
	deviceCode := parameters.Get(gois.TokenRequestDeviceCode)
	if deviceCode == "" {
		s.Logger.Error("Device code is missing")
		return s.invalid(gois.TokenErrorsInvalidRequest, "")
	}

	if len(deviceCode) > s.Options.InputLengthRestrictions.DeviceCode {
		s.Logger.Error("Device code is too long")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	// validate device code
	deviceCodeContext := &validators_models.DeviceCodeValidationContext{
		DeviceCode: deviceCode,
		Request:    s.validatedRequest,
	}

	err := s.DeviceCodeValidator.Validate(deviceCodeContext)
	if err != nil {
		s.Logger.Error("Device code validation failed", slog.String("error", err.Error()))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if deviceCodeContext.Result.Error != nil {
		return deviceCodeContext.Result
	}

	// scope validation
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       s.validatedRequest.DeviceCode.AuthorizedScopes,
			ResourceGaps: nil, // not supported for device grant
		},
	)

	if err != nil {
		s.Logger.Error("Resource validation failed. aborting", slog.String("error", err.Error()))
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(gois.TokenErrorsInvalidTarget, "Invalid resource gap.")
		}
		if len(validatedResources.InvalidScopes) > 0 {
			return s.invalid(gois.TokenErrorsInvalidScope, "Invalid scope.")
		}
	}

	//TODO License validation

	s.Logger.Debug("Validation of device code token request success")

	return s.valid()
}

func (s *TokenRequestValidator) validateBackchannelAuthenticationRequest(parameters url.Values) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start validation of CIBA token request")
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), gois.GrantTypeBackchannelAuthentication) {
		return s.invalid(gois.TokenErrorsUnauthorizedClient, "")
	}
	requestID := parameters.Get(gois.TokenRequestAuthenticationRequestId)
	if requestID == "" {
		return s.invalid(gois.TokenErrorsInvalidRequest, "")
	}
	if len(requestID) > s.Options.InputLengthRestrictions.AuthenticationRequestId {
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}
	ctx := &validators_models.BackchannelAuthenticationRequestIdValidationContext{
		RequestId: requestID,
		Request:   s.validatedRequest,
	}
	if err := s.BackchannelAuthenticationRequestIdValidator.Validate(ctx); err != nil {
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}
	if ctx.Result == nil {
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}
	if ctx.Result.Error != nil {
		return ctx.Result
	}
	validatedResources, err := s.ResourceValidator.ValidateRequestedResources(
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       s.validatedRequest.BackchannelAuthenticationRequest.RequestedScopes,
			ResourceGaps: s.validatedRequest.BackchannelAuthenticationRequest.RequestedResourceGaps,
		},
	)
	if err != nil {
		return s.invalid(err, "")
	}
	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidResourceGaps) > 0 {
			return s.invalid(gois.TokenErrorsInvalidTarget, "")
		}
		return s.invalid(gois.TokenErrorsInvalidScope, "")
	}
	s.validatedRequest.ValidatedResources = validatedResources.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)
	return s.valid()
}

func (s *TokenRequestValidator) validateExtensionGrantRequest(parameters url.Values) *models.TokenRequestValidationResult {
	s.Logger.Debug("Start validation of custom grant token request")

	// check if client is allowed to use grant type
	if !utils.Contains(s.validatedRequest.Client.AllowedGrantTypes(), s.validatedRequest.GrantType) {
		s.Logger.Error("Client does not have the custom grant type in the allowed list, therefore requested grant is not allowed", slog.String("clientId", s.validatedRequest.Client.ClientId))
		return s.invalid(gois.TokenErrorsUnsupportedGrantType, "")
	}

	// check if a validator is registered for the grant type
	if !utils.Contains(s.ExtensionGrantValidator.GetAvailableGrantTypes(), s.validatedRequest.GrantType) {
		s.Logger.Error("No validator is registered for the grant type", slog.String("grantType", s.validatedRequest.GrantType))
		return s.invalid(gois.TokenErrorsUnsupportedGrantType, "")
	}

	// check if client is allowed to request scopes
	scopesError := s.validateRequestedScopesAndResources(parameters, false, false)
	if scopesError != nil {
		return s.invalid(scopesError, "")
	}

	// validate custom grant type
	result := s.ExtensionGrantValidator.Validate(s.validatedRequest)

	if result == nil {
		s.Logger.Error("Invalid extension grant")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if result.Error != nil {
		s.Logger.Error("Invalid extension grant", slog.String("error", result.Error.Error()))
		return s.invalid(result.Error, result.Description)
	}

	if result.Subject != nil {
		// make sure user is enabled
		isActiveCtx := models_contexts.NewIsActiveContext(s.validatedRequest.Subject, s.validatedRequest.Client, gois.ProfileIsActiveCallersExtensionGrantValidation)

		s.Profile.IsActive(isActiveCtx)

		if !isActiveCtx.IsActive {
			s.Logger.Error("User has been disabled", slog.String("subjectId", extensions.GetSubjectIdFromPrincipal(result.Subject)))
			return s.invalid(gois.TokenErrorsInvalidGrant, "")
		}

		s.validatedRequest.Subject = result.Subject
	}

	s.Logger.Debug("Validation of extension grant token request success")

	return s.valid()
}

// todo: do we want to rework the semantics of these ignore params?
// also seems like other workflows other than CC clients can omit scopes?
func (s *TokenRequestValidator) validateRequestedScopesAndResources(parameters url.Values, ignoreImplicitIdentityScopes bool, ignoreImplicitOfflineAccess bool) error {
	scopes := parameters.Get(gois.TokenRequestScope)
	if scopes == "" {
		s.Logger.Debug("Client provided no scopes - checking allowed scopes list")

		if len(s.validatedRequest.Client.AllowedScopes) > 0 {
			// this finds all the scopes the client is allowed to access
			clientAllowedScopes := make([]string, 0)
			if !ignoreImplicitIdentityScopes {
				resources, err := s.ResourceStore.FindResourcesByScope(s.validatedRequest.Client.AllowedScopes)
				if err != nil {
					return err
				}

				clientAllowedScopes = append(clientAllowedScopes, utils.Where(resources.ToScopeNames(), func(x string) bool {
					return utils.Contains(s.validatedRequest.Client.AllowedScopes, x)
				})...)
			} else {
				apiScopes, err := s.ResourceStore.FindApiScopesByName(s.validatedRequest.Client.AllowedScopes)
				if err != nil {
					return err
				}

				clientAllowedScopes = append(clientAllowedScopes, utils.Select(apiScopes, func(x *storage_models.ApiScope) string { return x.Name })...)
			}

			if !ignoreImplicitOfflineAccess {
				if s.validatedRequest.Client.AllowOfflineAccess {
					clientAllowedScopes = append(clientAllowedScopes, gois.StandardScopesOfflineAccess)
				}
			}

			scopes = strings.Join(utils.Distinct(clientAllowedScopes), " ")
			s.Logger.Debug("Defaulting to", slog.String("scopes", scopes))
		} else {
			s.Logger.Error("No allowed scopes configured for client", slog.String("clientId", s.validatedRequest.Client.ClientId))
			return gois.TokenErrorsInvalidScope
		}
	}

	if len(scopes) > s.Options.InputLengthRestrictions.ClientSecret {
		s.Logger.Error("Scope parameter exceeds max allowed length")
		return gois.TokenErrorsInvalidScope
	}

	requestedScopes := utils.ParseScopesString(scopes)
	if len(requestedScopes) == 0 {
		s.Logger.Error("No scopes found in request")
		return gois.TokenErrorsInvalidScope
	}

	var resourceIndicators []string
	if s.validatedRequest.RequestedResourceGap != "" {
		resourceIndicators = append(resourceIndicators, s.validatedRequest.RequestedResourceGap)
	}

	resourceValidationResult, err := s.ResourceValidator.ValidateRequestedResources(
		&validators_models.ResourceValidationRequest{
			Client:       s.validatedRequest.Client,
			Scopes:       requestedScopes,
			ResourceGaps: resourceIndicators,
			// if the client is passing explicit scopes, we want to exclude the non-isolated resource scenaio from validation
			IncludeNonIsolatedApiResources: strings.TrimSpace(parameters.Get(gois.TokenRequestScope)) == "",
		},
	)

	if err != nil {
		return err
	}
	if !resourceValidationResult.Succeeded() {

		if len(resourceValidationResult.InvalidResourceGaps) > 0 {
			s.Logger.Error("Invalid resource gap")
			return gois.TokenErrorsInvalidTarget
		}
		if len(resourceValidationResult.InvalidScopes) > 0 {
			s.Logger.Error("Invalid scopes requested")
		} else {
			s.Logger.Error("Invalid scopes for client requested")
		}

		return gois.TokenErrorsInvalidScope
	}

	s.validatedRequest.RequestedScopes = requestedScopes

	s.validatedRequest.ValidatedResources = resourceValidationResult.FilterByResourceGap(s.validatedRequest.RequestedResourceGap)

	return nil
}

func (s *TokenRequestValidator) validateAuthorizationCodeWithProofKeyParameters(codeVerifier string, authZcode *storage_models.AuthorizationCode) *models.TokenRequestValidationResult {
	if authZcode.CodeChallenge == "" || authZcode.CodeChallengeMethod == "" {
		s.Logger.Error("Client is missing code challenge or code challenge method")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if codeVerifier == "" {
		s.Logger.Error("Missing code_verifier")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if len(codeVerifier) < s.Options.InputLengthRestrictions.CodeVerifierMinLength ||
		len(codeVerifier) > s.Options.InputLengthRestrictions.CodeVerifierMaxLength {
		s.Logger.Error("code_verifier is too short or too long")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if !utils.Contains(gois.SupportedCodeChallengeMethods, authZcode.CodeChallengeMethod) {
		s.Logger.Error("Unsupported code challenge method")
		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	if !s.validateCodeVerifierAgainstCodeChallenge(codeVerifier, authZcode.CodeChallenge, authZcode.CodeChallengeMethod) {
		s.Logger.Error("Transformed code verifier does not match code challenge", slog.String("codeVerifier", codeVerifier), slog.String("codeChallenge", authZcode.CodeChallenge), slog.String("codeChallengeMethod", authZcode.CodeChallengeMethod))

		return s.invalid(gois.TokenErrorsInvalidGrant, "")
	}

	return s.valid()
}

func (s *TokenRequestValidator) validateCodeVerifierAgainstCodeChallenge(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	if codeChallengeMethod == gois.CodeChallengeMethodsPlain {
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
