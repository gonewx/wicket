// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/services"
	storage "github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type AuthorizeRequestValidator struct {
	logger *slog.Logger

	options                 *config_options.WicketOptions
	issuerNameService       services.IssuerNameService
	clients                 storage.ClientStore
	jwtRequestUriHttpClient services.JwtRequestUriHttpClient
	jwtRequestValidator     validators.JwtRequestValidator
	uriValidator            validators.RedirectUriValidator
	resourceValidator       validators.ResourceValidator
	// httpContextAccessor     accessor.HttpContextAccessor
	userSession     services.UserSession
	customValidator validators.CustomAuthorizeRequestValidator
}

func NewAuthorizeRequestValidator(
	logger *slog.Logger,
	options *config_options.WicketOptions,
	issuerNameService services.IssuerNameService,
	clients storage.ClientStore,
	jwtRequestUriHttpClient services.JwtRequestUriHttpClient,
	jwtRequestValidator validators.JwtRequestValidator,
	uriValidator validators.RedirectUriValidator,
	resourceValidator validators.ResourceValidator,
	// httpContextAccessor accessor.HttpContextAccessor,
	userSession services.UserSession,
	customValidator validators.CustomAuthorizeRequestValidator,
) *AuthorizeRequestValidator {
	v := &AuthorizeRequestValidator{
		logger:                  logger,
		options:                 options,
		issuerNameService:       issuerNameService,
		clients:                 clients,
		jwtRequestUriHttpClient: jwtRequestUriHttpClient,
		jwtRequestValidator:     jwtRequestValidator,
		uriValidator:            uriValidator,
		resourceValidator:       resourceValidator,
		// httpContextAccessor:     httpContextAccessor,
		userSession:     userSession,
		customValidator: customValidator,
	}
	return v
}

func responseTypeEqualityComparer() *ResponseTypeEqualityComparer {
	return &ResponseTypeEqualityComparer{}
}

func (v *AuthorizeRequestValidator) Validate(values url.Values,
	subject *claimspkg.ClaimsPrincipal) *validators_models.AuthorizeRequestValidationResult {
	v.logger.Debug("Start authorize request protocol validation")

	if subject == nil {
		subject = claimspkg.ClaimsPrincipalAnonymous()
	}
	request := &validators_models.ValidatedAuthorizeRequest{
		ValidatedRequest: &validators_models.ValidatedRequest{
			Options:    v.options,
			IssuerName: string(v.issuerNameService.GetCurrent()),
			Subject:    subject,
			Raw:        values,
		},
	}

	var err error
	// client_id must always be present on the request
	result := v.loadClient(request)
	if result.Error != nil {
		return result
	}
	result = v.loadRequestObject(request)
	if result.Error != nil {
		return result
	}
	result = v.validateRequestObject(request)
	if result.Error != nil {
		return result
	}
	// validate client_id and redirect_uri
	result = v.validateClient(request)
	if result.Error != nil {
		return result
	}
	// state, response_type, response_mode
	result = v.validateCoreParameters(request)
	if result.Error != nil {
		return result
	}

	// scope, scope restrictions and plausability, and resource gaps
	result = v.validateScopeAndResource(request)
	if result.Error != nil {
		return result
	}

	// nonce, prompt, acr_values, login_hint etc.
	result = v.validateOptionalParameters(request)
	if result.Error != nil {
		return result
	}

	// custom validator
	context := &validators_contexts.CustomAuthorizeRequestValidationContext{
		Request: request,
	}
	err = v.customValidator.Validate(context)
	if err != nil {
		return invalid(request, err, err.Error())
	}

	return valid(request)
}

func (v *AuthorizeRequestValidator) loadClient(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	clientId := request.Raw.Get(gois.AuthorizeRequestClientId)

	// client_id must be present
	if clientId == "" ||
		len(clientId) > v.options.InputLengthRestrictions.ClientId {
		v.logger.Error("client_id is missing or too long", slog.Any("request", request))
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid client_id")
	}

	request.ClientId = clientId

	// check for valid client
	client, err := extensions.FindEnabledClientById(v.clients, clientId)
	if err != nil || client == nil {
		v.logger.Error("Unknown client or not enabled", slog.String("clientId", clientId), slog.Any("request", request))
		return invalid(request, gois.AuthorizeErrorsUnauthorizedClient, "Unknown client or client not enabled")
	}

	request.SetClient(client, nil, "")

	return valid(request)
}

func (v *AuthorizeRequestValidator) loadRequestObject(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {

	jwtRequest := strings.TrimSpace(request.Raw.Get(gois.AuthorizeRequestRequest))
	jwtRequestUri := strings.TrimSpace(request.Raw.Get(gois.AuthorizeRequestRequestUri))

	if jwtRequest != "" && jwtRequestUri != "" {
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Only one request parameter is allowed")
	}

	if v.options.Endpoints.EnableJwtRequestUri {
		if jwtRequestUri != "" {
			// 512 is from the spec
			if len(jwtRequestUri) > 512 {
				return invalid(request, gois.AuthorizeErrorsInvalidRequestUri, "request_uri is too long")
			}
		}

		jwt, err := v.jwtRequestUriHttpClient.GetJwt(jwtRequestUri, request.Client)
		if err != nil {
			return invalid(request, err, "")
		}

		if jwt == "" {
			return invalid(request, gois.AuthorizeErrorsInvalidRequestUri, "no value returned from request_uri")
		}

		jwtRequest = jwt
	} else {
		if jwtRequestUri != "" {
			return invalid(request, gois.AuthorizeErrorsRequestUriNotSupported, "")
		}
	}

	// check length restrictions
	if jwtRequest != "" {
		if len(jwtRequest) >= v.options.InputLengthRestrictions.Jwt {
			return invalid(request, gois.AuthorizeErrorsInvalidRequestObject, "Invalid request value")
		}
	}

	request.RequestObject = jwtRequest
	return valid(request)
}

func (v *AuthorizeRequestValidator) validateRequestObject(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	// validate request object
	if request.RequestObject == "" {
		return valid(request)
	}

	// validate the request JWT for this client
	jwtRequestValidationResult, err := v.jwtRequestValidator.Validate(&validators_contexts.JwtRequestValidationContext{
		Client:         request.Client,
		JwtTokenString: request.RequestObject,
	})
	if err != nil || jwtRequestValidationResult.Error != nil {
		v.logger.Error("request JWT validation failure", slog.String("err", err.Error()))
		return invalid(request, gois.AuthorizeErrorsInvalidRequestObject, "Invalid JWT request")
	}

	// validate response_type match
	responseType := request.Raw.Get(gois.AuthorizeRequestResponseType)
	if strings.TrimSpace(responseType) != "" {
		claim := utils.SingleOrDefaultPred(jwtRequestValidationResult.Payload, func(c *claimspkg.Claim) bool {
			if c == nil {
				return false
			}
			return c.Type == gois.AuthorizeRequestResponseType
		})

		if claim != nil {
			payloadResponseType := claim.Value.(string)
			if strings.TrimSpace(payloadResponseType) != "" && payloadResponseType != responseType {
				v.logger.Error("response_type in JWT payload does not match response_type in request", slog.Any("request", request))
				return invalid(request, gois.AuthorizeErrorsInvalidRequestObject, "Invalid JWT request")
			}
		}
	}

	// validate client_id match
	claim := utils.SingleOrDefaultPred(jwtRequestValidationResult.Payload, func(c *claimspkg.Claim) bool {
		if c == nil {
			return false
		}
		return c.Type == gois.AuthorizeRequestClientId
	})

	var payloadClientId string
	if claim != nil {
		payloadClientId = claim.Value.(string)
	}

	if strings.TrimSpace(payloadClientId) != "" {
		if payloadClientId != request.Client.ClientId {
			v.logger.Error("client_id in JWT payload does not match client_id in request", slog.Any("request", request))
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid JWT request")
		}
	} else {
		v.logger.Error("client_id is missing in JWT payload", slog.Any("request", request))
		return invalid(request, gois.AuthorizeErrorsInvalidRequestObject, "Invalid JWT request")
	}

	// merge jwt payload values into original request parameters
	// 1. clear the keys in the raw collection for every key found in the request object

	for _, claimType := range utils.Distinct(utils.Select(jwtRequestValidationResult.Payload, func(c *claimspkg.Claim) string {
		return c.Type
	})) {
		qsValue := request.Raw.Get(claimType)
		if qsValue != "" {
			request.Raw.Del(claimType)
		}
	}

	// 2. copy over the value
	for _, claim := range jwtRequestValidationResult.Payload {
		request.Raw.Add(claim.Type, fmt.Sprint(claim.Value))
	}

	ruri := request.Raw.Get(gois.AuthorizeRequestRequestUri)
	if ruri != "" {
		request.Raw.Del(gois.AuthorizeRequestRequestUri)
		request.Raw.Add(gois.AuthorizeRequestRequest, request.RequestObject)
	}

	request.RequestObjectValues = jwtRequestValidationResult.Payload

	return valid(request)
}

func (v *AuthorizeRequestValidator) validateClient(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	// check request object requirement
	if request.Client.RequireRequestObject {
		if !utils.Any(request.RequestObjectValues) {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Client must use request object, but no request or request_uri parameter present")
		}
	}

	redirectUri := request.Raw.Get(gois.AuthorizeRequestRedirectUri)
	if strings.TrimSpace(redirectUri) == "" || len(redirectUri) > v.options.InputLengthRestrictions.RedirectUri {
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid redirect_uri")
	}

	if !utils.IsUri(redirectUri) {
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid redirect_uri")
	}

	// check if client protocol type is oidc
	if request.Client.ProtocolType != gois.ProtocolTypesOpenIdConnect {
		return invalid(request, gois.AuthorizeErrorsUnauthorizedClient, "Invalid protocol")
	}

	// check if redirect_uri is valid
	if !v.uriValidator.IsRedirectUriValid(redirectUri, request.Client) {
		v.logger.Debug("redirect_uri is not valid", slog.String("redirect_uri", redirectUri), slog.Any("client", request.Client))
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid redirect_uri")
	}
	request.RedirectUri = redirectUri

	return valid(request)
}

func (v *AuthorizeRequestValidator) validateCoreParameters(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	// check state
	state := strings.TrimSpace(request.Raw.Get(gois.AuthorizeRequestState))
	if state != "" {
		request.State = state
	}

	// response_type must be present and supported
	responseType := strings.TrimSpace(request.Raw.Get(gois.AuthorizeRequestResponseType))
	if responseType == "" {
		return invalid(request, gois.AuthorizeErrorsUnsupportedResponseType, "Missing response_type")
	}

	// The responseType may come in in an unconventional order.
	// Use an IEqualityComparer that doesn't care about the order of multiple values.
	// Per https://tools.ietf.org/html/rfc6749#section-3.1.1 -
	// 'Extension response types MAY contain a space-delimited (%x20) list of
	// values, where the order of values does not matter (e.g., response
	// type "a b" is the same as "b a").'
	// http://openid.net/specs/oauth-v2-multiple-response-types-1_0-03.html#terminology -
	// 'If a response type contains one of more space characters (%20), it is compared
	// as a space-delimited list of values in which the order of values does not matter.'

	if !utils.ContainsEq[string](gois.SupportedResponseTypes, responseType, responseTypeEqualityComparer()) {
		return invalid(request, gois.AuthorizeErrorsUnsupportedResponseType, "Response type not supported")
	}

	// Even though the responseType may have come in in an unconventional order,
	// we still need the request's ResponseType property to be set to the
	// conventional, supported response type.
	request.ResponseType = utils.FirstPred(gois.SupportedResponseTypes, func(supportedResponseType string) bool {
		return responseTypeEqualityComparer().Equal(supportedResponseType, responseType)
	})

	// match response_type to grant type
	request.GrantType = gois.ResponseTypeToGrantTypeMapping[request.ResponseType]

	// set default response mode for flow; this is needed for any client error processing below
	request.ResponseMode = utils.First(gois.AllowedResponseModesForGrantType[request.GrantType])
	v.logger.Debug("ResponseMode", slog.String("ResponseMode", request.ResponseMode))

	// check if flow is allowed at authorize endpoint
	if !utils.Contains(gois.AllowedGrantTypesForAuthorizeEndpoint, request.GrantType) {
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid response_type")
	}

	// check if PKCE is required and validate parameters
	if request.GrantType == gois.GrantTypeAuthorizationCode || request.GrantType == gois.GrantTypeHybrid {
		// validate code_challenge and code_challenge_method
		result := v.validatePkceParameters(request)

		if result.Error != nil {
			return result
		}
	}

	// check response_mode parameter and set response_mode

	// check if response_mode parameter is present and valid
	responseMode := request.Raw.Get(gois.AuthorizeRequestResponseMode)
	v.logger.Debug("responseMode", slog.String("responseMode", responseMode))
	if strings.TrimSpace(responseMode) != "" {
		if utils.Contains(gois.SupportedResponseModes, responseMode) {
			if utils.Contains(gois.AllowedResponseModesForGrantType[request.GrantType], responseMode) {
				request.ResponseMode = responseMode
			} else {
				return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid response_mode for response_type")
			}
		} else {
			return invalid(request, gois.AuthorizeErrorsUnsupportedResponseType, "Invalid response_mode")
		}
	}

	// check if grant type is allowed for client
	if !utils.Contains(request.Client.AllowedGrantTypes(), request.GrantType) {
		return invalid(request, gois.AuthorizeErrorsUnauthorizedClient, "Invalid grant type  for client")
	}

	// check if response type contains an access token,
	// and if client is allowed to request access token via browser
	if utils.Contains(strings.Split(responseType, " "), gois.ResponseTypesToken) {
		if !request.Client.AllowAccessTokensViaBrowser {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Client not configured to receive access tokens via browser")
		}
	}

	return valid(request)
}

func (v *AuthorizeRequestValidator) validatePkceParameters(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	codeChallenge := request.Raw.Get(gois.AuthorizeRequestCodeChallenge)
	if strings.TrimSpace(codeChallenge) == "" {
		if request.Client.RequirePkce {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "code challenge required")
		}

		return valid(request)
	}

	if len(codeChallenge) < v.options.InputLengthRestrictions.CodeChallengeMinLength ||
		len(codeChallenge) > v.options.InputLengthRestrictions.CodeChallengeMaxLength {
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid code_challenge")
	}

	request.CodeChallenge = codeChallenge

	codeChallengeMethod := request.Raw.Get(gois.AuthorizeRequestCodeChallengeMethod)
	if strings.TrimSpace(codeChallengeMethod) == "" {
		codeChallengeMethod = gois.CodeChallengeMethodsPlain

	}
	if !utils.Contains(gois.SupportedCodeChallengeMethods, codeChallengeMethod) {
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Transform algorithm not supported")
	}

	// check if plain method is allowed
	if codeChallengeMethod == gois.CodeChallengeMethodsPlain {
		if !request.Client.AllowPlainTextPkce {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Transform algorithm not supported")
		}
	}

	request.CodeChallengeMethod = codeChallengeMethod

	return valid(request)
}
func (v *AuthorizeRequestValidator) validateScopeAndResource(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	// scope must be present
	scope := request.Raw.Get(gois.AuthorizeRequestScope)
	if strings.TrimSpace(scope) == "" {
		v.logger.Debug("scope is empty")
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid scope")
	}

	if len(scope) > v.options.InputLengthRestrictions.Scope {
		v.logger.Debug("scope is too long")
		return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid scope")
	}

	request.RequestedScopes = utils.Distinct(strings.Split(scope, " "))
	request.IsOpenIdRequest = utils.Contains(request.RequestedScopes, gois.StandardScopesOpenId)

	// check scope vs response_type plausability
	requirement := gois.ResponseTypeToScopeRequirement[request.ResponseType]
	if requirement == gois.ScopeRequirementIdentity ||
		requirement == gois.ScopeRequirementIdentityOnly {
		if !request.IsOpenIdRequest {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Missing openid scope")
		}
	}

	// check for resource gaps and valid format
	resourceIndicators := request.Raw[gois.AuthorizeRequestResource]
	if utils.AnyPred(resourceIndicators, func(x string) bool {
		return len(x) > v.options.InputLengthRestrictions.ResourceGapMaxLength
	}) {
		return invalid(request, gois.AuthorizeErrorsInvalidTarget, "Resource indicator maximum length exceeded")
	}

	if !utils.AreValidResourceGapFormat(resourceIndicators) {
		return invalid(request, gois.AuthorizeErrorsInvalidTarget, "Invalid resource gap format")
	}

	// we don't want to allow resource gaps when "token" is requested to authorize endpoint
	if utils.Any(resourceIndicators) && request.GrantType == gois.GrantTypeImplicit {
		// todo: correct error?
		return invalid(request, gois.AuthorizeErrorsInvalidTarget, "Resource indicators not allowed for response_type 'token'.")
	}

	request.RequestedResourceIndiators = resourceIndicators

	// check if scopes are valid/supported and check for resource scopes
	validatedResources, err := v.resourceValidator.ValidateRequestedResources(&validators_models.ResourceValidationRequest{
		Client:                         request.Client,
		Scopes:                         request.RequestedScopes,
		ResourceGaps:                   resourceIndicators,
		IncludeNonIsolatedApiResources: utils.Contains(request.RequestedScopes, gois.StandardScopesOfflineAccess),
	})
	if err != nil {
		return invalid(request, gois.AuthorizeErrorsInvalidTarget, err.Error())
	}

	if !validatedResources.Succeeded() {
		if utils.Any(validatedResources.InvalidResourceGaps) {
			return invalid(request, gois.AuthorizeErrorsInvalidTarget, "Invalid resource gap")
		}

		if utils.Any(validatedResources.InvalidScopes) {
			v.logger.Debug("invalid scope", slog.String("scope", strings.Join(validatedResources.InvalidScopes, ", ")))
			return invalid(request, gois.AuthorizeErrorsInvalidScope, "Invalid scope")
		}
	}

	if utils.Any(validatedResources.Resources.IdentityResources()) && !request.IsOpenIdRequest {
		return invalid(request, gois.AuthorizeErrorsInvalidScope, "Identity scopes requested, but openid scope is missing")
	}

	if utils.Any(validatedResources.Resources.ApiScopes()) {
		request.IsApiResourceRequest = true
	}

	// check id vs resource scopes and response types plausability
	responseTypeValidationCheck := true
	identityResourcesAny := utils.Any(validatedResources.Resources.IdentityResources())
	apiScopesAny := utils.Any(validatedResources.Resources.ApiScopes())

	switch requirement {
	case gois.ScopeRequirementIdentity:
		if !identityResourcesAny {
			responseTypeValidationCheck = false
		}
	case gois.ScopeRequirementIdentityOnly:
		if !identityResourcesAny || apiScopesAny {
			responseTypeValidationCheck = false
		}
	case gois.ScopeRequirementResourceOnly:
		if identityResourcesAny || !apiScopesAny {
			responseTypeValidationCheck = false
		}
	}

	if !responseTypeValidationCheck {
		return invalid(request, gois.AuthorizeErrorsInvalidScope, "Invalid scope for response type")
	}

	request.ValidatedResources = validatedResources

	return valid(request)
}

func (v *AuthorizeRequestValidator) validateOptionalParameters(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	// check nonce
	nonce := request.Raw.Get(gois.AuthorizeRequestNonce)
	if strings.TrimSpace(nonce) != "" {
		if len(nonce) > v.options.InputLengthRestrictions.Nonce {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid nonce")
		}

		request.Nonce = nonce

	} else {
		if utils.Contains(strings.Split(request.ResponseType, " "), gois.TokenTypesIdentityToken) {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid nonce")
		}
	}

	// check prompt
	prompt := request.Raw.Get(gois.AuthorizeRequestPrompt)
	if strings.TrimSpace(prompt) != "" {
		prompts := strings.Split(prompt, " ")
		if utils.All(prompts, func(p string) bool {
			return utils.Contains(gois.SupportedPromptModes, p)
		}) {
			if utils.Contains(prompts, gois.PromptModesNone) && len(prompts) > 1 {
				return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid prompt")
			}

			request.OriginalPromptModes = prompts
		}
	}

	suppressedPrompt := request.Raw.Get(gois.SuppressedPrompt)
	if strings.TrimSpace(suppressedPrompt) != "" {
		prompts := strings.Split(suppressedPrompt, " ")
		if utils.All(prompts, func(p string) bool {
			return utils.Contains(gois.SupportedPromptModes, p)
		}) {
			if utils.Contains(prompts, gois.PromptModesNone) && len(prompts) > 1 {
				return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid prompt")
			}

			request.SuppressedPromptModes = prompts
		}
	}

	request.PromptModes = utils.Except(request.OriginalPromptModes, request.SuppressedPromptModes)

	// check ui locales
	uilocales := request.Raw.Get(gois.AuthorizeRequestUiLocales)
	if strings.TrimSpace(uilocales) != "" {
		if len(uilocales) > v.options.InputLengthRestrictions.UiLocale {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid ui_locales")
		}

		request.UiLocales = uilocales
	}

	// check display
	display := request.Raw.Get(gois.AuthorizeRequestDisplay)
	if strings.TrimSpace(display) != "" {
		if utils.Contains(gois.SupportedDisplayModes, display) {
			request.DisplayMode = display
		}
	}

	// check max_age
	maxAge := request.Raw.Get(gois.AuthorizeRequestMaxAge)
	if strings.TrimSpace(maxAge) != "" {
		if seconds, err := strconv.ParseInt(maxAge, 10, 64); err == nil && seconds >= 0 {
			request.MaxAge = int(seconds)
		} else {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid max_age")
		}
	}

	// check login_hint
	loginHint := request.Raw.Get(gois.AuthorizeRequestLoginHint)
	if strings.TrimSpace(loginHint) != "" {
		if len(loginHint) > v.options.InputLengthRestrictions.LoginHint {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid login_hint")
		}
		request.LoginHint = loginHint
	}

	// check acr_values
	acrValues := request.Raw.Get(gois.AuthorizeRequestAcrValues)
	if strings.TrimSpace(acrValues) != "" {
		if len(acrValues) > v.options.InputLengthRestrictions.AcrValues {
			return invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid acr_values")
		}

		request.AuthenticationContextReferenceClasses = utils.Distinct(strings.Split(acrValues, " "))
	}

	// check custom acr_values: idp
	idp := request.GetIdP()
	if strings.TrimSpace(idp) != "" {
		// if idp is present but client does not allow it, strip it from the request message
		if request.Client.IdentityProviderRestrictions != nil {
			idps := request.Client.IdentityProviderRestrictions
			if utils.Any(idps) {
				if !utils.Contains(idps, idp) {
					request.RemoveIdP()
				}
			}
		}
	}

	// check session cookie
	if v.options.Endpoints.EnableCheckSessionEndpoint {
		sessionId := ""
		// TODO: 是否可优化？ golang 对 interface 参数判断是否为空的，需要明确赋 nil
		var user gois.Principal
		if request.Subject == nil {
			user = nil
		} else {
			user = request.Subject
		}

		if extensions.ClaimsPrincipalIsAuthenticated(user) {
			// sessionId = v.httpContextAccessor.UserSession().GetSessionId()
			sessionId = v.userSession.GetSessionId()
			if sessionId != "" {
				request.SessionId = sessionId
			}
		} else {
			request.SessionId = sessionId // empty string for anonymous users
		}
	}

	return valid(request)
}

func valid(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	return validators_models.NewAuthorizeRequestValidationResult(request)
}

func invalid(request *validators_models.ValidatedAuthorizeRequest, err error, description string) *validators_models.AuthorizeRequestValidationResult {
	return validators_models.NewAuthorizeRequestValidationResultWithErr(request, err, description)
}
