// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"fmt"
	"log/slog"
	"net/url"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	"github.com/gonewx/wicket/validators/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// EndSessionRequestValidator  Validates end session requests.
type EndSessionRequestValidator struct {
	logger                    *slog.Logger
	options                   *config_options.IdentityServerOptions
	TokenValidator            validators.TokenValidator
	UriValidator              validators.RedirectUriValidator
	UserSession               services.UserSession
	LogoutNotificationService services.LogoutNotificationService
	EndSessionMessageStore    storage.MessageStore[contexts.LogoutNotificationContext]
}

func NewEndSessionRequestValidator(
	logger *slog.Logger,
	options *config_options.IdentityServerOptions,
	tokenValidator validators.TokenValidator,
	uriValidator validators.RedirectUriValidator,
	userSession services.UserSession,
	logoutNotificationService services.LogoutNotificationService,
	endSessionMessageStore storage.MessageStore[contexts.LogoutNotificationContext],
) *EndSessionRequestValidator {
	return &EndSessionRequestValidator{
		logger:                    logger,
		options:                   options,
		TokenValidator:            tokenValidator,
		UriValidator:              uriValidator,
		UserSession:               userSession,
		LogoutNotificationService: logoutNotificationService,
		EndSessionMessageStore:    endSessionMessageStore,
	}
}

// Validates end session endpoint requests.
func (v *EndSessionRequestValidator) Validate(parameters url.Values, subject *claims.ClaimsPrincipal) (*validators_models.EndSessionValidationResult, error) {
	v.logger.Debug("Start validating end session request.")

	// TODO: 是否可优化？ golang 对 interface 参数判断是否为空的，需要明确赋 nil
	var user gois.Principal
	if subject == nil {
		user = nil
	} else {
		user = subject
	}
	isAuthenticated := extensions.ClaimsPrincipalIsAuthenticated(user)

	if !isAuthenticated && v.options.Authentication.RequireAuthenticatedUserForSignOutMessage {
		return v.invalid("User is anonymous. Ignoring end session parameters", nil), nil
	}

	validatedRequest := &validators_models.ValidatedEndSessionRequest{
		ValidatedRequest: &validators_models.ValidatedRequest{
			Raw: parameters,
		},
	}

	idTokenHint := parameters.Get(gois.EndSessionRequestIdTokenHint)

	if idTokenHint != "" {
		// validate id_token - no need to validate token life time
		tokenValidationResult := v.TokenValidator.ValidateIdentityToken(idTokenHint, "", false)

		validatedRequest.SetClient(tokenValidationResult.Client, nil, "")

		// validate sub claim against currently logged on user
		subClaim := utils.FirstOrDefaultPred(tokenValidationResult.Claims, func(c *claims.Claim) bool { return c.Type == gois.JwtClaimTypesSubject })
		if subClaim != nil && isAuthenticated {
			if extensions.GetSubjectIdFromPrincipal(user) != subClaim.Value {
				return v.invalid("Current user does not match identity token", validatedRequest), nil
			}

			id := v.UserSession.GetSessionId()
			validatedRequest.Subject = subject
			validatedRequest.SessionId = id

			clintList, err := v.UserSession.GetClientList()
			if err != nil {
				return nil, err
			}
			validatedRequest.ClientIds = clintList
		}

		redirectUri := parameters.Get(gois.EndSessionRequestPostLogoutRedirectUri)
		if redirectUri != "" {
			if v.UriValidator.IsPostLogoutRedirectUriValid(redirectUri, tokenValidationResult.Client) {
				validatedRequest.PostLogOutUri = redirectUri
			} else {
				v.logger.Warn("Invalid PostLogoutRedirectUri", slog.String("postLogoutRedirectUri", redirectUri))
			}
		}

		if validatedRequest.PostLogOutUri != "" {
			state := parameters.Get(gois.EndSessionRequestState)
			if state != "" {
				validatedRequest.State = state
			}
		}
	} else {
		// no id_token to authenticate the client, but we do have a user and a user session
		id := v.UserSession.GetSessionId()
		validatedRequest.Subject = subject
		validatedRequest.SessionId = id

		clientList, err := v.UserSession.GetClientList()
		if err != nil {
			return nil, err
		}

		validatedRequest.ClientIds = clientList
	}

	uilocales := parameters.Get(gois.EndSessionRequestUiLocales)
	if uilocales != "" {
		if len(uilocales) > v.options.InputLengthRestrictions.UiLocale {
			v.logger.Warn("UI locale too long. It will be ignored.", slog.Any("request", validatedRequest))
		} else {
			validatedRequest.UiLocales = uilocales
		}
	}

	v.logger.Info("End session request validation success", slog.Any("request", validatedRequest))

	return v.valid(validatedRequest), nil
}

// Validates requests from logout page iframe to trigger single signout.
func (v *EndSessionRequestValidator) ValidateCallback(parameters url.Values) (*validators_models.EndSessionCallbackValidationResult, error) {
	result := models.NewEndSessionCallbackValidationResult()

	endSessionId := parameters.Get(gois.UIConstantsDefaultRoutePathParamsEndSessionCallback)
	endSessionMessage, err := v.EndSessionMessageStore.Read(endSessionId)

	if err != nil || endSessionMessage == nil || endSessionMessage.Data == nil || len(endSessionMessage.Data.ClientIds) == 0 {
		result.Error = fmt.Errorf("Failed to read end session callback message")
		return result, nil
	}

	result.FrontChannelLogoutUrls, err = v.LogoutNotificationService.GetFrontChannelLogoutNotificationsUrls(endSessionMessage.Data)
	if err != nil {
		result.Error = fmt.Errorf("Failed to get front channel logout urls")
	}

	return result, nil
}

func (v *EndSessionRequestValidator) invalid(message string, request *validators_models.ValidatedEndSessionRequest) *validators_models.EndSessionValidationResult {
	message = "End session request validation failed: " + message
	result := models.NewEndSessionValidationResult()

	if request != nil {
		v.logger.Info(message, slog.Any("request", request))
	} else {
		v.logger.Info(message)
	}

	result.Error = fmt.Errorf("Invalid request")
	result.Description = message
	return result
}

func (v *EndSessionRequestValidator) valid(request *validators_models.ValidatedEndSessionRequest) *validators_models.EndSessionValidationResult {
	r := validators_models.NewEndSessionValidationResult()
	r.ValidatedRequest = request

	return r
}
