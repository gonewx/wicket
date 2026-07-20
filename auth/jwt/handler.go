// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package jwt

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/core"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/services"
)

const (
	HeaderValueNoCache        = "no-cache"
	HeaderValueNoCacheNoStore = "no-cache,no-store"
	HeaderValueEpocDate       = "Thu, 01 Jan 1970 00:00:00 GMT"
	SessionIdClaim            = "Microsoft.AspNetCore.Authentication.Cookies-SessionId"
)

type Handler struct {
	*core.Handler[*Options]

	// config *openid.OpenIdConnectConfig
}

func NewHandler(
	// ctxAccessor accessor.HttpContextAccessor,
	optionsMonitor optspkg.OptionsMonitor[*Options],
	logger *slog.Logger,
	clock services.SystemClock,
) *Handler {
	h := &Handler{}

	h.Handler = core.NewHandler(optionsMonitor, logger, clock, h).(*core.Handler[*Options])

	return h
}

// / The handler calls methods on the events which give the application control at certain points where processing is occurring.
func (h *Handler) Events() *Events {
	return h.Handler.Events.(*Events)
}

func (h *Handler) SetEvents(e *Events) {
	h.Handler.Events = e
}

// CreateEvents Creates a new instance of the events instance.
func (h *Handler) CreateEvents() any {
	return NewEvents()
}

// HandleAuthenticate Searches the 'Authorization' header for a 'Bearer' token. If the 'Bearer' token is found, it is validated using TokenValidationParameters set in the options.
func (h *Handler) HandleAuthenticate() (*auth.Result, error) {
	token := ""

	r, w := h.Request(), h.Response()

	// Give application opportunity to find from a different location, adjust, or reject token
	messageReceivedContext := NewMessageReceivedContext(r, w, h.Scheme, h.Options)

	// event can set the token
	err := h.Events().MessageReceived(messageReceivedContext)
	if err != nil {
		return nil, err
	}

	if messageReceivedContext.Result != nil {
		return messageReceivedContext.Result, nil
	}

	// If application retrieved token from somewhere else, use that.
	token = messageReceivedContext.Token

	if strings.TrimSpace(token) == "" {
		authorization := r.Header.Get("Authorization")

		// If no authorization header found, nothing to process further
		if strings.TrimSpace(authorization) == "" {
			return auth.NoResult(), nil
		}

		if strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
			token = authorization[len("bearer "):]
		}

		// If no token found, no further work possible
		if strings.TrimSpace(token) == "" {
			return auth.NoResult(), nil
		}
	}

	//Note: Don't use configuration manager

	// Wire the injected clock into the validation parameters when the caller left
	// it unset, so lifetime checks honor the same clock as the rest of the auth
	// stack rather than jwx's wall clock. A shallow copy keeps the shared options
	// singleton unmutated across concurrent requests.
	validationParameters := h.Options.TokenValidationParameters
	if validationParameters != nil && validationParameters.Clock == nil && h.Clock != nil {
		effective := *validationParameters
		effective.Clock = h.Clock
		validationParameters = &effective
	}

	for _, validator := range h.Options.SecurityTokenValidators {
		if validator.CanReadToken(token) {
			principal, validatedToken, err := validator.ValidateToken(token, validationParameters)
			if err != nil {
				h.Logger.Debug("validator.ValidateToken failed: ", slog.String("err", err.Error()))
				continue
			}

			if principal == nil {
				return auth.NoResult(), nil
			}

			tokenValidatedContext := NewTokenValidatedContext(r, w, h.Scheme, h.Options)
			tokenValidatedContext.SetSecurityToken(validatedToken)
			tokenValidatedContext.Principal = principal

			validTo := validatedToken.ValidTo()
			tokenValidatedContext.Properties().SetExpires(&validTo)
			validFrom := validatedToken.ValidFrom()
			tokenValidatedContext.Properties().SetIssued(&validFrom)

			err = h.Events().TokenValidated(tokenValidatedContext)
			if err != nil {
				continue
			}

			if tokenValidatedContext.Result != nil {
				return tokenValidatedContext.Result, nil
			}

			if h.Options.SaveToken {
				_ = auth.StoreTokens(
					tokenValidatedContext.Properties(),
					[]*auth.Token{
						{
							Name:  "access_token",
							Value: token,
						},
					},
				)
			}

			tokenValidatedContext.Success()
			return tokenValidatedContext.Result, nil
		}
	}

	return auth.Fail(fmt.Errorf("No SecurityTokenValidator available for token.")), nil
}
