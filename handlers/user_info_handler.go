// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

// UserInfoHandler serves the OpenID Connect userinfo endpoint over bearer
// authentication and, once SetDPoP was called, DPoP authentication.
type UserInfoHandler struct {
	bearerValidator  *validators_impl.BearerTokenUsageValidator
	requestValidator validators.UserInfoRequestValidator
	generator        responses.UserInfoResponseGenerator
	options          *config_options.WicketOptions
	logger           *slog.Logger
	certificates     ClientCertificateSource
	// dpop is set by SetDPoP; nil leaves the DPoP scheme unrecognized.
	dpop *userInfoDPoP
}

func NewUserInfoHandler(
	bearerValidator *validators_impl.BearerTokenUsageValidator,
	requestValidator validators.UserInfoRequestValidator,
	generator responses.UserInfoResponseGenerator,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *UserInfoHandler {
	return &UserInfoHandler{
		bearerValidator:  bearerValidator,
		requestValidator: requestValidator,
		generator:        generator,
		options:          options,
		logger:           logger,
	}
}

func (h *UserInfoHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !h.options.Endpoints.EnableUserInfoEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	if h.dpop != nil {
		if token, found, malformed := dpopAuthorization(r); found {
			return h.processDPoP(w, r, token, malformed)
		}
	}

	usage, err := h.bearerValidator.Validate(r)
	if err != nil {
		return results.NewProtectedResourceErrorResult(wicket.ProtectedResourceErrorsInvalidRequest, "").Execute(w, r)
	}
	if usage == nil || !usage.TokenFound {
		return results.NewProtectedResourceErrorResult(wicket.ProtectedResourceErrorsInvalidToken, "").Execute(w, r)
	}

	validationResult, err := h.requestValidator.ValidateRequest(r.Context(), usage.Token)
	if err != nil {
		return fmt.Errorf("validate userinfo request: %w", err)
	}
	if validationResult.Error != nil {
		return results.NewProtectedResourceErrorResult(validationResult.Error, validationResult.Description).Execute(w, r)
	}
	if validationResult.TokenValidationResult != nil {
		if written, err := h.rejectBoundBearer(w, r, validationResult.TokenValidationResult.Claims); written {
			return err
		}
		if err := h.checkCertificateBinding(r, validationResult.TokenValidationResult.Claims); err != nil {
			return results.NewProtectedResourceErrorResult(wicket.ProtectedResourceErrorsInvalidToken, "").Execute(w, r)
		}
	}

	claims, err := h.generator.Handle(r.Context(), validationResult)
	if err != nil {
		return fmt.Errorf("generate userinfo response: %w", err)
	}

	return results.NewUserInfoResult(claims).Execute(w, r)
}
