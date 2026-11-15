// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/validators"
)

// TokenHandler serves the token endpoint. It authenticates the client, validates
// the grant, and issues the token response. Protocol failures are written as
// 400 JSON error responses; only an unrecoverable infrastructure fault is
// returned as an error.
//
// A handler that holds options enforces Endpoints.EnableTokenEndpoint: while
// the switch is off it answers 404 to every request. A handler without options
// does not look at the switch and always serves.
type TokenHandler struct {
	clientValidator  validators.ClientSecretValidator
	requestValidator validators.TokenRequestValidator
	generator        responses.TokenResponseGenerator
	options          *config_options.WicketOptions
	logger           *slog.Logger

	// dpop is set by SetDPoP; nil leaves the DPoP header unread.
	dpop *tokenDPoP
}

// NewTokenHandler builds a token handler that holds no options. It does not
// enforce Endpoints.EnableTokenEndpoint and serves whatever the switch says;
// use NewTokenHandlerWithOptions for a handler that honors the switch.
func NewTokenHandler(
	clientValidator validators.ClientSecretValidator,
	requestValidator validators.TokenRequestValidator,
	generator responses.TokenResponseGenerator,
	logger *slog.Logger,
) *TokenHandler {
	return NewTokenHandlerWithOptions(clientValidator, requestValidator, generator, nil, logger)
}

// NewTokenHandlerWithOptions builds a token handler that holds options and
// enforces Endpoints.EnableTokenEndpoint: while the switch is off the handler
// answers 404 to every request. The switch is read on each request. Nil
// options leave the endpoint on.
func NewTokenHandlerWithOptions(
	clientValidator validators.ClientSecretValidator,
	requestValidator validators.TokenRequestValidator,
	generator responses.TokenResponseGenerator,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *TokenHandler {
	return &TokenHandler{
		clientValidator:  clientValidator,
		requestValidator: requestValidator,
		generator:        generator,
		options:          options,
		logger:           logger,
	}
}

func (h *TokenHandler) Process(w http.ResponseWriter, r *http.Request) error {
	// A switched-off endpoint answers as if it did not exist, whatever the
	// request looks like, and before anything of the request is read.
	if h.options != nil && !h.options.Endpoints.EnableTokenEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}
	if err := r.ParseForm(); err != nil {
		return results.NewBadRequestResult(wicket.TokenErrorsInvalidRequest, "").Execute(w, r)
	}
	// Reject bodies whose parameters carry a control byte the form reader accepts
	// but downstream token handling must not process. This is the token
	// endpoint's parse defense against a malformed form payload.
	if formHasControlBytes(r.Form) {
		return results.NewBadRequestResult(wicket.TokenErrorsInvalidRequest, "").Execute(w, r)
	}

	// Every stateless check of a DPoP proof runs before anything changes
	// state, the registration of a client assertion included.
	var proof *dpop.Proof
	if h.dpop != nil {
		accepted, err := h.dpop.verifyProof(r)
		if err != nil {
			h.logProofRejection(err.Error())
			return writeInvalidDPoPProof(w, r)
		}
		proof = accepted
	}

	clientResult := h.clientValidator.Validate(r)
	if clientResult != nil && errors.Is(clientResult.Error, clientassertion.ErrAuthenticationUnavailable) {
		writeClientAuthenticationUnavailable(w)
		return nil
	}
	if clientResult == nil || clientResult.Error != nil {
		response := responses_models.NewTokenErrorResponse()
		response.Error = wicket.TokenErrorsInvalidClient
		if clientResult != nil && clientResult.Error != nil {
			response.Error = clientResult.Error
			response.ErrorDescription = clientResult.Description
		}
		return results.NewTokenErrorResult(response).Execute(w, r)
	}

	// The proof identifier is registered once the client is known and
	// before any grant is redeemed; the proof key thumbprint then travels
	// down the context to the validator and the token services.
	ctx := r.Context()
	if h.dpop != nil {
		if written, err := h.enforceAndRegister(w, r, clientResult.Client, proof); written || err != nil {
			return err
		}
		if proof != nil {
			ctx = dpop.WithProof(ctx, proof.Thumbprint)
		}
	}

	validation, err := h.requestValidator.ValidateRequest(ctx, r.Form, clientResult)
	if err != nil {
		return fmt.Errorf("validate token request: %w", err)
	}
	if validation.Error != nil {
		response := responses_models.NewTokenErrorResponse()
		response.Error = validation.Error
		response.ErrorDescription = validation.Description
		if validation.CustomResponse != nil {
			response.Custom = validation.CustomResponse
		}
		return results.NewTokenErrorResult(response).Execute(w, r)
	}

	response, err := h.generator.Handle(ctx, validation)
	if err != nil {
		// Prefer failing to the client: a recognized standard token error is
		// written as a 400 error response; an unrecognized error cannot be
		// expressed as a protocol error and is treated as an infrastructure fault.
		if protocol := asTokenProtocolError(err); protocol != nil {
			errorResponse := responses_models.NewTokenErrorResponse()
			errorResponse.Error = protocol
			return results.NewTokenErrorResult(errorResponse).Execute(w, r)
		}
		return fmt.Errorf("create token response: %w", err)
	}

	if proof != nil {
		response.TokenType = wicket.TokenResponseTypesDPoP
	}
	return results.NewTokenResult(response).Execute(w, r)
}

// formHasControlBytes reports whether any parameter name or value contains a NUL
// byte.
func formHasControlBytes(values url.Values) bool {
	for key, entries := range values {
		if strings.ContainsRune(key, 0) {
			return true
		}
		for _, entry := range entries {
			if strings.ContainsRune(entry, 0) {
				return true
			}
		}
	}
	return false
}

// asTokenProtocolError returns the matching standard token error when err is one
// the token endpoint may report to the client, or nil when err should be treated
// as an infrastructure fault.
func asTokenProtocolError(err error) error {
	for _, candidate := range []error{
		wicket.TokenErrorsInvalidRequest,
		wicket.TokenErrorsInvalidClient,
		wicket.TokenErrorsInvalidGrant,
		wicket.TokenErrorsUnauthorizedClient,
		wicket.TokenErrorsUnsupportedGrantType,
		wicket.TokenErrorsInvalidScope,
		wicket.TokenErrorsInvalidTarget,
	} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return nil
}
