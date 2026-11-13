// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"net/http"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/validators"
)

// BackchannelAuthenticationHandler serves the CIBA backchannel authentication
// endpoint.
//
// A handler that holds options enforces
// Endpoints.EnableBackchannelAuthenticationEndpoint: while the switch is off it
// answers 404 to every request. A handler without options does not look at the
// switch and always serves.
type BackchannelAuthenticationHandler struct {
	clientValidator  validators.ClientSecretValidator
	requestValidator validators.BackchannelAuthenticationRequestValidator
	options          *config_options.WicketOptions
}

// NewBackchannelAuthenticationHandler builds a backchannel authentication
// handler that holds no options. It does not enforce
// Endpoints.EnableBackchannelAuthenticationEndpoint and serves whatever the
// switch says; use NewBackchannelAuthenticationHandlerWithOptions for a handler
// that honors the switch.
func NewBackchannelAuthenticationHandler(clientValidator validators.ClientSecretValidator, requestValidator validators.BackchannelAuthenticationRequestValidator) *BackchannelAuthenticationHandler {
	return NewBackchannelAuthenticationHandlerWithOptions(clientValidator, requestValidator, nil)
}

// NewBackchannelAuthenticationHandlerWithOptions builds a backchannel
// authentication handler that holds options and enforces
// Endpoints.EnableBackchannelAuthenticationEndpoint: while the switch is off
// the handler answers 404 to every request. The switch is read on each request.
// Nil options leave the endpoint on.
func NewBackchannelAuthenticationHandlerWithOptions(
	clientValidator validators.ClientSecretValidator,
	requestValidator validators.BackchannelAuthenticationRequestValidator,
	options *config_options.WicketOptions,
) *BackchannelAuthenticationHandler {
	return &BackchannelAuthenticationHandler{
		clientValidator:  clientValidator,
		requestValidator: requestValidator,
		options:          options,
	}
}

func (h *BackchannelAuthenticationHandler) Process(w http.ResponseWriter, r *http.Request) error {
	// A switched-off endpoint answers as if it did not exist, whatever the
	// request looks like, and before anything of the request is read.
	if h.options != nil && !h.options.Endpoints.EnableBackchannelAuthenticationEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}
	if err := r.ParseForm(); err != nil {
		return results.NewBadRequestResult(wicket.TokenErrorsInvalidRequest, "").Execute(w, r)
	}
	clientResult := h.clientValidator.Validate(r)
	if clientResult == nil || clientResult.Error != nil {
		err := wicket.TokenErrorsInvalidClient
		if clientResult != nil && clientResult.Error != nil {
			err = clientResult.Error
		}
		return results.NewBadRequestResult(err, "").Execute(w, r)
	}
	result := h.requestValidator.Validate(r.Context(), r.Form, clientResult.Client)
	if result.Error != nil {
		return results.NewBadRequestResult(result.Error, result.Description).Execute(w, r)
	}
	results.HttpRespSetNoCache(w)
	response := map[string]any{
		"auth_req_id": result.Request.RequestId,
		"expires_in":  result.ExpiresIn,
	}
	if result.Interval > 0 {
		response["interval"] = result.Interval
	}
	return results.HttpRespWriteJson(w, response, "")
}
