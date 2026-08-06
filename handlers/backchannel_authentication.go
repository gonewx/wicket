// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/validators"
)

type BackchannelAuthenticationHandler struct {
	clientValidator  validators.ClientSecretValidator
	requestValidator validators.BackchannelAuthenticationRequestValidator
}

func NewBackchannelAuthenticationHandler(clientValidator validators.ClientSecretValidator, requestValidator validators.BackchannelAuthenticationRequestValidator) *BackchannelAuthenticationHandler {
	return &BackchannelAuthenticationHandler{clientValidator: clientValidator, requestValidator: requestValidator}
}

func (h *BackchannelAuthenticationHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return results.NewBadRequestResult(gois.TokenErrorsInvalidRequest, "").Execute(w, r)
	}
	clientResult := h.clientValidator.Validate(r)
	if clientResult == nil || clientResult.Error != nil {
		err := gois.TokenErrorsInvalidClient
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
