// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"

	responses_models "github.com/gonewx/wicket/responses/models"
)

type TokenErrorResult struct {
	Response *responses_models.TokenErrorResponse
}

func NewTokenErrorResult(
	response *responses_models.TokenErrorResponse,
) *TokenErrorResult {
	return &TokenErrorResult{
		Response: response,
	}
}

func (ter *TokenErrorResult) Execute(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusBadRequest)
	HttpRespSetNoCache(w)

	dto := make(map[string]interface{})
	dto["error"] = ter.Response.Error.Error()
	dto["error_description"] = ter.Response.ErrorDescription

	dto["custom"] = ter.Response.Custom

	return HttpRespWriteJson(w, dto, "")
}
