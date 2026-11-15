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

// Execute writes the error as RFC 6749 §5.2 describes it: a JSON object
// with error, error_description when there is one and the custom entries
// beside them, served as application/json and not cached. A custom entry
// never replaces error, and replaces error_description only when the core
// has none. The headers are set before the status is written, since headers
// set afterwards are not sent.
func (ter *TokenErrorResult) Execute(w http.ResponseWriter, r *http.Request) error {
	dto := make(map[string]interface{}, len(ter.Response.Custom)+2)
	for key, value := range ter.Response.Custom {
		dto[key] = value
	}
	dto["error"] = ter.Response.Error.Error()
	if ter.Response.ErrorDescription != "" {
		dto["error_description"] = ter.Response.ErrorDescription
	}

	HttpRespSetNoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	return HttpRespWriteJson(w, dto, "")
}
