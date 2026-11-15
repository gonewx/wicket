// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"

	responses_models "github.com/gonewx/wicket/responses/models"
)

type TokenResult struct {
	Response *responses_models.TokenResponse
}

func NewTokenResult(
	response *responses_models.TokenResponse,
) *TokenResult {
	return &TokenResult{
		Response: response,
	}
}

func (tr *TokenResult) Execute(w http.ResponseWriter, r *http.Request) error {
	HttpRespSetNoCache(w)

	dto := make(map[string]interface{})
	dto["id_token"] = tr.Response.IdentityToken
	dto["access_token"] = tr.Response.AccessToken
	dto["refresh_token"] = tr.Response.RefreshToken
	dto["expires_in"] = tr.Response.AccessTokenLifetime
	tokenType := tr.Response.TokenType
	if tokenType == "" {
		tokenType = responses_models.BearerTokenType
	}
	dto["token_type"] = tokenType
	dto["scope"] = tr.Response.Scope

	return HttpRespWriteJson(w, dto, "")
}
