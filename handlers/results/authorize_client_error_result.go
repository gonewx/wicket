// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"net/http"

	responses_models "github.com/gonewx/wicket/responses/models"
)

// AuthorizeClientErrorResult answers an authorize request with an error that
// is always delivered to the client's redirect URI in the request's response
// mode, carrying state and, when configured, iss, rather than the error page.
type AuthorizeClientErrorResult struct {
	*AuthorizeResult
}

// NewAuthorizeClientErrorResult wraps the error response delivered to the
// client.
func NewAuthorizeClientErrorResult(response *responses_models.AuthorizeResponse) *AuthorizeClientErrorResult {
	return &AuthorizeClientErrorResult{AuthorizeResult: NewAuthorizeResult(response)}
}

func (r *AuthorizeClientErrorResult) Execute(w http.ResponseWriter, req *http.Request) error {
	r.init(req.Context())
	return r.ProcessResponse(w, req)
}
