// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"strings"

	validators_models "github.com/gonewx/wicket/validators/models"
)

type AuthorizeResponse struct {
	Request             *validators_models.ValidatedAuthorizeRequest
	IsLogin             bool
	IsConsent           bool
	IdentityToken       string
	AccessToken         string
	AccessTokenLifetime int
	Code                string
	SessionState        string
	Issuer              string
	Error               error
	ErrorDescription    string
}

func NewAuthorizeResponse() *AuthorizeResponse {
	return &AuthorizeResponse{
		Request: validators_models.NewValidatedAuthorizeRequest(),
	}
}

func (r *AuthorizeResponse) IsRedirect() bool {
	return strings.TrimSpace(r.RedirectUri()) != ""
}

func (r *AuthorizeResponse) RedirectUri() string {
	if r.Request == nil {
		return ""
	}
	return r.Request.RedirectUri
}

func (r *AuthorizeResponse) State() string {
	if r.Request == nil {
		return ""
	}
	return r.Request.State
}

func (r *AuthorizeResponse) Scope() string {
	if r.Request == nil || r.Request.ValidatedResources == nil {
		return ""
	}

	values := r.Request.ValidatedResources.RawScopeValues()
	return strings.Join(values, " ")
}
