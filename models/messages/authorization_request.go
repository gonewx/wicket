// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

import (
	"net/url"

	"github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// Represents contextual information about a authorization request.
type AuthorizationRequest struct {
	// The client.
	Client *storage_models.Client

	// The display mode passed from the authorization request.
	DisplayMode string

	// Gets or sets the redirect URI.
	RedirectUri string

	// The UI locales passed from the authorization request.
	UiLocales string

	// The external identity provider requested. This is used to bypass home realm
	// discovery (HRD). This is provided via the "idp:" prefix to the acr
	// parameter on the authorize request.
	// The external identity provider identifier.
	IdP string

	// The tenant requested. This is provided via the "tenant:" prefix to
	// the acr parameter on the authorize request.
	// The tenant.
	Tenant string

	// The expected username the user will use to login. This is requested from the client
	// via the login_hint parameter on the authorize request.
	// The LoginHint.
	LoginHint string

	// Gets or sets the collection of prompt modes.
	// The collection of prompt modes.
	PromptModes []string

	// The acr values passed from the authorization request.
	// The acr values.
	AcrValues []string

	// The validated resources.
	ValidatedResources *validators_models.ResourceValidationResult

	// Gets the entire parameter collection.
	// The parameters.
	Parameters url.Values

	// Gets the validated contents of the request object (if present)
	// The request object values
	RequestObjectValues []*claims.Claim
}

// Initializes a new instance of the AuthorizationRequest".
// request Authorized request validated parameters
func NewAuthorizationRequest(request *validators_models.ValidatedAuthorizeRequest) *AuthorizationRequest {
	r := &AuthorizationRequest{}
	r.Client = request.Client
	r.RedirectUri = request.RedirectUri
	r.DisplayMode = request.DisplayMode
	r.UiLocales = request.UiLocales
	r.IdP = request.GetIdP()
	r.Tenant = request.GetTenant()
	r.LoginHint = request.LoginHint
	// this allows the UI to see the original prompt modes
	r.PromptModes = request.OriginalPromptModes
	r.AcrValues = request.GetAcrValues()
	r.ValidatedResources = request.ValidatedResources
	r.Parameters = request.Raw
	r.RequestObjectValues = request.RequestObjectValues

	return r
}
