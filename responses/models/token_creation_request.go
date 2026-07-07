// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"errors"

	"github.com/gonewx/wicket/claims"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// From: IdentityServer4/src/IdentityServer/Models/TokenCreationRequest.cs
// should be placed in the mudule

// TokenCreationRequest Models the data to create a token from a validated request.
type TokenCreationRequest struct {
	// Gets or sets the subject.
	Subject *claims.ClaimsPrincipal

	// Gets or sets the validated resources.
	ValidatedResources *validators_models.ResourceValidationResult

	// Gets or sets the validated request.
	ValidatedRequest *validators_models.ValidatedRequest

	// Gets or sets a value indicating whether [include all identity claims.].
	IncludeAllIdentityClaims bool

	// Gets or sets the access token to hash.
	AccessTokenToHash string

	// Gets or sets the authorization code to hash.
	AuthorizationCodeToHash string

	// Gets or sets pre-hashed state
	StateHash string

	// Gets or sets the nonce.
	Nonce string

	// Gets the description the user assigned to the device being authorized.
	Description string
}

// Called to validate the <see cref="TokenCreationRequest"/> before it is processed.
func (r *TokenCreationRequest) Validate() error {
	if r.ValidatedResources == nil {
		return errors.New("validated resources is required")
	}
	if r.ValidatedRequest == nil {
		return errors.New("validated request is required")
	}
	return nil
}
