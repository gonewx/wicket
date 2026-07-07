// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

import (
	"github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
)

type RefreshTokenCreationRequest struct {
	Client                 *storage_models.Client
	Subject                *claims.ClaimsPrincipal
	Description            string
	AuthorizedScopes       []string
	AuthorizedResourceGaps []string
	AccessToken            *storage_models.Token
	RequestedResourceGap   string
}

type RefreshTokenUpdateRequest struct {
	Handle       string
	Client       *storage_models.Client
	RefreshToken *storage_models.RefreshToken
	AccessToken  *storage_models.Token
	MustUpdate   bool
}
