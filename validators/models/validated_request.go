// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"net/url"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
)

type ValidatedRequest struct {
	Raw                 url.Values
	Client              *storage_models.Client
	IssuerName          string
	Secret              *models.ParsedSecret
	AccessTokenLifetime int
	ClientClaims        []*claims.Claim
	AccessTokenType     wicket.AccessTokenType
	Subject             *claims.ClaimsPrincipal
	SessionId           string // empty string for anonymous users
	Options             *config_options.WicketOptions
	ValidatedResources  *ResourceValidationResult
	Confirmation        string
	ClientId            string
}

func NewValidatedRequest() *ValidatedRequest {
	return &ValidatedRequest{
		ValidatedResources: NewResourceValidationResult(),
	}
}

func (r *ValidatedRequest) SetClient(client *storage_models.Client, serect *models.ParsedSecret, confirmation string) {
	r.Client = client
	r.Secret = serect
	r.Confirmation = confirmation
	if client != nil {
		r.ClientId = client.ClientId
		r.AccessTokenLifetime = client.AccessTokenLifetime
		r.AccessTokenType = client.AccessTokenType
		for _, c := range client.Claims {
			r.ClientClaims = append(r.ClientClaims, claims.NewClaim(
				claims.WithClaimType(c.Type),
				claims.WithClaimValue(c.Value),
			))
		}
	}
}
