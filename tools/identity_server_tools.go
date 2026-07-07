// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package tools

import (
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// From: IdentityServer4/src/IdentityServer/IdentityServerTools.cs
// IdentityServerTools helpers for interacting with IdentityServer
type IdentityServerTools struct {
	issuerNameService services.IssuerNameService
	tokenCreation     services.TokenCreationService
	clock             services.SystemClock
}

// NewIdentityServerTools Initializes a new instance of the IdentityServerTools.
func NewIdentityServerTools(
	issuerNameService services.IssuerNameService,
	tokenCreation services.TokenCreationService,
	clock services.SystemClock,
) *IdentityServerTools {
	return &IdentityServerTools{
		issuerNameService: issuerNameService,
		tokenCreation:     tokenCreation,
		clock:             clock,
	}
}

// IssueJwt Issues a JWT.
func (t *IdentityServerTools) IssueJwt(lifetime int, claims []*claimspkg.Claim) (string, error) {
	if claims == nil {
		return "", gois.ArgumentNullException
	}

	issuer := t.issuerNameService.GetCurrent()

	token := &storage_models.Token{
		CreationTime: time.Now().UTC(),
		Issuer:       issuer,
		Lifetime:     lifetime,
		Claims:       claims,
	}

	return t.tokenCreation.CreateToken(token)
}

func (t *IdentityServerTools) IssueJwtWithIssuer(lifetime int, issuer string, claims []*claimspkg.Claim) (string, error) {
	if claims == nil {
		return "", gois.ArgumentNullException
	}

	token := &storage_models.Token{
		CreationTime: time.Now().UTC(),
		Issuer:       issuer,
		Lifetime:     lifetime,
		Claims:       claims,
	}

	return t.tokenCreation.CreateToken(token)
}
