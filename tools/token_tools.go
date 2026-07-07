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
// TokenTools helpers for issuing tokens.
type TokenTools struct {
	issuerNameService services.IssuerNameService
	tokenCreation     services.TokenCreationService
	clock             services.SystemClock
}

// NewTokenTools initializes a token helper.
func NewTokenTools(
	issuerNameService services.IssuerNameService,
	tokenCreation services.TokenCreationService,
	clock services.SystemClock,
) *TokenTools {
	return &TokenTools{
		issuerNameService: issuerNameService,
		tokenCreation:     tokenCreation,
		clock:             clock,
	}
}

// IssueJwt Issues a JWT.
func (t *TokenTools) IssueJwt(lifetime int, claims []*claimspkg.Claim) (string, error) {
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

func (t *TokenTools) IssueJwtWithIssuer(lifetime int, issuer string, claims []*claimspkg.Claim) (string, error) {
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
