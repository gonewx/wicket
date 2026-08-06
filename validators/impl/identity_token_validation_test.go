// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/stretchr/testify/require"
)

func TestValid_IdentityToken_DefaultKeyType(t *testing.T) {
	r := require.New(t)

	creator := createDefaultTokenCreator(nil)
	token := createIdentityToken("roclient", "valid")
	jwt, err := creator.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, _ := validator.ValidateIdentityToken(context.Background(), jwt, "roclient", true)

	r.NoError(result.Error)
}

func TestValid_IdentityToken_DefaultKeyType_no_ClientId_supplied(t *testing.T) {
	r := require.New(t)

	creator := createDefaultTokenCreator(nil)
	token := createIdentityToken("roclient", "valid")
	jwt, err := creator.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, _ := validator.ValidateIdentityToken(context.Background(), jwt, "roclient", true)

	r.NoError(result.Error)
}

func TestValid_IdentityToken_no_ClientId_supplied(t *testing.T) {
	r := require.New(t)

	creator := createDefaultTokenCreator(nil)
	token := createIdentityToken("roclient", "valid")
	jwt, err := creator.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, _ := validator.ValidateIdentityToken(context.Background(), jwt, "", true)

	r.NoError(result.Error)
}

func TestIdentityToken_InvalidClientId(t *testing.T) {
	r := require.New(t)

	creator := createDefaultTokenCreator(nil)
	token := createIdentityToken("roclient", "valid")
	jwt, err := creator.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, _ := validator.ValidateIdentityToken(context.Background(), jwt, "invalid", true)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestIdentityToken_Too_Long(t *testing.T) {
	r := require.New(t)

	creator := createDefaultTokenCreator(nil)
	token := createIdentityTokenLong("roclient", "valid", 1000)
	jwt, err := creator.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, _ := validator.ValidateIdentityToken(context.Background(), jwt, "roclient", true)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestClaims_that_collide_with_token_validation_should_be_ignored(t *testing.T) {
	r := require.New(t)

	creator := createDefaultTokenCreator(nil)
	id_token := createIdentityToken("roclient", "sub")
	id_token.Claims = append(id_token.Claims, claims.NewClaim(
		claims.WithClaimType("aud"),
		claims.WithClaimValue("some_aud"),
	))

	// this should not throw
	jwtString, err := creator.CreateToken(context.Background(), id_token)
	r.NoError(err)

	// check that the custom aud was ignored
	payload := strings.Split(jwtString, ".")
	r.Len(payload, 3)

	p, err := base64.RawURLEncoding.DecodeString(payload[1])
	r.NoError(err)

	values := make(map[string]any, 0)
	err = json.Unmarshal(p, &values)

	r.NoError(err)

	audiences, ok := values["aud"]
	r.True(ok)

	aud, ok := audiences.([]any)
	r.True(ok)
	r.Greater(len(aud), 0)
	r.Equal("roclient", aud[0])
}
