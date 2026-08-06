// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	storage "github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/gonewx/wicket/utils"
)

var (
	now time.Time
)

type accessTokenValidationTest struct {
	clients storage.ClientStore
	options *config_options.WicketOptions
	clock   *test_common.StubClock
}

func getNow() time.Time {
	return now
}

func newAccessTokenValidationTest() *accessTokenValidationTest {
	clients, _ := createClientStore()

	options := config_options.NewWicketOptions()
	clock := test_common.NewStubClock()
	clock.NowFunc = getNow

	return &accessTokenValidationTest{
		clients: clients,
		options: options,
		clock:   clock,
	}
}

func TestValid_Reference_Token(t *testing.T) {
	r := require.New(t)

	store := createReferenceTokenStore()
	validator := createTokenValidator(
		withTokenValidatorStore(store),
	)

	client := storage_models.NewClient()
	client.ClientId = "roclient"

	token := createAccessToken(client, "valid", 600, []string{"read", "write"})

	handle := "ref-token"
	err := store.StoreReferenceToken(context.Background(), handle, token)
	r.NoError(err)

	result, err := validator.ValidateAccessToken(context.Background(), handle, "")

	r.NoError(result.Error)
	r.Len(result.Claims, 9)
	r.Equal("roclient", utils.FirstPred(result.Claims, func(c *claims.Claim) bool { return c.Type == gois.JwtClaimTypesClientId }).Value)

	claimTypes := utils.Select(result.Claims, func(c *claims.Claim) string { return c.Type })
	r.Contains(claimTypes, "iss")
	r.Contains(claimTypes, "aud")
	r.Contains(claimTypes, "iat")
	r.Contains(claimTypes, "nbf")
	r.Contains(claimTypes, "exp")
	r.Contains(claimTypes, "client_id")
	r.Contains(claimTypes, "sub")
	r.Contains(claimTypes, "scope")
}

func TestValid_Reference_Token_with_required_Scope(t *testing.T) {
	r := require.New(t)

	store := createReferenceTokenStore()
	validator := createTokenValidator(withTokenValidatorStore(store))

	client := storage_models.NewClient()
	client.ClientId = "roclient"

	token := createAccessToken(client, "valid", 600, []string{"read", "write"})

	handle := "ref-token"
	err := store.StoreReferenceToken(context.Background(), handle, token)
	r.NoError(err)

	result, err := validator.ValidateAccessToken(context.Background(), handle, "read")
	r.NoError(err)

	r.NoError(result.Error)
}

func TestValid_Reference_Token_with_missing_Scope(t *testing.T) {
	r := require.New(t)

	store := createReferenceTokenStore()
	validator := createTokenValidator(withTokenValidatorStore(store))

	client := storage_models.NewClient()
	client.ClientId = "roclient"

	token := createAccessToken(client, "valid", 600, []string{"read", "write"})

	handle := "ref-token"
	err := store.StoreReferenceToken(context.Background(), handle, token)
	r.NoError(err)

	result, err := validator.ValidateAccessToken(context.Background(), handle, "missing")
	r.NoError(err)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInsufficientScope)
}

func TestUnknown_Reference_Token(t *testing.T) {
	r := require.New(t)

	validator := createTokenValidator()

	result, err := validator.ValidateAccessToken(context.Background(), "unknown", "")
	r.NoError(err)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestReference_Token_Too_Long(t *testing.T) {
	r := require.New(t)

	validator := createTokenValidator()
	options := config_options.NewWicketOptions()

	longToken := strings.Repeat("x", options.InputLengthRestrictions.TokenHandle+1)
	result, err := validator.ValidateAccessToken(context.Background(), longToken, "")
	r.NoError(err)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestExpired_Reference_Token(t *testing.T) {
	r := require.New(t)

	ti := newAccessTokenValidationTest()

	now = time.Now()

	store := createReferenceTokenStore()
	validator := createTokenValidator(
		withTokenValidatorStore(store),
		withTokenValidatorClock(ti.clock),
	)

	client := storage_models.NewClient()
	client.ClientId = "roclient"

	token := createAccessToken(client, "valid", 2, []string{"read", "write"})
	token.CreationTime = now

	handle := "ref-token"
	err := store.StoreReferenceToken(context.Background(), handle, token)
	r.NoError(err)

	now = now.Add(3 * time.Second)

	result, err := validator.ValidateAccessToken(context.Background(), handle, "")

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsExpiredToken)
}

func TestMalformed_JWT_Token(t *testing.T) {
	r := require.New(t)

	validator := createTokenValidator()

	result, err := validator.ValidateAccessToken(context.Background(), "unk.nown", "")
	r.NoError(err)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestValid_JWT_Token(t *testing.T) {
	r := require.New(t)

	client := storage_models.NewClient()
	client.ClientId = "roclient"

	token := createAccessToken(client, "valid", 600, []string{"read", "write"})

	signer := createDefaultTokenCreator(nil)
	jwt, err := signer.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, err := validator.ValidateAccessToken(context.Background(), jwt, "")
	r.NoError(err)

	r.NoError(result.Error)
}

func TestJWT_Token_with_scopes_have_expected_claims(t *testing.T) {
	r := require.New(t)

	flags := []bool{true, false}
	for _, flag := range flags {
		name := "false"
		if flag {
			name = "true"
		}
		t.Run(name, func(t *testing.T) {
			options := config_options.NewWicketOptions()
			options.EmitScopesAsSpaceDelimitedStringInJwt = flag

			signer := createDefaultTokenCreator(options)
			client := storage_models.NewClient()

			client.ClientId = "roclient"

			token := createAccessToken(client, "valid", 600, []string{"read", "write"})

			jwt, err := signer.CreateToken(context.Background(), token)
			r.NoError(err)

			validator := createTokenValidator()

			result, err := validator.ValidateAccessToken(context.Background(), jwt, "")
			r.NoError(err)

			r.NoError(result.Error)
			r.NotEmpty(result.Jwt)
			r.Equal("roclient", result.Client.ClientId)

			r.Len(result.Claims, 9)
			scopes := utils.Select(
				utils.Where(result.Claims, func(c *claims.Claim) bool { return c.Type == "scope" }),
				func(c *claims.Claim) string { return c.Value.(string) },
			)
			r.Len(scopes, 2)
			r.Equal(scopes, []string{"read", "write"}, scopes)
		})

	}
}

func TestJWT_Token_invalid_Issuer(t *testing.T) {
	r := require.New(t)

	signer := createDefaultTokenCreator(nil)

	client := storage_models.NewClient()
	client.ClientId = "roclient"

	token := createAccessToken(client, "valid", 600, []string{"read", "write"})
	token.Issuer = "invalid"

	jwt, err := signer.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, err := validator.ValidateAccessToken(context.Background(), jwt, "")
	r.NoError(err)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestJWT_Token_Too_Long(t *testing.T) {
	r := require.New(t)

	signer := createDefaultTokenCreator(nil)

	client := storage_models.NewClient()
	client.ClientId = "roclient"

	token := createAccessTokenLong(client, "valid", 600, 1000, []string{"read", "write"})

	jwt, err := signer.CreateToken(context.Background(), token)
	r.NoError(err)

	validator := createTokenValidator()

	result, err := validator.ValidateAccessToken(context.Background(), jwt, "")
	r.NoError(err)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestValid_AccessToken_but_Client_not_active(t *testing.T) {
	r := require.New(t)

	store := createReferenceTokenStore()
	validator := createTokenValidator(
		withTokenValidatorStore(store),
	)

	client := storage_models.NewClient()
	client.ClientId = "unknown"

	token := createAccessToken(client, "valid", 600, []string{"read", "write"})

	handle := "ref-token"
	err := store.StoreReferenceToken(context.Background(), handle, token)
	r.NoError(err)

	result, err := validator.ValidateAccessToken(context.Background(), handle, "")

	r.Error(result.Error)
}
