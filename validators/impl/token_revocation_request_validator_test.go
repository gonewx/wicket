// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
)

// tokenRevocationRequestValidatorTest
type tokenRevocationRequestValidatorTest struct {
	validator validators.TokenRevocationRequestValidator
	client    *storage_models.Client
}

func newTokenRevocationRequestValidatorTest() *tokenRevocationRequestValidatorTest {
	ti := &tokenRevocationRequestValidatorTest{}
	ti.validator = NewTokenRevocationRequestValidator(test_common.NewTestLogger())
	ti.client = storage_models.NewClient()
	ti.client.ClientName = "Code Client"
	ti.client.Enabled = true
	ti.client.ClientId = "codeclient"

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	ti.client.ClientSecrets = []*storage_models.Secret{secret}

	if err := ti.client.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}

	ti.client.RequireConsent = false

	ti.client.RedirectUris = []string{
		"https://server/cb",
	}

	ti.client.AuthorizationCodeLifetime = 60

	return ti
}

func TestEmpty_Parameters(t *testing.T) {
	a := require.New(t)

	ti := newTokenRevocationRequestValidatorTest()

	parameters := url.Values{}

	_, err := ti.validator.ValidateRequest(context.Background(), parameters, ti.client)

	a.Error(err)
	a.Equal("no parameters passed", err.Error())
}

func TestMissing_Token_Valid_Hint(t *testing.T) {
	a := require.New(t)

	ti := newTokenRevocationRequestValidatorTest()

	parameters := url.Values{}
	parameters.Add("token_type_hint", "access_token")

	result, err := ti.validator.ValidateRequest(context.Background(), parameters, ti.client)

	a.NoError(err)
	a.Error(result.Error)
	a.ErrorIs(result.Error, gois.TokenErrorsInvalidRequest)
}

func TestValid_Token_And_AccessTokenHint(t *testing.T) {
	a := require.New(t)

	ti := newTokenRevocationRequestValidatorTest()

	parameters := url.Values{}
	parameters.Add("token", "foo")
	parameters.Add("token_type_hint", "access_token")

	result, err := ti.validator.ValidateRequest(context.Background(), parameters, ti.client)

	a.NoError(err)
	a.NoError(result.Error)
	a.Equal("foo", result.Token)
	a.Equal("access_token", result.TokenTypeHint)
}

func TestValid_Token_and_RefreshTokenHint(t *testing.T) {
	a := require.New(t)

	ti := newTokenRevocationRequestValidatorTest()

	parameters := url.Values{}
	parameters.Add("token", "foo")
	parameters.Add("token_type_hint", "refresh_token")

	result, err := ti.validator.ValidateRequest(context.Background(), parameters, ti.client)

	a.NoError(err)
	a.NoError(result.Error)
	a.Equal("foo", result.Token)
	a.Equal("refresh_token", result.TokenTypeHint)
}

func TestValid_Token_And_Missing_Hint(t *testing.T) {
	a := require.New(t)

	ti := newTokenRevocationRequestValidatorTest()

	parameters := url.Values{}
	parameters.Add("token", "foo")

	result, err := ti.validator.ValidateRequest(context.Background(), parameters, ti.client)

	a.NoError(err)
	a.NoError(result.Error)
	a.Equal("foo", result.Token)
	a.Empty(result.TokenTypeHint)
}

func TestValid_Token_And_Invalid_Hint(t *testing.T) {
	a := require.New(t)

	ti := newTokenRevocationRequestValidatorTest()

	parameters := url.Values{}
	parameters.Add("token", "foo")
	parameters.Add("token_type_hint", "invalid")

	result, err := ti.validator.ValidateRequest(context.Background(), parameters, ti.client)

	a.NoError(err)
	a.Error(result.Error)
	a.ErrorIs(result.Error, gois.RevocationErrorsUnsupportedTokenType)
}
