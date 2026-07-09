// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/storage"
	test_common "github.com/gonewx/wicket/test/common"
	validators_mock "github.com/gonewx/wicket/validators/mock"
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

type userInfoRequestValidatorTest struct {
	clients storage.ClientStore
}

func newUserInfoRequestValidatorTest() *userInfoRequestValidatorTest {
	clients, _ := createClientStore()
	return &userInfoRequestValidatorTest{
		clients: clients,
	}
}

func TestToken_without_sub_should_fail(t *testing.T) {
	a := require.New(t)

	ti := newUserInfoRequestValidatorTest()

	tokenResult := validators_models.NewTokenValidationResult()
	tokenResult.Client, _ = extensions.FindEnabledClientById(ti.clients, "codeclient")
	tokenResult.Claims = make([]*claims.Claim, 0)

	validator := NewUserInfoRequestValidator(
		validators_mock.NewTestTokenValidator(tokenResult),
		validators_mock.NewTestProfileService(true),
		test_common.NewTestLogger(),
	)

	result := validator.ValidateRequest("token")

	a.Error(result.Error)
	a.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}

func TestActive_user_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newUserInfoRequestValidatorTest()

	tokenResult := validators_models.NewTokenValidationResult()
	tokenResult.Client, _ = extensions.FindEnabledClientById(ti.clients, "codeclient")
	tokenResult.Claims = []*claims.Claim{
		claims.NewClaim(
			claims.WithClaimType("sub"),
			claims.WithClaimValue("123"),
		),
	}

	validator := NewUserInfoRequestValidator(
		validators_mock.NewTestTokenValidator(tokenResult),
		validators_mock.NewTestProfileService(true),
		test_common.NewTestLogger(),
	)

	result := validator.ValidateRequest("token")

	a.NoError(result.Error)
}

func TestUserInfoRequestValidatorInactive_user_should_fail(t *testing.T) {
	a := require.New(t)

	ti := newUserInfoRequestValidatorTest()

	tokenResult := validators_models.NewTokenValidationResult()
	tokenResult.Client, _ = extensions.FindEnabledClientById(ti.clients, "codeclient")
	tokenResult.Claims = []*claims.Claim{
		claims.NewClaim(
			claims.WithClaimType("sub"),
			claims.WithClaimValue("123"),
		),
	}

	validator := NewUserInfoRequestValidator(
		validators_mock.NewTestTokenValidator(tokenResult),
		validators_mock.NewTestProfileService(false),
		test_common.NewTestLogger(),
	)

	result := validator.ValidateRequest("token")

	a.Error(result.Error)
	a.ErrorIs(result.Error, gois.ProtectedResourceErrorsInvalidToken)
}
